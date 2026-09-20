package threat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Updater runs the background feed refresh loop and maintains the current
// atomic snapshot. It owns the fetch/parse/reputation/compile pipeline, the
// disk cache (last known good snapshot), and per-feed sanity checks. On any
// update failure it keeps the previous snapshot active (never fail-closed to an
// empty list), matching the "old snapshot survives any error" requirement.
type Updater struct {
	cfg        *Config
	fetcher    Fetcher
	reputation *ReputationEngine

	mu      sync.RWMutex
	current *Snapshot
	blocks  map[string]BlockDecision

	state atomic.Value // *UpdaterState

	// allow/custom dynamic lists loaded from disk, reloadable.
	allowMu   sync.RWMutex
	allowSet  map[string]struct{}
	customMu  sync.RWMutex
	customSet map[string]struct{}

	metrics *Metrics
}

// UpdaterState is a thread-safe snapshot of update telemetry.
type UpdaterState struct {
	SnapshotDomains int64
	TotalEntries    int64
	LastSuccessUnix int64
	LastAttemptUnix int64
	LastError       string
	UpdateSuccess   int64
	UpdateFailed    int64
	LastDurationMS  int64
}

// Fetcher is an interface indirection to keep the updater unit-testable without
// real HTTP. The production implementation is *FeedFetcher.
type Fetcher interface {
	Fetch(ctx context.Context, feed FeedConfig, maxBytes int64) (*FetchResult, error)
}

// NewUpdater builds an updater with the given config, fetcher, reputation
// engine, and optional metrics (nil is safe — telemetry is skipped). It loads
// the disk cache (if any) into the current snapshot so DNS can start serving
// before the first background update.
func NewUpdater(cfg *Config, fetcher Fetcher, rep *ReputationEngine, metrics *Metrics) (*Updater, error) {
	u := &Updater{
		cfg:        cfg,
		fetcher:    fetcher,
		reputation: rep,
		metrics:    metrics,
	}
	u.current = EmptySnapshot()
	u.blocks = map[string]BlockDecision{}
	st := &UpdaterState{}
	if err := u.loadDiskCache(); err != nil {
		st.LastError = "disk cache: " + err.Error()
	} else {
		st.SnapshotDomains = u.current.DomainCount()
		st.TotalEntries = u.current.TotalEntries()
	}
	u.state.Store(st)
	_ = u.LoadAllowlist()
	_ = u.LoadCustom()
	return u, nil
}

// Snapshot returns the currently active snapshot under a read lock. The
// returned pointer is immutable after build.
func (u *Updater) Snapshot() *Snapshot {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.current
}

// Lookup performs an O(labels) lookup, returning the matched IOC and its
// BlockDecision (whether to block and why), honoring allowlist and custom
// blocklist priority. Returns nil IOC if not blocked.
func (u *Updater) Lookup(query string) (*IOC, BlockDecision, string) {
	norm := normalizeQuery(query)
	// 1. Allowlist highest priority: query or any parent allowed overrides all.
	if matchSetParent(norm, u.allowSet, &u.allowMu) {
		return nil, BlockDecision{ShouldBlock: false, Reason: "allowlist"}, ""
	}
	// 2. Custom ASTRACAT blocklist (max priority after allowlist).
	if base, ok := matchSetParentReturn(norm, u.customSet, &u.customMu); ok {
		return &IOC{
			Domain:     base,
			Category:   CategoryCustomAbuse,
			Confidence: ConfidenceCustom,
			Sources:    []string{"astracat-custom"},
		}, BlockDecision{ShouldBlock: true, Reason: "custom"}, base
	}
	// 3. Threat snapshot.
	u.mu.RLock()
	snap := u.current
	blocks := u.blocks
	u.mu.RUnlock()
	ioc, matched := snap.MatchIOC(norm)
	if ioc == nil {
		return nil, BlockDecision{}, ""
	}
	bd, ok := blocks[ioc.Domain]
	if !ok {
		bd = BlockDecision{IOC: ioc, ShouldBlock: false, Reason: "observe"}
	}
	return ioc, bd, matched
}

// matchSetParent checks whether d or any parent is in set (with lock held).
func matchSetParent(d string, set map[string]struct{}, mu *sync.RWMutex) bool {
	mu.RLock()
	for _, p := range allowParents(d) {
		if _, ok := set[p]; ok {
			mu.RUnlock()
			return true
		}
	}
	mu.RUnlock()
	return false
}

// matchSetParentReturn returns the matched parent domain.
func matchSetParentReturn(d string, set map[string]struct{}, mu *sync.RWMutex) (string, bool) {
	mu.RLock()
	defer mu.RUnlock()
	for _, p := range allowParents(d) {
		if _, ok := set[p]; ok {
			return p, true
		}
	}
	return "", false
}

// allowParents returns the query domain plus every progressively shorter parent
// (e.g. "a.b.example.com" => [a.b.example.com, b.example.com, example.com, com]).
func allowParents(d string) []string {
	if d == "" {
		return nil
	}
	out := []string{d}
	for {
		idx := strings.IndexByte(d, '.')
		if idx < 0 {
			break
		}
		d = d[idx+1:]
		if d == "" {
			break
		}
		out = append(out, d)
	}
	return out
}

// BlocksMap returns a copy of the block decisions map (for tests/metrics).
func (u *Updater) BlocksMap() map[string]BlockDecision {
	u.mu.RLock()
	defer u.mu.RUnlock()
	cp := make(map[string]BlockDecision, len(u.blocks))
	for k, v := range u.blocks {
		cp[k] = v
	}
	return cp
}

// Run starts the background update loop. It performs an immediate first update,
// then waits UpdateInterval between cycles. Stops when ctx is cancelled.
func (u *Updater) Run(ctx context.Context) {
	_ = u.UpdateOnce(ctx)
	ticker := time.NewTicker(u.cfg.UpdateInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = u.UpdateOnce(ctx)
		}
	}
}

// RefreshNow triggers an out-of-band update and returns the error (used by a
// reload endpoint) if the update failed to replace the snapshot.
func (u *Updater) RefreshNow(ctx context.Context) error {
	return u.UpdateOnce(ctx)
}

// UpdateOnce runs one full feed update cycle. On error it keeps the previous
// snapshot active and returns the error.
func (u *Updater) UpdateOnce(ctx context.Context) error {
	start := time.Now()
	st := u.state.Load().(*UpdaterState)
	st.LastAttemptUnix = time.Now().Unix()
	u.state.Store(st)

	err := u.update(ctx)
	if u.metrics != nil {
		u.metrics.ObserveUpdate(err == nil, time.Since(start))
	}
	st = u.state.Load().(*UpdaterState)
	if err != nil {
		st.UpdateFailed++
		st.LastError = err.Error()
	} else {
		st.UpdateSuccess++
		st.LastSuccessUnix = time.Now().Unix()
		st.LastDurationMS = time.Since(start).Milliseconds()
		st.LastError = ""
	}
	u.state.Store(st)
	return err
}

// update performs the pipeline: fetch feeds, parse, sanity-check, compile,
// atomic swap, persist. If ALL feeds fail it returns an error and keeps the old
// snapshot; partial success still rebuilds from what succeeded, and the old
// snapshot is kept if the result collapses to near-empty.
func (u *Updater) update(ctx context.Context) error {
	enabled := u.enabledFeeds()
	now := time.Now().Unix()

	if len(enabled) == 0 {
		// No external feeds: build a snapshot from the custom list alone.
		return u.rebuildFromCustom(now)
	}

	var results []*FeedParseResult
	var firstErr error
	for _, feed := range enabled {
		res, err := u.fetchFeed(ctx, feed, now)
		if err != nil {
			st := u.state.Load().(*UpdaterState)
			st.LastError = fmt.Sprintf("feed %s: %v", feed.Name, err)
			u.state.Store(st)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		results = append(results, res)
	}

	if len(results) == 0 {
		if firstErr != nil {
			// All feeds failed: keep the previously active snapshot intact
			// (never fail-closed to an empty list). The error is surfaced so
			// metrics reflect the outage; DNS keeps serving the last good data.
			return fmt.Errorf("all threat feeds failed: %w", firstErr)
		}
		return nil
	}

	// Sanity: reject a collapse (>90% drop to a tiny set) to protect against
	// the "feed 100k -> 3 domains" case. Old snapshot stays active.
	if u.rejectIfCollapsed(results) {
		return nil
	}

	snap, blocks := u.reputation.BuildSnapshot(results)
	if u.cfg.MaxDomains > 0 && snap.DomainCount() > int64(u.cfg.MaxDomains) {
		return fmt.Errorf("snapshot has %d domains, exceeds max_domains %d (update rejected)", snap.DomainCount(), u.cfg.MaxDomains)
	}

	u.swap(snap, blocks)
	u.persistDiskCache(snap, blocks)
	u.refreshLists()

	// Report snapshot domain count in state.
	st := u.state.Load().(*UpdaterState)
	st.SnapshotDomains = snap.DomainCount()
	st.TotalEntries = snap.TotalEntries()
	u.state.Store(st)
	return nil
}

// FetchedFeed ties a parsed result to its source feed.
type FetchedFeed struct {
	feed   FeedConfig
	parsed *FeedParseResult
}

// rejectIfCollapsed returns true when the newly parsed set is implausibly small
// relative to the previous snapshot (the "feed 100k -> 3 domains" guard).
func (u *Updater) rejectIfCollapsed(results []*FeedParseResult) bool {
	u.mu.RLock()
	prev := u.current.DomainCount()
	u.mu.RUnlock()

	total := 0
	for _, r := range results {
		if r != nil {
			total += r.Stats.ParsedEntries
		}
	}
	if total == 0 {
		return prev > 0
	}
	if prev > 0 && int64(total) < prev {
		decrease := float64(prev - int64(total))
		pct := math.Round(decrease / float64(prev) * 100)
		if pct > 90 && total < 1000 {
			return true
		}
	}
	return false
}

// rebuildFromCustom builds a snapshot purely from the custom blocklist so
// custom ASTRACAT blocks keep working even when all external feeds fail.
func (u *Updater) rebuildFromCustom(now int64) error {
	u.customMu.RLock()
	set := make(map[string]struct{}, len(u.customSet))
	for d := range u.customSet {
		set[d] = struct{}{}
	}
	u.customMu.RUnlock()

	iocs := make([]*IOC, 0, len(set))
	blocks := make(map[string]BlockDecision, len(set))
	for d := range set {
		ioc := &IOC{
			Domain:       d,
			Category:     CategoryCustomAbuse,
			Confidence:   ConfidenceCustom,
			Sources:      []string{"astracat-custom"},
			SourcesCount: 1,
			FirstSeen:    now,
			LastSeen:     now,
		}
		iocs = append(iocs, ioc)
		blocks[d] = BlockDecision{IOC: ioc, ShouldBlock: true, Reason: "custom"}
	}
	snap := BuildSnapshot(iocs)
	u.swap(snap, blocks)
	return nil
}

// fetchFeed fetches a single feed, applies per-feed sanity (min entries), and
// parses it.
func (u *Updater) fetchFeed(ctx context.Context, feed FeedConfig, now int64) (*FeedParseResult, error) {
	res, err := u.fetcher.Fetch(ctx, feed, u.cfg.MaxFeedBytes)
	if err != nil {
		u.observeFeedFetch(feed, false, 0)
		return nil, err
	}
	parsed, err := ParseFeedEntry(feed, bytes.NewReader(res.Body), now)
	if err != nil {
		u.observeFeedFetch(feed, false, 0)
		return nil, fmt.Errorf("parse feed %q: %w", feed.Name, err)
	}
	if feed.MinEntries > 0 && parsed.Stats.ParsedEntries < feed.MinEntries {
		u.observeFeedFetch(feed, false, 0)
		return nil, fmt.Errorf("feed %q has %d entries, below min_entries %d (rejected)", feed.Name, parsed.Stats.ParsedEntries, feed.MinEntries)
	}
	u.observeFeedFetch(feed, true, parsed.Stats.ParsedEntries)
	return parsed, nil
}

// observeFeedFetch records per-feed fetch telemetry (safe if metrics is nil).
func (u *Updater) observeFeedFetch(feed FeedConfig, ok bool, iocs int) {
	if u.metrics == nil {
		return
	}
	u.metrics.ObserveFeedFetch(feed.Name, ok)
	if ok {
		u.metrics.SetFeedIOC(feed.Name, iocs)
	}
}

// enabledFeeds returns only enabled, non-empty-config feeds.
func (u *Updater) enabledFeeds() []FeedConfig {
	var out []FeedConfig
	for _, f := range u.cfg.Feeds {
		if f.Enabled && f.URL != "" {
			out = append(out, f)
		}
	}
	return out
}

// swap atomically replaces the active snapshot and block map.
func (u *Updater) swap(snap *Snapshot, blocks map[string]BlockDecision) {
	u.mu.Lock()
	u.current = snap
	u.blocks = blocks
	u.mu.Unlock()
}

// updateWithResultsForTest builds and swaps a snapshot directly from given
// parse results; used by tests to construct state without fetching.
func (u *Updater) updateWithResultsForTest(results []*FeedParseResult) error {
	snap, blocks := u.reputation.BuildSnapshot(results)
	u.swap(snap, blocks)
	u.persistDiskCache(snap, blocks)
	return nil
}

// --- allowlist / custom list handling ---

// LoadAllowlist reads the allowlist file and reloads the allow set atomically.
// Non-fatal on missing file (empty set).
func (u *Updater) LoadAllowlist() error {
	set := map[string]struct{}{}
	if u.cfg.AllowlistFile != "" {
		data, err := os.ReadFile(u.cfg.AllowlistFile)
		if err == nil {
			parseDomainFileInto(set, string(data))
		}
	}
	u.allowMu.Lock()
	u.allowSet = set
	u.allowMu.Unlock()
	return nil
}

// LoadCustom reads the ASTRACAT custom blocklist and reloads the custom set
// atomically. Non-fatal on missing file (empty set).
func (u *Updater) LoadCustom() error {
	set := map[string]struct{}{}
	if u.cfg.CustomBlocklistFile != "" {
		data, err := os.ReadFile(u.cfg.CustomBlocklistFile)
		if err == nil {
			parseDomainFileInto(set, string(data))
		}
	}
	u.customMu.Lock()
	u.customSet = set
	u.customMu.Unlock()
	return nil
}

// refreshLists is called after a successful update to re-load disk lists (they
// may have changed since startup) without blocking the swap.
func (u *Updater) refreshLists() {
	_ = u.LoadAllowlist()
	_ = u.LoadCustom()
}

// --- disk cache ---

func (u *Updater) diskCachePath() string {
	return filepath.Join(u.cfg.DiskCacheDir, "snapshot.json")
}

type cacheEntry struct {
	Domain       string
	Category     Category
	Confidence   Confidence
	Sources      []string
	SourcesCount int
	ShouldBlock  bool
	Reason       string
}

// persistDiskCache writes the last good snapshot + block decisions to disk so a
// restart can begin from known-good data. Writes atomically via temp file.
func (u *Updater) persistDiskCache(snap *Snapshot, blocks map[string]BlockDecision) {
	if u.cfg.DiskCacheDir == "" {
		return
	}
	if err := os.MkdirAll(u.cfg.DiskCacheDir, 0o755); err != nil {
		return
	}
	entries := make([]cacheEntry, 0, snap.DomainCount())
	for _, dom := range snap.SortedDomains() {
		ioc := snap.LookupIOC(dom)
		if ioc == nil {
			continue
		}
		bd, _ := blocks[ioc.Domain]
		entries = append(entries, cacheEntry{
			Domain:       ioc.Domain,
			Category:     ioc.Category,
			Confidence:   ioc.Confidence,
			Sources:      ioc.Sources,
			SourcesCount: ioc.SourcesCount,
			ShouldBlock:  bd.ShouldBlock,
			Reason:       bd.Reason,
		})
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return
	}
	tmp := filepath.Join(u.cfg.DiskCacheDir, "snapshot.tmp")
	if err := os.WriteFile(tmp, data, 0o644); err == nil {
		_ = os.Rename(tmp, u.diskCachePath())
	}
}

// loadDiskCache loads a previously persisted snapshot into memory.
func (u *Updater) loadDiskCache() error {
	if u.cfg.DiskCacheDir == "" {
		return nil
	}
	data, err := os.ReadFile(u.diskCachePath())
	if err != nil {
		return err
	}
	var entries []cacheEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}
	iocs := make([]*IOC, 0, len(entries))
	blocks := make(map[string]BlockDecision, len(entries))
	for _, e := range entries {
		if e.Domain == "" {
			continue
		}
		ioc := &IOC{
			Domain:       e.Domain,
			Category:     e.Category,
			Confidence:   e.Confidence,
			Sources:      e.Sources,
			SourcesCount: e.SourcesCount,
		}
		iocs = append(iocs, ioc)
		blocks[e.Domain] = BlockDecision{IOC: ioc, ShouldBlock: e.ShouldBlock, Reason: e.Reason}
	}
	u.swap(BuildSnapshot(iocs), blocks)
	return nil
}

// State returns a copy of the current telemetry state.
func (u *Updater) State() UpdaterState {
	s := u.state.Load()
	if s == nil {
		return UpdaterState{}
	}
	return *s.(*UpdaterState)
}

// parseDomainFileInto reads a domain-per-line string into a set, applying
// normalization and skipping invalid/comment lines.
func parseDomainFileInto(dst map[string]struct{}, content string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if c := strings.IndexByte(line, '#'); c >= 0 {
			line = strings.TrimSpace(line[:c])
		}
		if line == "" {
			continue
		}
		base := stripWildcard(line)
		if !isValidDomain(base) {
			// Also allow bare parent domains like "com" (allowlists may include
			// top-level allow rules). Keep strict for custom/allow for safety.
			continue
		}
		dst[base] = struct{}{}
	}
}
