package threat

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

// Manager is the single entry point for the Threat Intelligence subsystem. It
// owns the Updater and its telemetry, and exposes the lookup API that the Go
// plugin extension (and through it the Lua policy) calls on every query.
//
// The manager is designed to be zero-downtime: the snapshot stays active during
// refresh (atomic swap), errors never fail-closed to an empty list, and metrics
// are updated on the happy path.
type Manager struct {
	cfg     *Config
	updater *Updater
	metrics *Metrics
}

// LookupOutcome is a lightweight result returned to the caller (Lua policy).
type LookupOutcome struct {
	Match    bool     // a domain matched (blocked or observe-only)
	Block    bool     // whether to actually block
	Reason   string   // custom | high_confidence | min_sources | allowlist | observe
	Category string   // matched category ("" if none)
	Sources  []string
	Matched  string // matched parent domain
}

// NewManager wires the updater, fetcher, reputation engine, and metrics into a
// single manager. It does NOT start the background loop; call Start().
func NewManager(cfg *Config, reg prometheus.Registerer) (*Manager, error) {
	cfg.ApplyDefaults()
	fetcher := NewFeedFetcher(cfg.RequestTimeout())
	rep := NewReputationEngine(cfg.Reputation)
	met := NewMetrics(reg)
	updater, err := NewUpdater(cfg, fetcher, rep, met)
	if err != nil {
		return nil, err
	}
	m := &Manager{
		cfg:     cfg,
		updater: updater,
		metrics: met,
	}
	return m, nil
}

// Start launches the background update loop in a goroutine and returns
// immediately, so DNS components are not blocked. It runs until ctx is
// cancelled. DNS can serve immediately from the disk cache while feeds warm in
// the background.
func (m *Manager) Start(ctx context.Context) {
	if m == nil || m.updater == nil {
		return
	}
	go func() {
		// First refresh runs synchronously inside the goroutine (bounded by the
		// per-request timeout) so the disk cache is warmed if empty; subsequent
		// cycles run on the configured interval until ctx is cancelled.
		m.updater.Run(ctx)
	}()
}

// Lookup answers a single query against the active snapshot with full
// allowlist/custom-priority semantics. It is safe for concurrent use and never
// blocks on network (reads the atomic snapshot under a short RLock).
func (m *Manager) Lookup(query string) LookupOutcome {
	if m == nil || m.updater == nil {
		return LookupOutcome{}
	}
	ioc, bd, matched := m.updater.Lookup(query)

	// Allowlist hit.
	if bd.Reason == "allowlist" {
		m.metrics.ObserveLookup("allowlist")
		return LookupOutcome{Match: true, Block: false, Reason: "allowlist", Matched: matched}
	}
	// No match.
	if ioc == nil {
		m.metrics.ObserveLookup("miss")
		return LookupOutcome{}
	}
	// Matched. Decide by reputation decision carried on the IOC.
	if bd.ShouldBlock {
		m.metrics.ObserveLookup("matched")
		m.metrics.ObserveBlocked(bd.Reason)
		cat := ioc.Category
		if cat == "" {
			cat = CategoryUnknown
		}
		return LookupOutcome{
			Match:    true,
			Block:    true,
			Reason:   bd.Reason,
			Category: string(cat),
			Sources:  ioc.Sources,
			Matched:  matched,
		}
	}
	// Observe-only.
	m.metrics.ObserveLookup("matched")
	m.metrics.ObserveObserved(bd.Reason)
	return LookupOutcome{
		Match:    true,
		Block:    false,
		Reason:   bd.Reason,
		Category: string(ioc.Category),
		Sources:  ioc.Sources,
		Matched:  matched,
	}
}

// State returns updater telemetry.
func (m *Manager) State() UpdaterState {
	if m == nil {
		return UpdaterState{}
	}
	return m.updater.State()
}

// Refresh triggers an external update now (e.g. from a reload endpoint).
func (m *Manager) Refresh(ctx context.Context) error {
	if m == nil || m.updater == nil {
		return fmt.Errorf("threat manager not initialised")
	}
	return m.updater.RefreshNow(ctx)
}

// ReloadLists reloads the allowlist and custom blocklist from disk.
func (m *Manager) ReloadLists() {
	if m == nil || m.updater == nil {
		return
	}
	_ = m.updater.LoadAllowlist()
	_ = m.updater.LoadCustom()
}

// Enabled reports whether the subsystem is configured.
func (m *Manager) Enabled() bool {
	return m != nil && m.cfg != nil && m.cfg.Enabled
}
