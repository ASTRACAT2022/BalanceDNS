package threat

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// --- snapshot matching ---

func TestSnapshotMatchExactAndSuffix(t *testing.T) {
	snap := BuildSnapshot([]*IOC{
		{Domain: "packetsdk.io", Category: CategoryBotnetC2, Confidence: ConfidenceHigh},
		{Domain: "exact.example.com", Category: CategoryMalware, Confidence: ConfidenceHigh},
	})

	cases := []struct {
		query     string
		wantHit   bool
		wantBase  string
	}{
		{"packetsdk.io.", true, "packetsdk.io"},
		{"zvf4wchb4z6dkdh4.api-seed.packetsdk.io.", true, "packetsdk.io"},
		{"deep.sub.packetsdk.io.", true, "packetsdk.io"},
		{"packetsdk.io.evil.ru.", false, ""},
		{"exact.example.com.", true, "exact.example.com"},
		{"sub.exact.example.com.", true, "exact.example.com"},
		{"example.com.", false, ""},
		{"google.com.", false, ""},
	}
	for _, c := range cases {
		ioc, base := snap.MatchIOC(c.query)
		if c.wantHit != (ioc != nil) {
			t.Errorf("MatchIOC(%q) hit=%v want=%v", c.query, ioc != nil, c.wantHit)
			continue
		}
		if c.wantHit && base != c.wantBase {
			t.Errorf("MatchIOC(%q) base=%q want=%q", c.query, base, c.wantBase)
		}
	}
}

func TestEmptySnapshotNoFalsePositives(t *testing.T) {
	snap := EmptySnapshot()
	if ioc, _ := snap.MatchIOC("anything.example."); ioc != nil {
		t.Fatalf("empty snapshot returned a match")
	}
	if n := snap.DomainCount(); n != 0 {
		t.Fatalf("empty snapshot domain count = %d", n)
	}
}

func TestSnapshotNilSafe(t *testing.T) {
	var snap *Snapshot
	if ioc, _ := snap.MatchIOC("x.com."); ioc != nil {
		t.Fatal("nil snapshot returned match")
	}
	if n := snap.DomainCount(); n != 0 {
		t.Fatal("nil snapshot count not 0")
	}
}

// --- parser ---

func TestParsePlainDomains(t *testing.T) {
	feed := FeedConfig{Name: "f1", Format: "domains", Confidence: "high", Category: "botnet_c2"}
	body := `# comment
*.ads.example
.tracker.net
evil.com
evil.com  ; dup inline
sub.example.com
not a valid domain!$$
`
	res, err := ParseFeedEntry(feed, strings.NewReader(body), 1000)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Stats.ParsedEntries != 4 {
		t.Fatalf("parsed entries = %d, want 4", res.Stats.ParsedEntries)
	}
	var domains []string
	for _, i := range res.IOCs {
		domains = append(domains, i.Domain)
	}
	joined := strings.Join(domains, ",")
	for _, want := range []string{"ads.example", "tracker.net", "evil.com", "sub.example.com"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, joined)
		}
	}
}

func TestParseHostsFormat(t *testing.T) {
	feed := FeedConfig{Name: "h", Format: "hosts", Confidence: "low", Category: "malware"}
	body := `127.0.0.1 localhost
0.0.0.0 evil-malware.com
0.0.0.0 trojan.net # comment
`
	res, err := ParseFeedEntry(feed, strings.NewReader(body), 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Stats.ParsedEntries != 2 {
		t.Fatalf("parsed = %d, want 2", res.Stats.ParsedEntries)
	}
}

func TestParseRPZ(t *testing.T) {
	feed := FeedConfig{Name: "r", Format: "rpz", Confidence: "medium", Category: "phishing"}
	body := `; RPZ zone
evil-phish.com CNAME .
phish2.net .
sub.phish3.com 127.0.0.1
`
	res, err := ParseFeedEntry(feed, strings.NewReader(body), 1)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Stats.ParsedEntries != 3 {
		t.Fatalf("parsed = %d, want 3", res.Stats.ParsedEntries)
	}
}

func TestParseJSON(t *testing.T) {
	feed := FeedConfig{Name: "j", Format: "json", Confidence: "high", Category: "scam"}
	body := `{
	  "domains": ["scam1.example", "scam2.example"],
	  "values": ["scam3.example"]
	}`
	res, err := ParseFeedEntry(feed, strings.NewReader(body), 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Stats.ParsedEntries != 3 {
		t.Fatalf("parsed = %d, want 3", res.Stats.ParsedEntries)
	}
}

func TestParseJSONArrayObjects(t *testing.T) {
	feed := FeedConfig{Name: "j2", Format: "json", Confidence: "medium", Category: "cryptomining"}
	body := `[{"domain":"mine1.example"},{"host":"mine2.example"},{"ioc":{"domain":"mine3.example"}}]`
	res, err := ParseFeedEntry(feed, strings.NewReader(body), 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Stats.ParsedEntries != 3 {
		t.Fatalf("parsed = %d, want 3", res.Stats.ParsedEntries)
	}
}

func TestParserUnsupportedFormat(t *testing.T) {
	feed := FeedConfig{Name: "x", Format: "yaml"}
	if _, err := ParseFeedEntry(feed, strings.NewReader(""), 0); err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

// --- reputation ---

func TestReputationCustomAlwaysBlocks(t *testing.T) {
	rep := NewReputationEngine(ReputationConfig{
		MinimumSources:       2,
		BlockHighConfidence:  true,
		BlockMediumConfidence: true,
	})
	ioc := &IOC{Domain: "x.com", Confidence: ConfidenceCustom, SourcesCount: 1}
	bd := rep.Evaluate(ioc)
	if !bd.ShouldBlock || bd.Reason != "custom" {
		t.Fatalf("custom IOC should block, got %+v", bd)
	}
}

func TestReputationLowNeedsMinSources(t *testing.T) {
	rep := NewReputationEngine(ReputationConfig{MinimumSources: 2})
	// Low confidence, 1 source -> observe only.
	ioc1 := &IOC{Domain: "a.com", Confidence: ConfidenceLow, SourcesCount: 1}
	if bd := rep.Evaluate(ioc1); bd.ShouldBlock {
		t.Fatal("low confidence 1 source should not block")
	}
	// Low confidence, 2 sources -> block.
	ioc2 := &IOC{Domain: "a.com", Confidence: ConfidenceLow, SourcesCount: 2}
	if bd := rep.Evaluate(ioc2); !bd.ShouldBlock || bd.Reason != "min_sources" {
		t.Fatalf("low confidence 2 sources should block, got %+v", bd)
	}
}

func TestReputationHighBlocks(t *testing.T) {
	rep := NewReputationEngine(ReputationConfig{BlockHighConfidence: true, MinimumSources: 2})
	ioc := &IOC{Domain: "h.com", Confidence: ConfidenceHigh, SourcesCount: 1}
	if bd := rep.Evaluate(ioc); !bd.ShouldBlock || bd.Reason != "high_confidence" {
		t.Fatalf("high confidence should block, got %+v", bd)
	}
}

// --- updater: atomic swap keeps old snapshot on failure ---

// stubFetcher returns configurable canned results / errors for tests.
type stubFetcher struct {
	mu      sync.Mutex
	results map[string]*FetchResult
	errs    map[string]error
}

func (s *stubFetcher) Fetch(_ context.Context, feed FeedConfig, _ int64) (*FetchResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.errs[feed.Name]; ok && e != nil {
		return nil, e
	}
	if r, ok := s.results[feed.Name]; ok {
		return r, nil
	}
	return nil, errors.New("no stub for feed " + feed.Name)
}

func TestUpdaterSwapOnSuccessAndKeepsOldOnFailure(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.DiskCacheDir = dir
	cfg.UpdateIntervalSeconds = 3600
	cfg.RequestTimeoutMS = 2000
	cfg.Feeds = []FeedConfig{{
		Name: "a", URL: "https://x.example/a.txt", Format: "domains",
		Confidence: "high", Category: "botnet_c2", Enabled: true, MinEntries: 1,
	}}

	fetcher := &stubFetcher{
		results: map[string]*FetchResult{
			"a": {Body: []byte("evil1.com\nevil2.com\n")},
		},
	}
	rep := NewReputationEngine(cfg.Reputation)
	u, err := NewUpdater(cfg, fetcher, rep, nil)
	if err != nil {
		t.Fatalf("new updater: %v", err)
	}

	ctx := context.Background()
	if err := u.UpdateOnce(ctx); err != nil {
		t.Fatalf("first update: %v", err)
	}
	if n := u.Snapshot().DomainCount(); n != 2 {
		t.Fatalf("snapshot domains = %d, want 2", n)
	}
	ioc, _, _ := u.Lookup("evil1.com.")
	if ioc == nil {
		t.Fatal("evil1.com should be blocked after first update")
	}

	// Now the feed fails: old snapshot must survive intact.
	fetcher.mu.Lock()
	fetcher.errs = map[string]error{"a": errors.New("network down")}
	fetcher.mu.Unlock()

	if err := u.UpdateOnce(ctx); err == nil {
		t.Fatal("expected error when feed fails")
	}
	if n := u.Snapshot().DomainCount(); n != 2 {
		t.Fatalf("snapshot domains after failure = %d, want 2 (old kept)", n)
	}
	ioc, _, _ = u.Lookup("evil1.com.")
	if ioc == nil {
		t.Fatal("evil1.com should still be blocked after feed failure (old snapshot)")
	}
}

func TestUpdaterDiskCacheSeeds(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.DiskCacheDir = dir
	cfg.Feeds = nil

	// Build with one fetch, persist, then a fresh updater should seed from disk
	// even with no feeds available (fail-open to cached data).
	fetcher := &stubFetcher{}
	rep := NewReputationEngine(cfg.Reputation)
	u1, _ := NewUpdater(cfg, fetcher, rep, nil)
	_ = u1.updateWithResultsForTest([]*FeedParseResult{
		{IOCs: []*IOC{{Domain: "cached1.com", Category: CategoryMalware, Confidence: ConfidenceHigh, Sources: []string{"f"}, SourcesCount: 1}}},
	})

	// Simulate a restart: new updater on same dir, no feeds in config.
	u2, err := NewUpdater(cfg, fetcher, rep, nil)
	if err != nil {
		t.Fatalf("new updater u2: %v", err)
	}
	ioc, _, _ := u2.Lookup("cached1.com.")
	if ioc == nil {
		t.Fatal("restart should seed from disk cache")
	}
}

// TestUpdaterFailOpenOnDisabled keeps serving empty (fail open) when disabled.
func TestManagerFailOpenWhenNil(t *testing.T) {
	var m *Manager
	if m.Lookup("x.com.").Block {
		t.Fatal("nil manager should not block")
	}
	if m.Enabled() {
		t.Fatal("nil manager not enabled")
	}
}
