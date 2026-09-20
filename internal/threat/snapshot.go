package threat

import (
	"sort"
	"strings"
	"sync/atomic"
)

// IOC is one normalized domain with its reputation metadata. Stored inside the
// immutable snapshot; never mutated after build.
type IOC struct {
	Domain       string     // normalized bare domain, e.g. "packetsdk.io"
	SourcesCount int        // number of feeds contributing this domain
	Sources      []string   // feed names, sorted, deduplicated
	Category     Category   // dominant category
	Confidence   Confidence // highest-confidence value
	FirstSeen    int64      // unix seconds of earliest contribution
	LastSeen     int64      // unix seconds of latest contribution
}

// Category is a threat taxonomy category.
type Category string

// Supported categories. Keep in sync with config category keys in config.go.
const (
	CategoryMalware        Category = "malware"
	CategoryBotnetC2       Category = "botnet_c2"
	CategoryPhishing      Category = "phishing"
	CategoryScam           Category = "scam"
	CategoryCryptomining   Category = "cryptomining"
	CategoryMaliciousRedir Category = "malicious_redirector"
	CategoryCustomAbuse    Category = "custom_abuse"
	CategoryUnknown        Category = "unknown"
)

// Confidence is a feed/IOC trust level.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
	ConfidenceCustom Confidence = "custom" // ASTRACAT custom IOC -> always block
)

// parseConfidence maps a raw string to a Confidence, defaulting to low for
// unrecognized values. Feed configs pass raw strings here.
func parseConfidence(s string) Confidence {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return ConfidenceHigh
	case "medium":
		return ConfidenceMedium
	case "custom":
		return ConfidenceCustom
	default:
		return ConfidenceLow
	}
}

// parseCategory maps a raw category string to a Category, defaulting to
// UNKNOWN for unrecognized values.
func parseCategory(s string) Category {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "malware":
		return CategoryMalware
	case "botnet_c2", "c2", "botnet":
		return CategoryBotnetC2
	case "phishing":
		return CategoryPhishing
	case "scam":
		return CategoryScam
	case "cryptomining", "crypto", "mining":
		return CategoryCryptomining
	case "malicious_redirector", "redirector", "redirect":
		return CategoryMaliciousRedir
	case "custom_abuse", "custom":
		return CategoryCustomAbuse
	default:
		return CategoryUnknown
	}
}

// weight returns a monotonic ordering used to resolve the dominant category
// when a domain is contributed by multiple feeds with different categories.
func (c Category) weight() int {
	switch c {
	case CategoryCustomAbuse:
		return 9
	case CategoryBotnetC2:
		return 8
	case CategoryMalware:
		return 7
	case CategoryPhishing:
		return 6
	case CategoryScam:
		return 5
	case CategoryCryptomining:
		return 4
	case CategoryMaliciousRedir:
		return 3
	default:
		return 1
	}
}

// confidenceWeight orders Confidence values; higher weight = more trusted.
func confidenceWeight(c Confidence) int {
	switch c {
	case ConfidenceCustom:
		return 4
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	default:
		return 1
	}
}

// Snapshot is an immutable compiled threat database. It is swapped atomically:
// a single pointer is exchanged under the manager so readers always see either
// the previous complete snapshot or the new complete one, never a partial list.
type Snapshot struct {
	exact  map[string]*IOC // bare domain -> IOC (exact matches)
	suffix map[string]*IOC // bare domain -> IOC (also blocks subdomains)

	total       int64 // total IOCs stored (exact+suffix)
	domainCount int64 // distinct domains (exact map size)
}

// BuildSnapshot compiles a flat set of IOCs into an immutable Snapshot.
// Parent-domain blocking: every IOC is inserted into both exact and suffix
// maps so that "packetsdk.io" also matches "zvf4wchb4z6dkdh4.api-seed.packetsdk.io".
func BuildSnapshot(iocs []*IOC) *Snapshot {
	exact := make(map[string]*IOC, len(iocs))
	suffix := make(map[string]*IOC, len(iocs))
	var total int64
	for _, i := range iocs {
		if i == nil || i.Domain == "" {
			continue
		}
		exact[i.Domain] = i
		suffix[i.Domain] = i
		total++
	}
	return &Snapshot{
		exact:       exact,
		suffix:      suffix,
		total:       total,
		domainCount: int64(len(exact)),
	}
}

// EmptySnapshot returns a snapshot with no entries (used on first start before
// any update, and on fail-open).
func EmptySnapshot() *Snapshot {
	return &Snapshot{
		exact:  make(map[string]*IOC),
		suffix: make(map[string]*IOC),
	}
}

// DomainCount returns the number of distinct domains (exact map size).
func (s *Snapshot) DomainCount() int64 {
	if s == nil {
		return 0
	}
	return atomic.LoadInt64(&s.domainCount)
}

// TotalEntries returns the count of raw stored entries (exact+suffix).
func (s *Snapshot) TotalEntries() int64 {
	if s == nil {
		return 0
	}
	return atomic.LoadInt64(&s.total)
}

// MatchIOC looks up a normalized bare query domain and returns the matching
// IOC and the matched parent domain, or nil if not blocked.
//
// Because every IOC is present in both exact and suffix maps, the lookup is
// O(number of labels): at each suffix boundary we check whether the path is in
// the suffix map; the exact map handles the full-domain case. No iteration over
// the whole list, so 2M-domain snapshots cost the same as a 100-domain one.
func (s *Snapshot) MatchIOC(qdomain string) (*IOC, string) {
	if s == nil {
		return nil, ""
	}
	d := normalizeQuery(qdomain)
	if d == "" {
		return nil, ""
	}
	if ioc, ok := s.exact[d]; ok {
		return ioc, d
	}
	// Suffix match: walk labels right-to-left, checking each progressively
	// shorter suffix of the query against the suffix map.
	rest := d
	for {
		i := strings.IndexByte(rest, '.')
		if i < 0 {
			break
		}
		rest = rest[i+1:]
		if ioc, ok := s.suffix[rest]; ok {
			return ioc, rest
		}
	}
	return nil, ""
}

// Contains reports whether the exact domain is in the snapshot.
func (s *Snapshot) Contains(d string) bool {
	if s == nil {
		return false
	}
	_, ok := s.exact[normalizeQuery(d)]
	return ok
}

// LookupIOC returns the IOC for an exact normalized domain (nil if absent).
func (s *Snapshot) LookupIOC(d string) *IOC {
	if s == nil {
		return nil
	}
	return s.exact[normalizeQuery(d)]
}

// SortedDomains returns all exact domains sorted lexicographically, useful for
// deterministic tests and for exporting the snapshot.
func (s *Snapshot) SortedDomains() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.exact))
	for _, ioc := range s.exact {
		out = append(out, ioc.Domain)
	}
	sort.Strings(out)
	return out
}
