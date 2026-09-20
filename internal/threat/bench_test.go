package threat

import (
	"fmt"
	"testing"
)

// BenchmarkMatchIOC measures the hot-path O(labels) lookup cost against a
// large snapshot. 2M domains => suffix map lookups per query are O(labels), not
// O(N); this benchmark documents that the threat check does not add latency
// materially.
func BenchmarkMatchIOC(b *testing.B) {
	const n = 2_000_000
	iocs := make([]*IOC, 0, n)
	for i := 0; i < n; i++ {
		iocs = append(iocs, &IOC{
			Domain:     fmt.Sprintf("domain%d.example.net", i),
			Category:   CategoryBotnetC2,
			Confidence: ConfidenceHigh,
		})
	}
	snap := BuildSnapshot(iocs)

	queries := []string{
		"notblocked.clean.example.",
		"domain0.example.net.",
		"deep.sub.domain1234567.example.net.",
		"www.google.com.",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q := queries[i%len(queries)]
		if _, _ = snap.MatchIOC(q); true {
		}
	}
}
