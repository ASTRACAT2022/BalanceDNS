package recursor

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func rrOrFatal(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("parse rr %q: %v", s, err)
	}
	return rr
}

func TestExtractZoneCutMetadata(t *testing.T) {
	resp := &dns.Msg{
		Ns: []dns.RR{
			rrOrFatal(t, "example.com. 300 IN NS ns1.example.net."),
			rrOrFatal(t, "example.com. 120 IN NS ns2.example.net."),
		},
	}
	zone, ttl, ok := extractZoneCutMetadata(resp)
	if !ok {
		t.Fatalf("expected zone cut metadata")
	}
	if got, want := zone, "example.com."; got != want {
		t.Fatalf("zone=%s want=%s", got, want)
	}
	if got, want := ttl, 120*time.Second; got != want {
		t.Fatalf("ttl=%s want=%s", got, want)
	}
}

func TestZoneCutStoreAndLookup(t *testing.T) {
	r := &Resolver{
		opts:         withDefaultOptions(Options{ZoneCutCacheEntries: 4}),
		zoneCutCache: make(map[string]zoneCutEntry),
	}

	r.storeZoneCut("example.com.", []string{"ns1.example.net."}, []string{"203.0.113.10", "203.0.113.11"}, 30*time.Second)
	servers := r.lookupZoneCutServers("www.api.example.com.")
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}
	if servers[0] != "203.0.113.10:53" || servers[1] != "203.0.113.11:53" {
		t.Fatalf("unexpected servers: %#v", servers)
	}
}

func TestZoneCutLookupSkipsExpired(t *testing.T) {
	r := &Resolver{
		opts: withDefaultOptions(Options{ZoneCutCacheEntries: 4}),
		zoneCutCache: map[string]zoneCutEntry{
			"example.com.": {
				zone:      "example.com.",
				nsIPs:     []string{"203.0.113.10:53"},
				expiresAt: time.Now().Add(-time.Second),
			},
		},
	}

	servers := r.lookupZoneCutServers("a.example.com.")
	if len(servers) != 0 {
		t.Fatalf("expected no servers for expired zonecut")
	}
}
