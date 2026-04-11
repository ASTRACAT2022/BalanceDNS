package hosts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

func TestLoadAndLookup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	content := `
# comment
127.0.0.10 local.test
::1 local.test
10.10.10.10 api.test www.api.test
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write hosts: %v", err)
	}

	table, err := Load(path, 120)
	if err != nil {
		t.Fatalf("load hosts: %v", err)
	}

	a, ok := table.Lookup("local.test", dns.TypeA)
	if !ok || len(a.IPs) != 1 || a.IPs[0].String() != "127.0.0.10" {
		t.Fatalf("unexpected A answer: %+v, ok=%v", a, ok)
	}
	if a.TTL != 120 {
		t.Fatalf("unexpected ttl: %d", a.TTL)
	}

	aaaa, ok := table.Lookup("local.test.", dns.TypeAAAA)
	if !ok || len(aaaa.IPs) != 1 || aaaa.IPs[0].String() != "::1" {
		t.Fatalf("unexpected AAAA answer: %+v, ok=%v", aaaa, ok)
	}

	any, ok := table.Lookup("api.test", dns.TypeANY)
	if !ok || len(any.IPs) != 1 || any.IPs[0].String() != "10.10.10.10" {
		t.Fatalf("unexpected ANY answer: %+v, ok=%v", any, ok)
	}

	_, ok = table.Lookup("missing.test", dns.TypeA)
	if ok {
		t.Fatalf("expected miss")
	}
}
