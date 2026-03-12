package anyblock

import (
	"testing"

	"github.com/miekg/dns"
)

func TestExecuteDropsANYQueries(t *testing.T) {
	p := New(true)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeANY)

	handled, err := p.Execute(nil, nil, req)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !handled {
		t.Fatal("expected ANY query to be handled")
	}
}

func TestExecutePassesNonANYQueries(t *testing.T) {
	p := New(true)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	handled, err := p.Execute(nil, nil, req)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if handled {
		t.Fatal("expected non-ANY query to pass through")
	}
}
