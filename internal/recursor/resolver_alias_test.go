package recursor

import (
	"testing"

	"github.com/miekg/dns"
)

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("failed to parse RR %q: %v", s, err)
	}
	return rr
}

func TestHasDirectAnswerForQuestion_IgnoresCNAMEForA(t *testing.T) {
	resp := &dns.Msg{
		Answer: []dns.RR{
			mustRR(t, "www.example.org. 60 IN CNAME target.example.org."),
		},
	}
	q := dns.Question{Name: "www.example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	if hasDirectAnswerForQuestion(resp, q) {
		t.Fatalf("expected no direct A answer when only CNAME is present")
	}
}

func TestHasDirectAnswerForQuestion_CNAMEQuery(t *testing.T) {
	resp := &dns.Msg{
		Answer: []dns.RR{
			mustRR(t, "www.example.org. 60 IN CNAME target.example.org."),
		},
	}
	q := dns.Question{Name: "www.example.org.", Qtype: dns.TypeCNAME, Qclass: dns.ClassINET}
	if !hasDirectAnswerForQuestion(resp, q) {
		t.Fatalf("expected direct CNAME answer")
	}
}

func TestFindAliasTarget_CNAME(t *testing.T) {
	resp := &dns.Msg{
		Answer: []dns.RR{
			mustRR(t, "www.example.org. 60 IN CNAME target.example.org."),
		},
	}
	target, ok := findAliasTarget(resp, "www.example.org.")
	if !ok {
		t.Fatalf("expected CNAME alias target")
	}
	if target != "target.example.org." {
		t.Fatalf("unexpected target: got %q", target)
	}
}

func TestFindAliasTarget_DNAME(t *testing.T) {
	resp := &dns.Msg{
		Answer: []dns.RR{
			mustRR(t, "example.org. 300 IN DNAME example.net."),
		},
	}
	target, ok := findAliasTarget(resp, "a.b.example.org.")
	if !ok {
		t.Fatalf("expected DNAME alias target")
	}
	if target != "a.b.example.net." {
		t.Fatalf("unexpected target: got %q", target)
	}
}

func TestFindAliasTarget_DNAMEUsesLongestSuffix(t *testing.T) {
	resp := &dns.Msg{
		Answer: []dns.RR{
			mustRR(t, "example.org. 300 IN DNAME example.net."),
			mustRR(t, "b.example.org. 300 IN DNAME b.example.com."),
		},
	}
	target, ok := findAliasTarget(resp, "x.b.example.org.")
	if !ok {
		t.Fatalf("expected DNAME alias target")
	}
	if target != "x.b.example.com." {
		t.Fatalf("unexpected target: got %q", target)
	}
}
