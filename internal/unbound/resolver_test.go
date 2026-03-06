//go:build cgo && unbound
// +build cgo,unbound

package unbound

import (
	"testing"

	"github.com/miekg/dns"
	ub "github.com/miekg/unbound"
)

func TestResponseFromResult_NoDataNoError(t *testing.T) {
	q := dns.Question{Name: "ipv4only.arpa.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	res := &ub.Result{
		Qname:    q.Name,
		Qtype:    q.Qtype,
		Qclass:   q.Qclass,
		HaveData: false,
		NxDomain: false,
		Rcode:    dns.RcodeSuccess,
	}

	msg, err := responseFromResult(q, res)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[msg.Rcode])
	}
	if len(msg.Answer) != 0 {
		t.Fatalf("expected empty answer for NODATA, got %d", len(msg.Answer))
	}
	if len(msg.Question) != 1 || msg.Question[0].Name != q.Name {
		t.Fatalf("unexpected question section: %+v", msg.Question)
	}
}

func TestResponseFromResult_UsesAnswerPacket(t *testing.T) {
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	packet := new(dns.Msg)
	packet.SetQuestion(q.Name, q.Qtype)
	rr, err := dns.NewRR("example.com. 60 IN A 93.184.216.34")
	if err != nil {
		t.Fatalf("failed to build rr: %v", err)
	}
	packet.Answer = []dns.RR{rr}

	res := &ub.Result{
		AnswerPacket: packet,
		Rcode:        dns.RcodeSuccess,
		Secure:       true,
	}

	msg, err := responseFromResult(q, res)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answer))
	}
	if !msg.AuthenticatedData {
		t.Fatal("expected AD flag to be set")
	}
	if msg.Question[0].Name != q.Name {
		t.Fatalf("unexpected qname: %s", msg.Question[0].Name)
	}
}
