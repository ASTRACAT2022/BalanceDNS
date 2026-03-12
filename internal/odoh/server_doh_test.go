package odoh

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"testing"

	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"
	"dns-resolver/plugins/anyblock"

	"github.com/miekg/dns"
)

func mustPackedDNSQuery(t *testing.T, qName string, qType uint16) []byte {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion(qName, qType)
	wire, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack dns message: %v", err)
	}
	return wire
}

func TestParseDoHGETRequest(t *testing.T) {
	wire := mustPackedDNSQuery(t, "example.com.", dns.TypeA)
	param := base64.RawURLEncoding.EncodeToString(wire)

	req := httptest.NewRequest("GET", "/dns-query?dns="+param, nil)
	msg, err := parseDoHRequest(req)
	if err != nil {
		t.Fatalf("parseDoHRequest(GET): %v", err)
	}

	if len(msg.Question) != 1 {
		t.Fatalf("unexpected question count: %d", len(msg.Question))
	}
	if got, want := msg.Question[0].Name, "example.com."; got != want {
		t.Fatalf("unexpected qname: got=%q want=%q", got, want)
	}
}

func TestParseDoHPOSTRequest(t *testing.T) {
	wire := mustPackedDNSQuery(t, "ripe.net.", dns.TypeAAAA)
	req := httptest.NewRequest("POST", "/dns-query", bytes.NewReader(wire))
	req.Header.Set("Content-Type", "application/dns-message")

	msg, err := parseDoHRequest(req)
	if err != nil {
		t.Fatalf("parseDoHRequest(POST): %v", err)
	}

	if len(msg.Question) != 1 {
		t.Fatalf("unexpected question count: %d", len(msg.Question))
	}
	if got, want := msg.Question[0].Name, "ripe.net."; got != want {
		t.Fatalf("unexpected qname: got=%q want=%q", got, want)
	}
}

func TestParseDoHPOSTUnsupportedMediaType(t *testing.T) {
	wire := mustPackedDNSQuery(t, "example.org.", dns.TypeA)
	req := httptest.NewRequest("POST", "/dns-query", bytes.NewReader(wire))
	req.Header.Set("Content-Type", "application/json")

	_, err := parseDoHRequest(req)
	if !errors.Is(err, errUnsupportedDoHMediaType) {
		t.Fatalf("expected errUnsupportedDoHMediaType, got: %v", err)
	}
}

func TestResolveDNSMessageBlocksANYQueries(t *testing.T) {
	m := &metrics.Metrics{}
	s := &Server{Metrics: m, DropANYQueries: true}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeANY)

	resp, outcome, err := s.resolveDNSMessage(context.Background(), "odoh", req)
	if err != nil {
		t.Fatalf("resolveDNSMessage() error = %v", err)
	}
	if got, want := outcome, "security_drop_any_query"; got != want {
		t.Fatalf("unexpected outcome: got=%q want=%q", got, want)
	}
	if resp == nil {
		t.Fatal("expected DNS response")
	}
	if got, want := resp.Rcode, dns.RcodeRefused; got != want {
		t.Fatalf("unexpected rcode: got=%d want=%d", got, want)
	}

	snapshot := m.SnapshotDashboard()
	if got, want := snapshot.TotalQueries, int64(1); got != want {
		t.Fatalf("unexpected total queries: got=%d want=%d", got, want)
	}
	if got, want := typeCount(snapshot.QueryTypes, "ANY"), int64(1); got != want {
		t.Fatalf("unexpected ANY query count: got=%d want=%d", got, want)
	}
	if got, want := codeCount(snapshot.ResponseCodes, dns.RcodeToString[dns.RcodeRefused]), int64(1); got != want {
		t.Fatalf("unexpected REFUSED count: got=%d want=%d", got, want)
	}
}

func TestResolveDNSMessagePreflightAnyBlockPlugin(t *testing.T) {
	m := &metrics.Metrics{}
	pm := plugins.NewPluginManager()
	pm.Register(anyblock.New(true))

	s := &Server{Metrics: m, PM: pm}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeANY)

	resp, outcome, err := s.resolveDNSMessage(context.Background(), "odoh", req)
	if err != nil {
		t.Fatalf("resolveDNSMessage() error = %v", err)
	}
	if got, want := outcome, "security_drop_any_query"; got != want {
		t.Fatalf("unexpected outcome: got=%q want=%q", got, want)
	}
	if resp == nil || resp.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED response, got %#v", resp)
	}
}

func typeCount(items []metrics.TypeCount, value string) int64 {
	for _, item := range items {
		if item.Type == value {
			return item.Count
		}
	}
	return 0
}

func codeCount(items []metrics.CodeCount, value string) int64 {
	for _, item := range items {
		if item.Code == value {
			return item.Count
		}
	}
	return 0
}
