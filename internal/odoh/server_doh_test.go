package odoh

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"testing"

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
