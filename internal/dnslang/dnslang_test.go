package dnslang

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestDNSLangPreflightIPAndSuffixRules(t *testing.T) {
	policy := `
set banned = ipset(["192.0.2.0/24"])
set trackers = suffixes(["doubleclick.net", "ads.example"])

rule block_banned_ip {
  phase = preflight
  when = client_ip in banned
  action = drop
}

rule block_tracker_suffix {
  phase = preflight
  when = qname suffix in trackers and transport in [udp, tcp]
  action = refuse
}
`

	engine, err := LoadString("inline", policy)
	if err != nil {
		t.Fatalf("LoadString() error = %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("api.doubleclick.net.", dns.TypeA)

	result := engine.Apply(PhasePreflight, EvalContext{Transport: "udp", ClientIP: "198.51.100.7"}, req)
	if !result.Handled {
		t.Fatal("expected preflight rule to handle request")
	}
	if result.Drop {
		t.Fatal("expected REFUSED response, got drop")
	}
	if result.Response == nil || result.Response.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED response, got %#v", result.Response)
	}

	dropped := engine.Apply(PhasePreflight, EvalContext{Transport: "udp", ClientIP: "192.0.2.10"}, req)
	if !dropped.Handled || !dropped.Drop {
		t.Fatalf("expected silent drop for banned IP, got %+v", dropped)
	}
}

func TestDNSLangHostsAndPoolActions(t *testing.T) {
	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts.txt")
	poolPath := filepath.Join(dir, "pool.txt")

	writeFile(t, hostsPath, "203.0.113.10 app.internal\n2001:db8::10 app.internal\n")
	writeFile(t, poolPath, "198.51.100.10\n198.51.100.11\n2001:db8::20\n")

	policy := `
set app_hosts = hosts("` + hostsPath + `")
set edge_pool = ippool("` + poolPath + `")

rule answer_from_hosts {
  phase = policy
  when = qname in app_hosts and qtype in [A, AAAA]
  action = answer from app_hosts ttl 120
}

rule balance_edge_pool {
  phase = policy
  when = qname suffix "edge.example" and qtype == A
  action = load_balance from edge_pool ttl 20 strategy round_robin
}
`

	engine, err := LoadString("files", policy)
	if err != nil {
		t.Fatalf("LoadString() error = %v", err)
	}

	reqHosts := new(dns.Msg)
	reqHosts.SetQuestion("app.internal.", dns.TypeA)
	resultHosts := engine.Apply(PhasePolicy, EvalContext{Transport: "udp", ClientIP: "198.51.100.4"}, reqHosts)
	if !resultHosts.Handled || resultHosts.Response == nil {
		t.Fatalf("expected host-based answer, got %+v", resultHosts)
	}
	if len(resultHosts.Response.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resultHosts.Response.Answer))
	}
	if got := resultHosts.Response.Answer[0].String(); got == "" || !containsAll(got, "203.0.113.10", "120") {
		t.Fatalf("unexpected hosts answer %q", got)
	}

	reqPool := new(dns.Msg)
	reqPool.SetQuestion("api.edge.example.", dns.TypeA)
	first := engine.Apply(PhasePolicy, EvalContext{Transport: "udp", ClientIP: "198.51.100.4"}, reqPool)
	second := engine.Apply(PhasePolicy, EvalContext{Transport: "udp", ClientIP: "198.51.100.4"}, reqPool)
	if !first.Handled || !second.Handled {
		t.Fatalf("expected load balancer answers, got first=%+v second=%+v", first, second)
	}
	if first.Response.Answer[0].String() == second.Response.Answer[0].String() {
		t.Fatalf("expected round robin answers to differ, got %q", first.Response.Answer[0].String())
	}
}

func TestDNSLangInlineAnswerAndBooleanExpressions(t *testing.T) {
	policy := `
rule direct_answer {
  phase = policy
  when = transport == doh and qtype == AAAA and not (qname suffix "blocked.example")
  action = answer AAAA "2001:db8::53" ttl 45
}
`

	engine, err := LoadString("inline-answer", policy)
	if err != nil {
		t.Fatalf("LoadString() error = %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("resolver.example.", dns.TypeAAAA)

	result := engine.Apply(PhasePolicy, EvalContext{Transport: "doh", ClientIP: "203.0.113.1"}, req)
	if !result.Handled || result.Response == nil {
		t.Fatalf("expected synthetic AAAA answer, got %+v", result)
	}
	answer := result.Response.Answer[0].String()
	if !containsAll(answer, "2001:db8::53", "45") {
		t.Fatalf("unexpected AAAA answer %q", answer)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}
