package dnsproxy

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

type rewriteRule struct {
	domainPattern string
	isWildcard    bool
	qtype         uint16
	ttl           uint32
	value         string
}

type lbRule struct {
	domainPattern string
	isWildcard    bool
	qtype         uint16
	ttl           uint32
	strategy      string
	targets       []string
	cursor        atomic.Uint64
}

type policyEngine struct {
	enabled         bool
	blockedExact    map[string]struct{}
	blockedWildcard []string
	rewriteRules    []rewriteRule
	lbRules         []lbRule
}

func newPolicyEngine(opts ProxyPolicyOptions) *policyEngine {
	if !opts.Enabled {
		return nil
	}

	engine := &policyEngine{
		enabled:      true,
		blockedExact: make(map[string]struct{}),
		rewriteRules: make([]rewriteRule, 0, len(opts.RewriteRules)),
		lbRules:      make([]lbRule, 0, len(opts.LoadBalancers)),
	}

	for _, raw := range opts.BlockedDomains {
		domain, isWildcard := normalizePattern(raw)
		if domain == "" {
			continue
		}
		if isWildcard {
			engine.blockedWildcard = append(engine.blockedWildcard, domain)
		} else {
			engine.blockedExact[domain] = struct{}{}
		}
	}

	for _, raw := range opts.RewriteRules {
		domain, isWildcard := normalizePattern(raw.Domain)
		qtype, ok := parseDNSQType(raw.Type)
		if !ok || domain == "" || raw.Value == "" {
			continue
		}
		ttl := raw.TTL
		if ttl == 0 {
			ttl = 60
		}
		engine.rewriteRules = append(engine.rewriteRules, rewriteRule{
			domainPattern: domain,
			isWildcard:    isWildcard,
			qtype:         qtype,
			ttl:           ttl,
			value:         strings.TrimSpace(raw.Value),
		})
	}

	for _, raw := range opts.LoadBalancers {
		domain, isWildcard := normalizePattern(raw.Domain)
		qtype, ok := parseDNSQType(raw.Type)
		if !ok || domain == "" {
			continue
		}
		if qtype != dns.TypeA && qtype != dns.TypeAAAA {
			continue
		}
		ttl := raw.TTL
		if ttl == 0 {
			ttl = 30
		}

		targets := make([]string, 0)
		for _, t := range raw.Targets {
			v := strings.TrimSpace(t.Value)
			if v == "" {
				continue
			}
			if ip := net.ParseIP(v); ip == nil {
				continue
			}
			weight := t.Weight
			if weight <= 0 {
				weight = 1
			}
			if weight > 100 {
				weight = 100
			}
			for i := 0; i < weight; i++ {
				targets = append(targets, v)
			}
		}
		if len(targets) == 0 {
			continue
		}

		strategy := strings.ToLower(strings.TrimSpace(raw.Strategy))
		if strategy == "" {
			strategy = "round_robin"
		}
		engine.lbRules = append(engine.lbRules, lbRule{
			domainPattern: domain,
			isWildcard:    isWildcard,
			qtype:         qtype,
			ttl:           ttl,
			strategy:      strategy,
			targets:       targets,
		})
	}

	if len(engine.blockedExact) == 0 && len(engine.blockedWildcard) == 0 && len(engine.rewriteRules) == 0 && len(engine.lbRules) == 0 {
		return nil
	}

	return engine
}

func (p *policyEngine) apply(r *dns.Msg) (*dns.Msg, bool, string) {
	if p == nil || !p.enabled || r == nil || len(r.Question) == 0 {
		return nil, false, ""
	}

	q := r.Question[0]
	qName := normalizeDomain(q.Name)

	if p.isBlocked(qName) {
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeNameError)
		return resp, true, "block"
	}

	for _, rw := range p.rewriteRules {
		if rw.qtype != q.Qtype {
			continue
		}
		if !matchDomainPattern(qName, rw.domainPattern, rw.isWildcard) {
			continue
		}
		rr, err := buildRR(q.Name, q.Qtype, rw.ttl, rw.value)
		if err != nil {
			continue
		}
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = true
		resp.Answer = []dns.RR{rr}
		return resp, true, "rewrite"
	}

	for i := range p.lbRules {
		rule := &p.lbRules[i]
		if rule.qtype != q.Qtype {
			continue
		}
		if !matchDomainPattern(qName, rule.domainPattern, rule.isWildcard) {
			continue
		}
		target := rule.pickTarget()
		if target == "" {
			continue
		}
		rr, err := buildRR(q.Name, q.Qtype, rule.ttl, target)
		if err != nil {
			continue
		}
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = true
		resp.Answer = []dns.RR{rr}
		return resp, true, "load_balance"
	}

	return nil, false, ""
}

func (p *policyEngine) isBlocked(qName string) bool {
	if _, ok := p.blockedExact[qName]; ok {
		return true
	}
	for _, suffix := range p.blockedWildcard {
		if matchDomainPattern(qName, suffix, true) {
			return true
		}
	}
	return false
}

func (l *lbRule) pickTarget() string {
	if len(l.targets) == 0 {
		return ""
	}
	next := l.cursor.Add(1)
	return l.targets[(next-1)%uint64(len(l.targets))]
}

func normalizeDomain(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return ""
	}
	if !strings.HasSuffix(d, ".") {
		d += "."
	}
	return d
}

func normalizePattern(pattern string) (domain string, wildcard bool) {
	raw := strings.TrimSpace(pattern)
	if raw == "" {
		return "", false
	}
	if strings.HasPrefix(raw, "*.") {
		return normalizeDomain(strings.TrimPrefix(raw, "*.")), true
	}
	return normalizeDomain(raw), false
}

func matchDomainPattern(qName, pattern string, wildcard bool) bool {
	if !wildcard {
		return qName == pattern
	}
	if qName == pattern {
		return false
	}
	return strings.HasSuffix(qName, "."+strings.TrimSuffix(pattern, ".")+".") || strings.HasSuffix(qName, pattern)
}

func parseDNSQType(s string) (uint16, bool) {
	v := strings.ToUpper(strings.TrimSpace(s))
	if v == "" {
		return 0, false
	}
	t, ok := dns.StringToType[v]
	return t, ok
}

func buildRR(name string, qtype uint16, ttl uint32, value string) (dns.RR, error) {
	typeName := dns.TypeToString[qtype]
	if typeName == "" {
		return nil, fmt.Errorf("unsupported qtype: %d", qtype)
	}
	val := strings.TrimSpace(value)
	switch qtype {
	case dns.TypeCNAME:
		if !strings.HasSuffix(val, ".") {
			val += "."
		}
	case dns.TypeTXT:
		val = fmt.Sprintf("\"%s\"", val)
	}
	return dns.NewRR(fmt.Sprintf("%s %d IN %s %s", name, ttl, typeName, val))
}
