package dnslang

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

type Engine struct {
	program Program
	sets    map[string]compiledSet
	rules   map[Phase][]*compiledRule
}

type compiledRule struct {
	spec   RuleSpec
	cursor atomic.Uint64
}

type compiledSet interface{}

type stringSet struct {
	values map[string]struct{}
}

type domainSet struct {
	values map[string]struct{}
}

type suffixSet struct {
	values []string
}

type ipSet struct {
	nets []*net.IPNet
}

type ipPool struct {
	v4 []net.IP
	v6 []net.IP
}

type hostsSet struct {
	names map[string]struct{}
	v4    map[string][]net.IP
	v6    map[string][]net.IP
}

func Compile(program *Program) (*Engine, error) {
	if program == nil {
		return nil, fmt.Errorf("program is nil")
	}

	engine := &Engine{
		program: *program,
		sets:    make(map[string]compiledSet, len(program.Sets)),
		rules: map[Phase][]*compiledRule{
			PhasePreflight: make([]*compiledRule, 0),
			PhasePolicy:    make([]*compiledRule, 0),
		},
	}

	for _, decl := range program.Sets {
		if _, exists := engine.sets[decl.Name]; exists {
			return nil, fmt.Errorf("duplicate set %q", decl.Name)
		}
		set, err := compileSet(decl)
		if err != nil {
			return nil, fmt.Errorf("set %q: %w", decl.Name, err)
		}
		engine.sets[decl.Name] = set
	}

	for _, rule := range program.Rules {
		compiled := &compiledRule{spec: rule}
		engine.rules[rule.Phase] = append(engine.rules[rule.Phase], compiled)
	}

	return engine, nil
}

func (e *Engine) Apply(phase Phase, ctx EvalContext, req *dns.Msg) Result {
	if e == nil || req == nil || len(req.Question) == 0 {
		return Result{}
	}

	env := &evalEnv{
		engine:   e,
		ctx:      normalizeEvalContext(ctx),
		req:      req,
		question: req.Question[0],
	}

	for _, rule := range e.rules[phase] {
		if rule == nil || rule.spec.When == nil || !rule.spec.When.eval(env) {
			continue
		}

		result, ok := e.executeRule(rule, env)
		if ok {
			return result
		}
	}

	return Result{}
}

func normalizeEvalContext(ctx EvalContext) EvalContext {
	ctx.Transport = strings.ToLower(strings.TrimSpace(ctx.Transport))
	ctx.ClientIP = strings.TrimSpace(ctx.ClientIP)
	if ctx.ClientIP == "" {
		ctx.ClientIP = "unknown"
	}
	return ctx
}

func (e *Engine) executeRule(rule *compiledRule, env *evalEnv) (Result, bool) {
	action := rule.spec.Action
	switch action.Kind {
	case ActionDrop:
		return Result{Handled: true, Drop: true, Action: string(ActionDrop), Rule: rule.spec.Name}, true
	case ActionRefuse:
		msg := new(dns.Msg)
		msg.SetRcode(env.req, dns.RcodeRefused)
		return Result{Handled: true, Response: msg, Action: string(ActionRefuse), Rule: rule.spec.Name}, true
	case ActionNXDOMAIN:
		msg := new(dns.Msg)
		msg.SetRcode(env.req, dns.RcodeNameError)
		return Result{Handled: true, Response: msg, Action: string(ActionNXDOMAIN), Rule: rule.spec.Name}, true
	case ActionEmpty:
		msg := new(dns.Msg)
		msg.SetReply(env.req)
		return Result{Handled: true, Response: msg, Action: string(ActionEmpty), Rule: rule.spec.Name}, true
	case ActionAnswer:
		msg, ok := e.buildAnswerResponse(action, env)
		if !ok {
			return Result{}, false
		}
		return Result{Handled: true, Response: msg, Action: string(ActionAnswer), Rule: rule.spec.Name}, true
	case ActionSpoof:
		msg, ok := e.buildPoolResponse(action, env, rule, false)
		if !ok {
			return Result{}, false
		}
		return Result{Handled: true, Response: msg, Action: string(ActionSpoof), Rule: rule.spec.Name}, true
	case ActionLoadBalance:
		msg, ok := e.buildPoolResponse(action, env, rule, true)
		if !ok {
			return Result{}, false
		}
		return Result{Handled: true, Response: msg, Action: string(ActionLoadBalance), Rule: rule.spec.Name}, true
	default:
		return Result{}, false
	}
}

func (e *Engine) buildAnswerResponse(action ActionSpec, env *evalEnv) (*dns.Msg, bool) {
	q := env.question
	ttl := action.TTL
	if ttl == 0 {
		ttl = 60
	}

	if action.SetName != "" {
		set, ok := e.sets[action.SetName]
		if !ok {
			return nil, false
		}
		hosts, ok := set.(*hostsSet)
		if !ok {
			return nil, false
		}
		ip, ok := hosts.lookup(q.Name, q.Qtype)
		if !ok {
			return nil, false
		}
		rr, err := buildRR(q.Name, q.Qtype, ttl, ip.String())
		if err != nil {
			return nil, false
		}
		return makeAnswerResponse(env.req, rr), true
	}

	answerType := action.Type
	if answerType == 0 {
		answerType = q.Qtype
	}
	if q.Qtype != dns.TypeANY && q.Qtype != answerType {
		return nil, false
	}

	rr, err := buildRR(q.Name, answerType, ttl, action.Value)
	if err != nil {
		return nil, false
	}
	return makeAnswerResponse(env.req, rr), true
}

func (e *Engine) buildPoolResponse(action ActionSpec, env *evalEnv, rule *compiledRule, balance bool) (*dns.Msg, bool) {
	set, ok := e.sets[action.SetName]
	if !ok {
		return nil, false
	}
	pool, ok := set.(*ipPool)
	if !ok {
		return nil, false
	}
	ttl := action.TTL
	if ttl == 0 {
		ttl = 30
	}

	targets := pool.targetsForQType(env.question.Qtype)
	if len(targets) == 0 {
		return nil, false
	}

	picked := targets[0]
	if balance {
		switch strings.ToLower(strings.TrimSpace(action.Strategy)) {
		case "", "round_robin":
			next := rule.cursor.Add(1)
			picked = targets[(next-1)%uint64(len(targets))]
		case "random":
			picked = targets[rand.Intn(len(targets))]
		case "first":
			picked = targets[0]
		default:
			return nil, false
		}
	}

	rr, err := buildRR(env.question.Name, env.question.Qtype, ttl, picked.String())
	if err != nil {
		return nil, false
	}
	return makeAnswerResponse(env.req, rr), true
}

func makeAnswerResponse(req *dns.Msg, rr dns.RR) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true
	msg.Answer = []dns.RR{rr}
	return msg
}

func compileSet(decl SetDecl) (compiledSet, error) {
	values, err := loadSetValues(decl.Source)
	if err != nil {
		return nil, err
	}

	switch decl.Source.Kind {
	case SetStrings:
		out := &stringSet{values: make(map[string]struct{}, len(values))}
		for _, value := range values {
			norm := strings.ToLower(strings.TrimSpace(value))
			if norm == "" {
				continue
			}
			out.values[norm] = struct{}{}
		}
		return out, nil
	case SetDomains:
		out := &domainSet{values: make(map[string]struct{}, len(values))}
		for _, value := range values {
			norm := normalizeDomain(value)
			if norm == "" {
				continue
			}
			out.values[norm] = struct{}{}
		}
		return out, nil
	case SetSuffixes:
		out := &suffixSet{values: make([]string, 0, len(values))}
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			norm := normalizeDomain(value)
			if norm == "" {
				continue
			}
			if _, ok := seen[norm]; ok {
				continue
			}
			seen[norm] = struct{}{}
			out.values = append(out.values, norm)
		}
		return out, nil
	case SetIPSet:
		out := &ipSet{nets: make([]*net.IPNet, 0, len(values))}
		for _, value := range values {
			nets, err := parseIPSetEntry(value)
			if err != nil {
				return nil, err
			}
			out.nets = append(out.nets, nets...)
		}
		return out, nil
	case SetIPPool:
		out := &ipPool{v4: make([]net.IP, 0, len(values)), v6: make([]net.IP, 0, len(values))}
		for _, value := range values {
			ip := net.ParseIP(strings.TrimSpace(value))
			if ip == nil {
				return nil, fmt.Errorf("invalid ip %q", value)
			}
			if ip4 := ip.To4(); ip4 != nil {
				out.v4 = append(out.v4, ip4)
			} else {
				out.v6 = append(out.v6, ip)
			}
		}
		return out, nil
	case SetHosts:
		return parseHostsSet(decl.Source)
	default:
		return nil, fmt.Errorf("unsupported set kind %q", decl.Source.Kind)
	}
}

func loadSetValues(source SetSource) ([]string, error) {
	if source.Path != "" {
		file, err := os.Open(source.Path)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		values := make([]string, 0)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(stripInlineComment(scanner.Text()))
			if line == "" {
				continue
			}
			values = append(values, line)
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		return values, nil
	}
	return append([]string(nil), source.Values...), nil
}

func parseHostsSet(source SetSource) (*hostsSet, error) {
	lines, err := loadSetValues(source)
	if err != nil {
		return nil, err
	}
	out := &hostsSet{
		names: make(map[string]struct{}),
		v4:    make(map[string][]net.IP),
		v6:    make(map[string][]net.IP),
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("invalid hosts entry %q", line)
		}
		ip := net.ParseIP(fields[0])
		if ip == nil {
			return nil, fmt.Errorf("invalid hosts ip %q", fields[0])
		}
		for _, rawName := range fields[1:] {
			name := normalizeDomain(rawName)
			if name == "" {
				continue
			}
			out.names[name] = struct{}{}
			if ip4 := ip.To4(); ip4 != nil {
				out.v4[name] = append(out.v4[name], ip4)
			} else {
				out.v6[name] = append(out.v6[name], ip)
			}
		}
	}
	return out, nil
}

func parseIPSetEntry(raw string) ([]*net.IPNet, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if strings.Contains(raw, "/") {
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid cidr %q", raw)
		}
		return []*net.IPNet{network}, nil
	}

	ip := net.ParseIP(raw)
	if ip == nil {
		return nil, fmt.Errorf("invalid ip %q", raw)
	}
	maskBits := 128
	if ip.To4() != nil {
		maskBits = 32
		ip = ip.To4()
	}
	return []*net.IPNet{{IP: ip, Mask: net.CIDRMask(maskBits, maskBits)}}, nil
}

func (e *binaryExpr) eval(env *evalEnv) bool {
	switch e.Op {
	case "and":
		return e.Left.eval(env) && e.Right.eval(env)
	case "or":
		return e.Left.eval(env) || e.Right.eval(env)
	default:
		return false
	}
}

func (e *unaryExpr) eval(env *evalEnv) bool {
	if e.Op == "not" {
		return !e.Expr.eval(env)
	}
	return false
}

func (e *conditionExpr) eval(env *evalEnv) bool {
	lhs := fieldValue(e.Field, env)
	switch e.Comparator {
	case "==":
		return lhs == normalizeScalar(e.Field, e.Value.Text)
	case "!=":
		return lhs != normalizeScalar(e.Field, e.Value.Text)
	case "in":
		return valueContains(e.Field, lhs, e.Value, env.engine)
	case "suffix":
		return hasDomainSuffix(lhs, normalizeScalar("qname", e.Value.Text))
	case "suffix_in":
		return suffixInValue(lhs, e.Value, env.engine)
	default:
		return false
	}
}

func fieldValue(field string, env *evalEnv) string {
	switch field {
	case "qname":
		return normalizeDomain(env.question.Name)
	case "qtype":
		return strings.ToUpper(dns.TypeToString[env.question.Qtype])
	case "qclass":
		return strings.ToUpper(dns.ClassToString[env.question.Qclass])
	case "transport":
		return strings.ToLower(env.ctx.Transport)
	case "client_ip":
		return strings.TrimSpace(env.ctx.ClientIP)
	default:
		return ""
	}
}

func normalizeScalar(field, raw string) string {
	switch field {
	case "qname":
		return normalizeDomain(raw)
	case "qtype", "qclass":
		return strings.ToUpper(strings.TrimSpace(raw))
	case "transport":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func valueContains(field, lhs string, value valueNode, engine *Engine) bool {
	switch value.Kind {
	case valueList:
		for _, item := range value.List {
			if lhs == normalizeScalar(field, item.Text) {
				return true
			}
		}
		return false
	case valueScalar:
		if set, ok := engine.sets[value.Text]; ok {
			return setContains(field, lhs, set)
		}
		return lhs == normalizeScalar(field, value.Text)
	default:
		return false
	}
}

func suffixInValue(lhs string, value valueNode, engine *Engine) bool {
	switch value.Kind {
	case valueList:
		for _, item := range value.List {
			if hasDomainSuffix(lhs, normalizeScalar("qname", item.Text)) {
				return true
			}
		}
		return false
	case valueScalar:
		if set, ok := engine.sets[value.Text]; ok {
			switch typed := set.(type) {
			case *suffixSet:
				for _, suffix := range typed.values {
					if hasDomainSuffix(lhs, suffix) {
						return true
					}
				}
				return false
			case *domainSet:
				for suffix := range typed.values {
					if hasDomainSuffix(lhs, suffix) {
						return true
					}
				}
				return false
			case *hostsSet:
				for suffix := range typed.names {
					if hasDomainSuffix(lhs, suffix) {
						return true
					}
				}
				return false
			}
		}
		return hasDomainSuffix(lhs, normalizeScalar("qname", value.Text))
	default:
		return false
	}
}

func setContains(field, lhs string, set compiledSet) bool {
	switch typed := set.(type) {
	case *stringSet:
		_, ok := typed.values[strings.ToLower(lhs)]
		return ok
	case *domainSet:
		_, ok := typed.values[normalizeScalar(field, lhs)]
		return ok
	case *suffixSet:
		for _, suffix := range typed.values {
			if hasDomainSuffix(lhs, suffix) {
				return true
			}
		}
		return false
	case *ipSet:
		ip := net.ParseIP(lhs)
		if ip == nil {
			return false
		}
		for _, network := range typed.nets {
			if network.Contains(ip) {
				return true
			}
		}
		return false
	case *hostsSet:
		_, ok := typed.names[normalizeDomain(lhs)]
		return ok
	default:
		return false
	}
}

func (h *hostsSet) lookup(name string, qtype uint16) (net.IP, bool) {
	name = normalizeDomain(name)
	switch qtype {
	case dns.TypeA:
		values := h.v4[name]
		if len(values) == 0 {
			return nil, false
		}
		return values[0], true
	case dns.TypeAAAA:
		values := h.v6[name]
		if len(values) == 0 {
			return nil, false
		}
		return values[0], true
	default:
		return nil, false
	}
}

func (p *ipPool) targetsForQType(qtype uint16) []net.IP {
	switch qtype {
	case dns.TypeA:
		return p.v4
	case dns.TypeAAAA:
		return p.v6
	default:
		return nil
	}
}

func normalizeDomain(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return ""
	}
	if !strings.HasSuffix(value, ".") {
		value += "."
	}
	return value
}

func hasDomainSuffix(name, suffix string) bool {
	name = normalizeDomain(name)
	suffix = normalizeDomain(suffix)
	if name == "" || suffix == "" {
		return false
	}
	if name == suffix {
		return true
	}
	return strings.HasSuffix(name, "."+strings.TrimSuffix(suffix, ".")+".") || strings.HasSuffix(name, suffix)
}

func buildRR(name string, qtype uint16, ttl uint32, value string) (dns.RR, error) {
	typeName := dns.TypeToString[qtype]
	switch qtype {
	case dns.TypeA, dns.TypeAAAA:
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil {
			return nil, fmt.Errorf("invalid ip %q", value)
		}
		if qtype == dns.TypeA {
			ip = ip.To4()
			if ip == nil {
				return nil, fmt.Errorf("invalid IPv4 value %q", value)
			}
		}
		return dns.NewRR(fmt.Sprintf("%s %d IN %s %s", name, ttl, typeName, ip.String()))
	case dns.TypeCNAME:
		target := normalizeDomain(value)
		if target == "" {
			return nil, fmt.Errorf("invalid cname target")
		}
		return dns.NewRR(fmt.Sprintf("%s %d IN CNAME %s", name, ttl, target))
	case dns.TypeTXT:
		return dns.NewRR(fmt.Sprintf("%s %d IN TXT %s", name, ttl, strconv.Quote(value)))
	default:
		return nil, fmt.Errorf("unsupported rr type %s", typeName)
	}
}
