package dnsdistcompat

import (
	"dns-resolver/internal/plugins"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

// Config configures dnsdist-compatible policy behavior.
type Config struct {
	LogAll             bool
	BannedIPsPath      string
	SNIProxyIPsPath    string
	DomainsWithSubPath string
	CustomPath         string
	DomainsPath        string
	HostsPath          string
	GarbagePath        string
	DropSuffixes       []string
	LateDropSuffixes   []string
}

// Plugin applies a dnsdist-like action chain before recursion.
type Plugin struct {
	mu sync.RWMutex

	cfg Config

	bannedPrefixes   []netip.Prefix
	sniProxyIPs      []netip.Addr
	proxySuffixes    []string
	customSuffixes   []string
	exactProxyNames  map[string]struct{}
	hostsMap         map[string]netip.Addr
	garbageNames     map[string]struct{}
	dropSuffixes     []string
	lateDropSuffixes []string

	rrCounter atomic.Uint64
}

// New creates and initializes dnsdist compatibility plugin.
func New(cfg Config) *Plugin {
	p := &Plugin{
		cfg:             cfg,
		exactProxyNames: make(map[string]struct{}),
		hostsMap:        make(map[string]netip.Addr),
		garbageNames:    make(map[string]struct{}),
	}
	p.reloadLocked()
	return p
}

func (p *Plugin) Name() string {
	return "dnsdist_compat"
}

func (p *Plugin) Execute(_ *plugins.PluginContext, w dns.ResponseWriter, r *dns.Msg) (bool, error) {
	if r == nil || len(r.Question) == 0 {
		return false, nil
	}
	q := r.Question[0]
	qName := normalizeDomain(q.Name)
	if qName == "" {
		return false, nil
	}

	p.mu.RLock()
	logAll := p.cfg.LogAll
	bannedPrefixes := p.bannedPrefixes
	dropSuffixes := p.dropSuffixes
	lateDropSuffixes := p.lateDropSuffixes
	proxySuffixes := p.proxySuffixes
	customSuffixes := p.customSuffixes
	exactProxyNames := p.exactProxyNames
	hostsMap := p.hostsMap
	garbageNames := p.garbageNames
	sniProxyIPs := p.sniProxyIPs
	p.mu.RUnlock()

	clientIP := extractClientIP(w)
	if logAll {
		log.Printf("[dnsdist_compat] client=%s qname=%s qtype=%s", clientIP.String(), qName, dns.TypeToString[q.Qtype])
	}

	if clientIP.IsValid() {
		for _, prefix := range bannedPrefixes {
			if prefix.Contains(clientIP) {
				// DropAction(): handle query without sending a response.
				return true, nil
			}
		}
	}

	if q.Qtype == dns.TypeANY {
		// DropAction() for ANY requests.
		return true, nil
	}

	if matchesAnySuffix(qName, dropSuffixes) {
		return true, nil
	}

	if matchesAnySuffix(qName, proxySuffixes) || matchesAnySuffix(qName, customSuffixes) {
		p.writeSpoofReply(w, r, qName, q.Qtype, sniProxyIPs)
		return true, nil
	}

	if ip, ok := hostsMap[qName]; ok {
		switch q.Qtype {
		case dns.TypeA:
			if ip.Is4() {
				p.writeSpoofReply(w, r, qName, q.Qtype, []netip.Addr{ip})
				return true, nil
			}
			p.writeNoErrorEmpty(w, r)
			return true, nil
		case dns.TypeAAAA:
			// dnsdist script explicitly returns NOERROR empty for AAAA.
			p.writeNoErrorEmpty(w, r)
			return true, nil
		}
	}

	if _, ok := exactProxyNames[qName]; ok {
		p.writeSpoofReply(w, r, qName, q.Qtype, sniProxyIPs)
		return true, nil
	}

	if matchesAnySuffix(qName, lateDropSuffixes) {
		return true, nil
	}

	if _, ok := garbageNames[qName]; ok {
		p.writeNXDOMAIN(w, r)
		return true, nil
	}

	return false, nil
}

func (p *Plugin) GetConfig() map[string]any {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return map[string]any{
		"logAll":             p.cfg.LogAll,
		"bannedIPsPath":      p.cfg.BannedIPsPath,
		"sniProxyIPsPath":    p.cfg.SNIProxyIPsPath,
		"domainsWithSubPath": p.cfg.DomainsWithSubPath,
		"customPath":         p.cfg.CustomPath,
		"domainsPath":        p.cfg.DomainsPath,
		"hostsPath":          p.cfg.HostsPath,
		"garbagePath":        p.cfg.GarbagePath,
		"dropSuffixes":       append([]string(nil), p.cfg.DropSuffixes...),
		"lateDropSuffixes":   append([]string(nil), p.cfg.LateDropSuffixes...),
	}
}

func (p *Plugin) SetConfig(config map[string]any) error {
	p.mu.Lock()
	if v, ok := config["logAll"].(bool); ok {
		p.cfg.LogAll = v
	} else if v, ok := config["logAll"].(string); ok {
		p.cfg.LogAll = strings.EqualFold(strings.TrimSpace(v), "true")
	}
	if v, ok := config["bannedIPsPath"].(string); ok {
		p.cfg.BannedIPsPath = v
	}
	if v, ok := config["sniProxyIPsPath"].(string); ok {
		p.cfg.SNIProxyIPsPath = v
	}
	if v, ok := config["domainsWithSubPath"].(string); ok {
		p.cfg.DomainsWithSubPath = v
	}
	if v, ok := config["customPath"].(string); ok {
		p.cfg.CustomPath = v
	}
	if v, ok := config["domainsPath"].(string); ok {
		p.cfg.DomainsPath = v
	}
	if v, ok := config["hostsPath"].(string); ok {
		p.cfg.HostsPath = v
	}
	if v, ok := config["garbagePath"].(string); ok {
		p.cfg.GarbagePath = v
	}
	if v, ok := config["dropSuffixes"]; ok {
		p.cfg.DropSuffixes = parseListConfig(v)
	}
	if v, ok := config["lateDropSuffixes"]; ok {
		p.cfg.LateDropSuffixes = parseListConfig(v)
	}
	p.reloadLocked()
	p.mu.Unlock()
	return nil
}

func (p *Plugin) GetConfigFields() []plugins.ConfigField {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return []plugins.ConfigField{
		{Name: "logAll", Description: "Log all incoming DNS queries", Type: "boolean", Value: p.cfg.LogAll},
		{Name: "bannedIPsPath", Description: "Path to banned IP CIDR list", Type: "text", Value: p.cfg.BannedIPsPath},
		{Name: "sniProxyIPsPath", Description: "Path to spoof IP list", Type: "text", Value: p.cfg.SNIProxyIPsPath},
		{Name: "domainsWithSubPath", Description: "Path to suffix-spoof domains list", Type: "text", Value: p.cfg.DomainsWithSubPath},
		{Name: "customPath", Description: "Path to custom suffix-spoof domains list", Type: "text", Value: p.cfg.CustomPath},
		{Name: "domainsPath", Description: "Path to exact-spoof domains list", Type: "text", Value: p.cfg.DomainsPath},
		{Name: "hostsPath", Description: "Path to hosts override file", Type: "text", Value: p.cfg.HostsPath},
		{Name: "garbagePath", Description: "Path to garbage domains list", Type: "text", Value: p.cfg.GarbagePath},
		{Name: "dropSuffixes", Description: "Suffixes to silently drop", Type: "text", Value: strings.Join(p.cfg.DropSuffixes, ",")},
		{Name: "lateDropSuffixes", Description: "Late suffixes to silently drop", Type: "text", Value: strings.Join(p.cfg.LateDropSuffixes, ",")},
	}
}

func (p *Plugin) reloadLocked() {
	p.dropSuffixes = normalizeSuffixes(p.cfg.DropSuffixes)
	p.lateDropSuffixes = normalizeSuffixes(p.cfg.LateDropSuffixes)
	p.bannedPrefixes = loadPrefixes(p.cfg.BannedIPsPath)
	p.sniProxyIPs = loadIPs(p.cfg.SNIProxyIPsPath)
	p.proxySuffixes = normalizeSuffixes(loadDomains(p.cfg.DomainsWithSubPath))
	p.customSuffixes = normalizeSuffixes(loadDomains(p.cfg.CustomPath))
	p.exactProxyNames = toSet(loadDomains(p.cfg.DomainsPath))
	p.garbageNames = toSet(loadDomains(p.cfg.GarbagePath))
	p.hostsMap = loadHostsMap(p.cfg.HostsPath)
}

func normalizeDomain(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return ""
	}
	v = strings.TrimSuffix(v, ".")
	if v == "" {
		return ""
	}
	return dns.Fqdn(v)
}

func normalizeSuffixes(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if d := normalizeDomain(v); d != "" {
			out = append(out, d)
		}
	}
	return out
}

func matchesAnySuffix(qName string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if hasDomainSuffix(qName, suffix) {
			return true
		}
	}
	return false
}

func hasDomainSuffix(qName, suffix string) bool {
	if qName == suffix {
		return true
	}
	if !strings.HasSuffix(qName, suffix) || len(qName) <= len(suffix) {
		return false
	}
	return qName[len(qName)-len(suffix)-1] == '.'
}

func readLines(path string) []string {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("dnsdist_compat: failed to read %s: %v", path, err)
		}
		return nil
	}
	lines := strings.Split(string(data), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
			if line == "" {
				continue
			}
		}
		out = append(out, line)
	}
	return out
}

func loadPrefixes(path string) []netip.Prefix {
	lines := readLines(path)
	out := make([]netip.Prefix, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(line, "/") {
			pfx, err := netip.ParsePrefix(line)
			if err != nil {
				continue
			}
			out = append(out, pfx.Masked())
			continue
		}
		addr, err := netip.ParseAddr(line)
		if err != nil {
			continue
		}
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		out = append(out, netip.PrefixFrom(addr, bits))
	}
	return out
}

func loadIPs(path string) []netip.Addr {
	lines := readLines(path)
	out := make([]netip.Addr, 0, len(lines))
	for _, line := range lines {
		addr, err := netip.ParseAddr(line)
		if err != nil {
			continue
		}
		out = append(out, addr)
	}
	return out
}

func loadDomains(path string) []string {
	lines := readLines(path)
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if d := normalizeDomain(line); d != "" {
			out = append(out, d)
		}
	}
	return out
}

func loadHostsMap(path string) map[string]netip.Addr {
	lines := readLines(path)
	out := make(map[string]netip.Addr, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		if domain := normalizeDomain(fields[1]); domain != "" {
			out[domain] = ip
		}
	}
	return out
}

func toSet(domains []string) map[string]struct{} {
	out := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		if domain == "" {
			continue
		}
		out[domain] = struct{}{}
	}
	return out
}

func extractClientIP(w dns.ResponseWriter) netip.Addr {
	if w == nil || w.RemoteAddr() == nil {
		return netip.Addr{}
	}

	host := w.RemoteAddr().String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

func parseListConfig(value any) []string {
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			line := strings.TrimSpace(fmt.Sprint(item))
			if line != "" {
				out = append(out, line)
			}
		}
		return out
	case string:
		splitter := "\n"
		if strings.Contains(v, ",") && !strings.Contains(v, "\n") {
			splitter = ","
		}
		parts := strings.Split(v, splitter)
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
		return out
	default:
		return nil
	}
}

func (p *Plugin) writeNoErrorEmpty(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = dns.RcodeSuccess
	_ = w.WriteMsg(resp)
}

func (p *Plugin) writeNXDOMAIN(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeNameError)
	_ = w.WriteMsg(resp)
}

func (p *Plugin) writeSpoofReply(w dns.ResponseWriter, req *dns.Msg, qName string, qType uint16, ipPool []netip.Addr) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = dns.RcodeSuccess

	selected, ok := p.pickSpoofIP(qType, ipPool)
	if !ok {
		_ = w.WriteMsg(resp)
		return
	}

	const ttl = 60
	switch qType {
	case dns.TypeA:
		if !selected.Is4() {
			_ = w.WriteMsg(resp)
			return
		}
		rr := &dns.A{
			Hdr: dns.RR_Header{Name: qName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   net.IP(selected.AsSlice()),
		}
		resp.Answer = append(resp.Answer, rr)
	case dns.TypeAAAA:
		if !selected.Is6() {
			_ = w.WriteMsg(resp)
			return
		}
		rr := &dns.AAAA{
			Hdr:  dns.RR_Header{Name: qName, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
			AAAA: net.IP(selected.AsSlice()),
		}
		resp.Answer = append(resp.Answer, rr)
	default:
		// SpoofAction() in this compatibility layer only synthesizes address records.
	}

	_ = w.WriteMsg(resp)
}

func (p *Plugin) pickSpoofIP(qType uint16, ipPool []netip.Addr) (netip.Addr, bool) {
	candidates := make([]netip.Addr, 0, len(ipPool))
	for _, ip := range ipPool {
		switch qType {
		case dns.TypeA:
			if ip.Is4() {
				candidates = append(candidates, ip)
			}
		case dns.TypeAAAA:
			if ip.Is6() {
				candidates = append(candidates, ip)
			}
		default:
			return netip.Addr{}, false
		}
	}
	if len(candidates) == 0 {
		return netip.Addr{}, false
	}
	idx := int(p.rrCounter.Add(1)-1) % len(candidates)
	return candidates[idx], true
}
