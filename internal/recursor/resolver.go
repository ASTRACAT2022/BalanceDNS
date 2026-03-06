package recursor

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

var defaultRootServers = []string{
	"198.41.0.4",     // a.root-servers.net
	"170.247.170.2",  // b.root-servers.net
	"192.33.4.12",    // c.root-servers.net
	"199.7.91.13",    // d.root-servers.net
	"192.203.230.10", // e.root-servers.net
	"192.5.5.241",    // f.root-servers.net
	"192.112.36.4",   // g.root-servers.net
	"198.97.190.53",  // h.root-servers.net
	"192.36.148.17",  // i.root-servers.net
	"192.58.128.30",  // j.root-servers.net
	"193.0.14.129",   // k.root-servers.net
	"199.7.83.42",    // l.root-servers.net
	"202.12.27.33",   // m.root-servers.net
}

// Options configures the pure-Go recursive resolver.
type Options struct {
	WorkerCount    int
	QueryTimeout   time.Duration
	ResolveTimeout time.Duration
	MaxDepth       int
	RootServers    []string

	CacheEntries int
	CacheMinTTL  time.Duration
	CacheMaxTTL  time.Duration

	ValidateDNSSEC   bool
	DNSSECFailClosed bool
	DNSSECTrustDS    []string
}

// Resolver performs iterative DNS resolution starting from root servers.
type Resolver struct {
	opts        Options
	rootServers []string
	next        atomic.Uint64
	cache       *ristretto.Cache
	sf          singleflight.Group
	trustedDS   []*dns.DS
}

// NewResolverWithOptions builds a recursive resolver with sane defaults.
func NewResolverWithOptions(opts Options) (*Resolver, error) {
	opts = withDefaultOptions(opts)
	roots := sanitizeServers(opts.RootServers)
	if len(roots) == 0 {
		return nil, fmt.Errorf("no valid root servers configured")
	}
	var trustDS []*dns.DS
	if opts.ValidateDNSSEC {
		var err error
		trustDS, err = loadTrustAnchorDS(opts.DNSSECTrustDS)
		if err != nil {
			return nil, err
		}
	}

	var c *ristretto.Cache
	if opts.CacheEntries > 0 {
		numCounters := int64(opts.CacheEntries * 10)
		if numCounters < 1000 {
			numCounters = 1000
		}
		rc, err := ristretto.NewCache(&ristretto.Config{
			NumCounters: numCounters,
			MaxCost:     int64(opts.CacheEntries),
			BufferItems: 64,
		})
		if err != nil {
			return nil, fmt.Errorf("create recursor cache: %w", err)
		}
		c = rc
	}

	return &Resolver{
		opts:        opts,
		rootServers: roots,
		cache:       c,
		trustedDS:   trustDS,
	}, nil
}

// Resolve resolves one DNS question via iterative recursion.
func (r *Resolver) Resolve(question dns.Question) (*dns.Msg, error) {
	q := normalizeQuestion(question)

	if cached, ok := r.getCached(q); ok {
		return withClientHeader(cached, q), nil
	}

	k := cacheKey(q)
	v, err, _ := r.sf.Do(k, func() (interface{}, error) {
		if cached, ok := r.getCached(q); ok {
			return cached, nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), r.opts.ResolveTimeout)
		defer cancel()

		guard := map[string]int{}
		resp, err := r.resolveIterative(ctx, q, r.rootServers, 0, guard)
		if err != nil {
			return nil, err
		}
		if resp == nil {
			return nil, fmt.Errorf("empty resolver response")
		}
		if r.opts.ValidateDNSSEC {
			status, valErr := r.validateResponseDNSSEC(ctx, q, resp)
			if valErr != nil {
				if r.opts.DNSSECFailClosed {
					return nil, fmt.Errorf("dnssec validation failed for %s: %w", q.Name, valErr)
				}
				resp.AuthenticatedData = false
			} else {
				resp.AuthenticatedData = status == dnssecStatusSecure
			}
		}
		if shouldCacheResponse(resp, q) {
			r.setCached(q, resp)
		}
		return resp, nil
	})
	if err != nil {
		return nil, err
	}

	resp, ok := v.(*dns.Msg)
	if !ok || resp == nil {
		return nil, fmt.Errorf("unexpected resolver result type")
	}
	return withClientHeader(resp, q), nil
}

// Close exists for compatibility with the previous backend lifecycle.
func (r *Resolver) Close() {
	if r.cache != nil {
		r.cache.Close()
	}
}

// Reload exists for admin compatibility. Resolver is stateless between queries.
func (r *Resolver) Reload(_ string) error { return nil }

// ClearCache clears recursive cache.
func (r *Resolver) ClearCache(_ string) error {
	if r.cache == nil {
		return nil
	}
	r.cache.Clear()
	return nil
}

// WorkerCount returns configured worker count for diagnostics/UI.
func (r *Resolver) WorkerCount() int { return r.opts.WorkerCount }

func (r *Resolver) resolveIterative(ctx context.Context, q dns.Question, servers []string, depth int, guard map[string]int) (*dns.Msg, error) {
	if depth > r.opts.MaxDepth {
		return nil, fmt.Errorf("max recursion depth reached for %s", q.Name)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if cached, ok := r.getCached(q); ok {
		return cached, nil
	}

	key := fmt.Sprintf("%s|%d", strings.ToLower(q.Name), q.Qtype)
	guard[key]++
	if guard[key] > 8 {
		guard[key]--
		return nil, fmt.Errorf("recursive loop detected for %s", q.Name)
	}
	defer func() { guard[key]-- }()

	query := new(dns.Msg)
	query.SetQuestion(q.Name, q.Qtype)
	query.RecursionDesired = false
	query.SetEdns0(1232, true)

	ordered := r.orderServers(servers)
	if len(ordered) == 0 {
		return nil, fmt.Errorf("no nameservers to query for %s", q.Name)
	}

	var lastResp *dns.Msg
	var lastErr error

	for _, server := range ordered {
		resp, err := r.exchange(ctx, server, query)
		if err != nil {
			lastErr = err
			continue
		}
		if resp == nil {
			continue
		}
		lastResp = resp

		switch resp.Rcode {
		case dns.RcodeSuccess, dns.RcodeNameError:
			// handled below
		default:
			continue
		}

		if resp.Rcode == dns.RcodeNameError {
			if shouldCacheResponse(resp, q) {
				r.setCached(q, resp)
			}
			return resp, nil
		}

		if hasAnswerForQuestion(resp, q) {
			if shouldCacheResponse(resp, q) {
				r.setCached(q, resp)
			}
			return resp, nil
		}

		if cnameTarget, ok := findCNAMETarget(resp, q.Name); ok && q.Qtype != dns.TypeCNAME {
			targetQ := q
			targetQ.Name = cnameTarget
			targetResp, err := r.resolveIterative(ctx, targetQ, r.rootServers, depth+1, guard)
			if err != nil {
				if shouldCacheResponse(resp, q) {
					r.setCached(q, resp)
				}
				return resp, nil
			}
			merged := mergeCNAMEChain(resp, targetResp)
			if shouldCacheResponse(merged, q) {
				r.setCached(q, merged)
			}
			return merged, nil
		}

		if isAuthoritativeNoData(resp) {
			if shouldCacheResponse(resp, q) {
				r.setCached(q, resp)
			}
			return resp, nil
		}

		if glue := extractGlueIPs(resp); len(glue) > 0 {
			return r.resolveIterative(ctx, q, glue, depth+1, guard)
		}

		nsNames := extractNSHostnames(resp)
		if len(nsNames) > 0 {
			nextIPs := r.resolveNSHostIPs(ctx, nsNames, depth+1, guard)
			if len(nextIPs) > 0 {
				return r.resolveIterative(ctx, q, nextIPs, depth+1, guard)
			}
		}
	}

	if lastResp != nil {
		if shouldCacheResponse(lastResp, q) {
			r.setCached(q, lastResp)
		}
		return lastResp, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("resolution failed for %s", q.Name)
}

func (r *Resolver) resolveNSHostIPs(ctx context.Context, nsNames []string, depth int, guard map[string]int) []string {
	ips := make(map[string]struct{})
	for _, nsName := range nsNames {
		if err := ctx.Err(); err != nil {
			break
		}

		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			q := dns.Question{Name: dns.Fqdn(nsName), Qtype: qt, Qclass: dns.ClassINET}
			resp, err := r.resolveIterative(ctx, q, r.rootServers, depth+1, guard)
			if err != nil || resp == nil {
				continue
			}
			for _, rr := range resp.Answer {
				switch v := rr.(type) {
				case *dns.A:
					ips[v.A.String()] = struct{}{}
				case *dns.AAAA:
					ips[v.AAAA.String()] = struct{}{}
				}
			}
		}
	}

	out := make([]string, 0, len(ips))
	for ip := range ips {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

func (r *Resolver) orderServers(servers []string) []string {
	clean := sanitizeServers(servers)
	if len(clean) <= 1 {
		return clean
	}

	start := int((r.next.Add(1) - 1) % uint64(len(clean)))
	ordered := make([]string, 0, len(clean))
	ordered = append(ordered, clean[start:]...)
	ordered = append(ordered, clean[:start]...)
	return ordered
}

func (r *Resolver) exchange(ctx context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
	addr := normalizeServerAddr(server)

	udpClient := &dns.Client{Net: "udp", Timeout: r.opts.QueryTimeout}
	resp, _, err := udpClient.ExchangeContext(ctx, query.Copy(), addr)
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.Truncated {
		tcpClient := &dns.Client{Net: "tcp", Timeout: r.opts.QueryTimeout}
		tcpResp, _, tcpErr := tcpClient.ExchangeContext(ctx, query.Copy(), addr)
		if tcpErr == nil && tcpResp != nil {
			return tcpResp, nil
		}
	}
	return resp, nil
}

func (r *Resolver) getCached(q dns.Question) (*dns.Msg, bool) {
	if r.cache == nil {
		return nil, false
	}
	v, ok := r.cache.Get(cacheKey(q))
	if !ok {
		return nil, false
	}
	msg, ok := v.(*dns.Msg)
	if !ok || msg == nil {
		return nil, false
	}
	return msg.Copy(), true
}

func (r *Resolver) setCached(q dns.Question, resp *dns.Msg) {
	if r.cache == nil || resp == nil {
		return
	}
	ttl := responseCacheTTL(resp, q, r.opts.CacheMinTTL, r.opts.CacheMaxTTL)
	if ttl <= 0 {
		return
	}
	cpy := resp.Copy()
	if r.cache.SetWithTTL(cacheKey(q), cpy, 1, ttl) {
		r.cache.Wait()
	}
}

func cacheKey(q dns.Question) string {
	return fmt.Sprintf("%s|%d|%d", strings.ToLower(q.Name), q.Qtype, q.Qclass)
}

func shouldCacheResponse(resp *dns.Msg, q dns.Question) bool {
	if resp == nil {
		return false
	}
	switch resp.Rcode {
	case dns.RcodeNameError:
		return true
	case dns.RcodeSuccess:
		if hasAnswerForQuestion(resp, q) {
			return true
		}
		if isAuthoritativeNoData(resp) {
			return true
		}
	}
	return false
}

func responseCacheTTL(resp *dns.Msg, q dns.Question, minTTL, maxTTL time.Duration) time.Duration {
	var ttlSec uint32
	haveTTL := false

	if resp.Rcode == dns.RcodeNameError || isAuthoritativeNoData(resp) {
		if soaTTL, ok := negativeSOATTL(resp); ok {
			ttlSec = soaTTL
			haveTTL = true
		}
	}

	if !haveTTL {
		for _, rr := range resp.Answer {
			h := rr.Header()
			if h == nil {
				continue
			}
			if !strings.EqualFold(h.Name, q.Name) {
				continue
			}
			if q.Qtype != dns.TypeANY && h.Rrtype != q.Qtype && h.Rrtype != dns.TypeCNAME {
				continue
			}
			if !haveTTL || h.Ttl < ttlSec {
				ttlSec = h.Ttl
				haveTTL = true
			}
		}
	}

	if !haveTTL || ttlSec == 0 {
		return 0
	}

	ttl := time.Duration(ttlSec) * time.Second
	if minTTL > 0 && ttl < minTTL {
		ttl = minTTL
	}
	if maxTTL > 0 && ttl > maxTTL {
		ttl = maxTTL
	}
	return ttl
}

func negativeSOATTL(resp *dns.Msg) (uint32, bool) {
	for _, rr := range resp.Ns {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		ttl := soa.Hdr.Ttl
		if soa.Minttl > 0 && (ttl == 0 || soa.Minttl < ttl) {
			ttl = soa.Minttl
		}
		if ttl > 0 {
			return ttl, true
		}
	}
	return 0, false
}

func normalizeQuestion(q dns.Question) dns.Question {
	q.Name = dns.Fqdn(strings.ToLower(strings.TrimSpace(q.Name)))
	if q.Qclass == 0 {
		q.Qclass = dns.ClassINET
	}
	return q
}

func withClientHeader(resp *dns.Msg, q dns.Question) *dns.Msg {
	cpy := resp.Copy()
	cpy.MsgHdr.Response = true
	cpy.RecursionAvailable = true
	cpy.Question = []dns.Question{q}
	return cpy
}

func mergeCNAMEChain(cnameResp, targetResp *dns.Msg) *dns.Msg {
	out := cnameResp.Copy()
	seen := make(map[string]struct{})
	answers := make([]dns.RR, 0, len(cnameResp.Answer)+len(targetResp.Answer))

	for _, rr := range cnameResp.Answer {
		s := rr.String()
		seen[s] = struct{}{}
		answers = append(answers, rr)
	}
	for _, rr := range targetResp.Answer {
		s := rr.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		answers = append(answers, rr)
	}
	out.Answer = answers
	if len(out.Ns) == 0 {
		out.Ns = append(out.Ns, targetResp.Ns...)
	}
	if len(out.Extra) == 0 {
		out.Extra = append(out.Extra, targetResp.Extra...)
	}
	if targetResp.AuthenticatedData {
		out.AuthenticatedData = true
	}
	return out
}

func hasAnswerForQuestion(resp *dns.Msg, q dns.Question) bool {
	if len(resp.Answer) == 0 {
		return false
	}
	for _, rr := range resp.Answer {
		h := rr.Header()
		if h == nil || !strings.EqualFold(h.Name, q.Name) {
			continue
		}
		if q.Qtype == dns.TypeANY || h.Rrtype == q.Qtype || h.Rrtype == dns.TypeCNAME {
			return true
		}
	}
	return false
}

func findCNAMETarget(resp *dns.Msg, name string) (string, bool) {
	for _, rr := range resp.Answer {
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}
		if strings.EqualFold(cname.Hdr.Name, name) {
			return dns.Fqdn(cname.Target), true
		}
	}
	return "", false
}

func isAuthoritativeNoData(resp *dns.Msg) bool {
	if !resp.Authoritative || len(resp.Answer) > 0 {
		return false
	}
	for _, rr := range resp.Ns {
		if rr.Header() != nil && rr.Header().Rrtype == dns.TypeSOA {
			return true
		}
	}
	return false
}

func extractNSHostnames(resp *dns.Msg) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, rr := range resp.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		host := strings.ToLower(dns.Fqdn(ns.Ns))
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

func extractGlueIPs(resp *dns.Msg) []string {
	nsHosts := make(map[string]struct{})
	for _, ns := range extractNSHostnames(resp) {
		nsHosts[ns] = struct{}{}
	}
	if len(nsHosts) == 0 {
		return nil
	}

	ips := make(map[string]struct{})
	for _, rr := range resp.Extra {
		h := rr.Header()
		if h == nil {
			continue
		}
		if _, ok := nsHosts[strings.ToLower(h.Name)]; !ok {
			continue
		}
		switch v := rr.(type) {
		case *dns.A:
			ips[v.A.String()] = struct{}{}
		case *dns.AAAA:
			ips[v.AAAA.String()] = struct{}{}
		}
	}

	out := make([]string, 0, len(ips))
	for ip := range ips {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

func withDefaultOptions(opts Options) Options {
	if opts.WorkerCount <= 0 {
		workers := runtime.GOMAXPROCS(0)
		if workers < 2 {
			workers = 2
		}
		if workers > 16 {
			workers = 16
		}
		opts.WorkerCount = workers
	}
	if opts.QueryTimeout <= 0 {
		opts.QueryTimeout = 2 * time.Second
	}
	if opts.ResolveTimeout <= 0 {
		opts.ResolveTimeout = 8 * time.Second
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 20
	}
	if len(opts.RootServers) == 0 {
		opts.RootServers = append([]string(nil), defaultRootServers...)
	}
	if opts.CacheEntries <= 0 {
		opts.CacheEntries = 200000
	}
	if opts.CacheMinTTL <= 0 {
		opts.CacheMinTTL = 5 * time.Second
	}
	if opts.CacheMaxTTL <= 0 {
		opts.CacheMaxTTL = 30 * time.Minute
	}
	return opts
}

func sanitizeServers(servers []string) []string {
	if len(servers) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, len(servers))
	for _, raw := range servers {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		host := raw
		if h, _, err := net.SplitHostPort(raw); err == nil {
			host = h
		}
		if ip := net.ParseIP(host); ip == nil {
			continue
		}
		norm := normalizeServerAddr(raw)
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	return out
}

func normalizeServerAddr(server string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	if strings.Contains(server, ":") {
		if ip := net.ParseIP(server); ip != nil {
			return net.JoinHostPort(server, "53")
		}
	}
	if ip := net.ParseIP(server); ip != nil {
		return net.JoinHostPort(server, "53")
	}
	return server
}
