package recursor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/domainr/dnsr"
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
	fallback    *dnsr.Resolver
	sf          singleflight.Group
	trustedDS   []*dns.DS
}

type serverQueryResult struct {
	server string
	resp   *dns.Msg
	err    error
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
		fallback: dnsr.NewResolver(
			dnsr.WithCache(10000),
			dnsr.WithTimeout(opts.ResolveTimeout),
			dnsr.WithTCPRetry(),
		),
		trustedDS: trustDS,
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
		usedFallback := false
		if err != nil {
			if !r.canUseFallback() {
				return nil, err
			}
			fbCtx, fbCancel := context.WithTimeout(context.Background(), fallbackResolveTimeout(r.opts))
			fallbackResp, fbErr := r.resolveWithFallbackDNSR(fbCtx, q)
			fbCancel()
			if fbErr != nil {
				return nil, err
			}
			resp = fallbackResp
			usedFallback = true
			log.Printf("Resolver fallback(dnsr) used for %s type=%d after iterative error: %v", q.Name, q.Qtype, err)
		}
		if resp == nil {
			return nil, fmt.Errorf("empty resolver response")
		}
		if r.opts.ValidateDNSSEC {
			if usedFallback {
				// dnsr fallback responses are not DNSSEC-validated.
				resp.AuthenticatedData = false
			} else {
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

	for i := 0; i < len(ordered); i += 3 {
		end := i + 3
		if end > len(ordered) {
			end = len(ordered)
		}
		batch := ordered[i:end]
		batchCtx, batchCancel := context.WithCancel(ctx)
		resultsCh := make(chan serverQueryResult, len(batch))

		for _, server := range batch {
			server := server
			go func() {
				resp, err := r.exchange(batchCtx, server, query)
				select {
				case resultsCh <- serverQueryResult{server: server, resp: resp, err: err}:
				case <-batchCtx.Done():
				}
			}()
		}

		for j := 0; j < len(batch); j++ {
			var result serverQueryResult
			select {
			case <-ctx.Done():
				batchCancel()
				return nil, ctx.Err()
			case result = <-resultsCh:
			}

			if result.err != nil {
				lastErr = result.err
				continue
			}

			resp := result.resp
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
				if !resp.Authoritative && !hasSOAInAuthority(resp) {
					lastErr = errors.New("non-authoritative NXDOMAIN ignored")
					continue
				}
				if shouldCacheResponse(resp, q) {
					r.setCached(q, resp)
				}
				batchCancel()
				return resp, nil
			}

			if hasDirectAnswerForQuestion(resp, q) {
				if shouldCacheResponse(resp, q) {
					r.setCached(q, resp)
				}
				batchCancel()
				return resp, nil
			}

			if q.Qtype != dns.TypeCNAME && q.Qtype != dns.TypeDNAME && q.Qtype != dns.TypeANY {
				if aliasTarget, ok := findAliasTarget(resp, q.Name); ok {
					targetQ := q
					targetQ.Name = aliasTarget
					targetResp, err := r.resolveIterative(ctx, targetQ, r.rootServers, depth+1, guard)
					if err != nil {
						if shouldCacheResponse(resp, q) {
							r.setCached(q, resp)
						}
						batchCancel()
						return resp, nil
					}
					merged := mergeCNAMEChain(resp, targetResp)
					if shouldCacheResponse(merged, q) {
						r.setCached(q, merged)
					}
					batchCancel()
					return merged, nil
				}
			}

			if isAuthoritativeNoData(resp) {
				if shouldCacheResponse(resp, q) {
					r.setCached(q, resp)
				}
				batchCancel()
				return resp, nil
			}

			if glue := extractGlueIPs(resp); len(glue) > 0 {
				batchCancel()
				return r.resolveIterative(ctx, q, glue, depth+1, guard)
			}

			nsNames := extractNSHostnames(resp)
			if len(nsNames) > 0 {
				nextIPs := r.resolveNSHostIPs(ctx, nsNames, depth+1, guard)
				if len(nextIPs) > 0 {
					batchCancel()
					return r.resolveIterative(ctx, q, nextIPs, depth+1, guard)
				}
			}
		}
		batchCancel()
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
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	for _, nsName := range nsNames {
		if err := ctx.Err(); err != nil {
			break
		}

		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			nsName := nsName
			qt := qt
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()

				q := dns.Question{Name: dns.Fqdn(nsName), Qtype: qt, Qclass: dns.ClassINET}
				resp, err := r.resolveIterative(ctx, q, r.rootServers, depth+1, cloneGuardMap(guard))
				if err != nil || resp == nil {
					return
				}
				local := make([]string, 0, 2)
				for _, rr := range resp.Answer {
					switch v := rr.(type) {
					case *dns.A:
						local = append(local, v.A.String())
					case *dns.AAAA:
						local = append(local, v.AAAA.String())
					}
				}
				if len(local) == 0 {
					return
				}
				mu.Lock()
				for _, ip := range local {
					ips[ip] = struct{}{}
				}
				mu.Unlock()
			}()
		}
	}
	wg.Wait()

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
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		resp, _, err := udpClient.ExchangeContext(ctx, query.Copy(), addr)
		if err == nil {
			if resp != nil && resp.Truncated {
				tcpResp, tcpErr := r.exchangeTCP(ctx, addr, query)
				if tcpErr == nil && tcpResp != nil {
					return tcpResp, nil
				}
			}
			return resp, nil
		}
		lastErr = err
		if !isRetriableExchangeError(err) {
			break
		}
	}

	if shouldFallbackToTCPOnError(lastErr) {
		tcpResp, tcpErr := r.exchangeTCP(ctx, addr, query)
		if tcpErr == nil && tcpResp != nil {
			return tcpResp, nil
		}
		if tcpErr != nil {
			lastErr = tcpErr
		}
	}
	return nil, lastErr
}

func (r *Resolver) exchangeTCP(ctx context.Context, addr string, query *dns.Msg) (*dns.Msg, error) {
	tcpClient := &dns.Client{Net: "tcp", Timeout: r.opts.QueryTimeout}
	tcpResp, _, tcpErr := tcpClient.ExchangeContext(ctx, query.Copy(), addr)
	if tcpErr != nil {
		return nil, tcpErr
	}
	return tcpResp, nil
}

func isRetriableExchangeError(err error) bool {
	if err == nil {
		return false
	}
	if nerr, ok := err.(net.Error); ok {
		return nerr.Timeout() || nerr.Temporary()
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "temporary")
}

func shouldFallbackToTCPOnError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "buffer size too small") ||
		strings.Contains(msg, "overflow") ||
		strings.Contains(msg, "truncated")
}

func cloneGuardMap(in map[string]int) map[string]int {
	if len(in) == 0 {
		return map[string]int{}
	}
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
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
		// Intentionally do not block on Wait(); cache writes are async.
		// Blocking here hurts throughput under load.
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

func hasDirectAnswerForQuestion(resp *dns.Msg, q dns.Question) bool {
	if len(resp.Answer) == 0 {
		return false
	}
	for _, rr := range resp.Answer {
		h := rr.Header()
		if h == nil || !strings.EqualFold(h.Name, q.Name) {
			continue
		}
		if q.Qtype == dns.TypeANY || h.Rrtype == q.Qtype {
			return true
		}
	}
	return false
}

func findAliasTarget(resp *dns.Msg, name string) (string, bool) {
	name = dns.Fqdn(name)

	for _, rr := range resp.Answer {
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}
		if strings.EqualFold(cname.Hdr.Name, name) {
			return dns.Fqdn(cname.Target), true
		}
	}

	var (
		bestOwner  string
		bestTarget string
	)
	for _, rr := range resp.Answer {
		dname, ok := rr.(*dns.DNAME)
		if !ok {
			continue
		}
		owner := dns.Fqdn(dname.Hdr.Name)
		if !dns.IsSubDomain(owner, name) || strings.EqualFold(owner, name) {
			continue
		}
		if len(owner) <= len(bestOwner) {
			continue
		}
		bestOwner = owner
		bestTarget = dns.Fqdn(dname.Target)
	}
	if bestOwner == "" || bestTarget == "" {
		return "", false
	}

	lowerName := strings.ToLower(name)
	lowerOwner := strings.ToLower(bestOwner)
	if !strings.HasSuffix(lowerName, lowerOwner) {
		return "", false
	}
	prefix := name[:len(name)-len(bestOwner)]
	return dns.Fqdn(prefix + bestTarget), true

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

func hasSOAInAuthority(resp *dns.Msg) bool {
	if resp == nil {
		return false
	}
	for _, rr := range resp.Ns {
		if rr.Header() != nil && rr.Header().Rrtype == dns.TypeSOA {
			return true
		}
	}
	return false
}

func (r *Resolver) resolveWithFallbackDNSR(ctx context.Context, q dns.Question) (*dns.Msg, error) {
	if r.fallback == nil {
		return nil, fmt.Errorf("dnsr fallback not initialized")
	}

	qtype := dns.TypeToString[q.Qtype]
	if qtype == "" {
		qtype = "A"
	}

	rrs, err := r.fallback.ResolveContext(ctx, q.Name, qtype)
	if err != nil {
		if errors.Is(err, dnsr.NXDOMAIN) {
			msg := new(dns.Msg)
			msg.MsgHdr.Response = true
			msg.RecursionAvailable = true
			msg.Authoritative = true
			msg.Rcode = dns.RcodeNameError
			msg.Question = []dns.Question{q}
			return msg, nil
		}
		return nil, err
	}

	msg := new(dns.Msg)
	msg.MsgHdr.Response = true
	msg.RecursionAvailable = true
	msg.Rcode = dns.RcodeSuccess
	msg.Question = []dns.Question{q}

	for _, rr := range rrs {
		dnsRR, ok := convertDNSRRFromDNSR(rr)
		if !ok || dnsRR == nil || dnsRR.Header() == nil {
			continue
		}
		if strings.EqualFold(dnsRR.Header().Name, q.Name) {
			if q.Qtype == dns.TypeANY || dnsRR.Header().Rrtype == q.Qtype || dnsRR.Header().Rrtype == dns.TypeCNAME {
				msg.Answer = append(msg.Answer, dnsRR)
			}
		}
	}
	return msg, nil
}

func convertDNSRRFromDNSR(rr dnsr.RR) (dns.RR, bool) {
	name := dns.Fqdn(strings.TrimSpace(rr.Name))
	if name == "." {
		name = rr.Name
	}
	if name == "" {
		return nil, false
	}

	ttl := uint32(60)
	if rr.TTL > 0 {
		ttl = uint32(rr.TTL / time.Second)
		if ttl == 0 {
			ttl = 1
		}
	}

	h := dns.RR_Header{
		Name:     name,
		Class:    dns.ClassINET,
		Ttl:      ttl,
		Rdlength: 0,
	}

	switch strings.ToUpper(strings.TrimSpace(rr.Type)) {
	case "A":
		ip := net.ParseIP(strings.TrimSpace(rr.Value)).To4()
		if ip == nil {
			return nil, false
		}
		h.Rrtype = dns.TypeA
		return &dns.A{Hdr: h, A: ip}, true
	case "AAAA":
		ip := net.ParseIP(strings.TrimSpace(rr.Value))
		if ip == nil || ip.To16() == nil {
			return nil, false
		}
		h.Rrtype = dns.TypeAAAA
		return &dns.AAAA{Hdr: h, AAAA: ip}, true
	case "CNAME":
		h.Rrtype = dns.TypeCNAME
		return &dns.CNAME{Hdr: h, Target: dns.Fqdn(rr.Value)}, true
	case "NS":
		h.Rrtype = dns.TypeNS
		return &dns.NS{Hdr: h, Ns: dns.Fqdn(rr.Value)}, true
	case "TXT":
		h.Rrtype = dns.TypeTXT
		parts := strings.Split(rr.Value, "\t")
		if len(parts) == 0 {
			parts = []string{rr.Value}
		}
		return &dns.TXT{Hdr: h, Txt: parts}, true
	default:
		parsed, err := dns.NewRR(rr.String())
		if err != nil {
			return nil, false
		}
		return parsed, true
	}
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

func (r *Resolver) canUseFallback() bool {
	// In strict DNSSEC mode do not return unvalidated fallback answers.
	return !(r.opts.ValidateDNSSEC && r.opts.DNSSECFailClosed)
}

func fallbackResolveTimeout(opts Options) time.Duration {
	timeout := opts.QueryTimeout * 2
	if timeout < 2*time.Second {
		timeout = 2 * time.Second
	}
	if timeout > 10*time.Second {
		timeout = 10 * time.Second
	}
	return timeout
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
