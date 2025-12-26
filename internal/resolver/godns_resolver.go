package resolver

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/pool"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// GoDNSResolver is a recursive DNS resolver using pure Go.
type GoDNSResolver struct {
	config        *config.Config
	cache         *cache.Cache
	sf            singleflight.Group
	client        *DNSClient
	workerPool    *WorkerPool
	metrics       *metrics.Metrics
	rootServers   []string
	mutex         sync.RWMutex
}

// NewGoDNSResolver creates a new Go DNS resolver instance.
func NewGoDNSResolver(cfg *config.Config, c *cache.Cache, m *metrics.Metrics) *GoDNSResolver {
	r := &GoDNSResolver{
		config:     cfg,
		cache:      c,
		sf:         singleflight.Group{},
		client:     NewDNSClient(cfg.Resolver.UpstreamTimeout),
		workerPool: NewWorkerPool(cfg.Resolver.MaxWorkers),
		metrics:    m,
		// Root servers list - the authoritative DNS servers for the root zone
		rootServers: []string{
			"198.41.0.4:53",      // a.root-servers.net
			"199.9.14.201:53",    // b.root-servers.net
			"192.33.4.12:53",     // c.root-servers.net
			"199.7.91.13:53",     // d.root-servers.net
			"192.203.230.10:53",  // e.root-servers.net
			"192.5.5.241:53",     // f.root-servers.net
			"192.112.36.4:53",    // g.root-servers.net
			"198.97.190.53:53",   // h.root-servers.net
			"192.36.148.17:53",   // i.root-servers.net
			"192.58.128.30:53",   // j.root-servers.net
			"193.0.14.129:53",    // k.root-servers.net
			"199.7.83.42:53",     // l.root-servers.net
			"202.12.27.33:53",    // m.root-servers.net
		},
	}

	return r
}

// GetSingleflightGroup returns the singleflight.Group instance.
func (r *GoDNSResolver) GetSingleflightGroup() *singleflight.Group {
	return &r.sf
}

// GetConfig returns the resolver's configuration.
func (r *GoDNSResolver) GetConfig() *config.Config {
	return r.config
}

// Resolve performs a recursive DNS lookup for a given request.
func (r *GoDNSResolver) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Question[0]
	key := cache.Key(q)

	// Check the cache first.
	if msgBytes, found, revalidate := r.cache.Get(key); found {
		msg := pool.GetDnsMsg()
		if err := msg.Unpack(msgBytes); err != nil {
			log.Printf("Failed to unpack message from cache for key %s: %v", key, err)
			pool.PutDnsMsg(msg)
			// Treat as cache miss and proceed to resolve
		} else {
			msg.Id = req.Id

			if revalidate {
				r.metrics.IncrementCacheRevalidations()
				// Trigger a background revalidation using the worker pool
				go func() {
					if err := r.workerPool.Acquire(context.Background()); err != nil {
						log.Printf("Failed to acquire worker for revalidation: %v", err)
						return
					}
					defer r.workerPool.Release()

					ctx, cancel := context.WithTimeout(context.Background(), r.config.Resolver.UpstreamTimeout)
					defer cancel()

					// Create a new request for revalidation
					revalidationReq := pool.GetDnsMsg()
					defer pool.PutDnsMsg(revalidationReq)
					revalidationReq.SetQuestion(q.Name, q.Qtype)
					revalidationReq.RecursionDesired = true
					if opt := req.IsEdns0(); opt != nil {
						revalidationReq.SetEdns0(opt.UDPSize(), opt.Do())
					}

					res, err, _ := r.sf.Do(key+"-revalidate", func() (interface{}, error) {
						return r.recursiveLookup(ctx, revalidationReq)
					})
					if err != nil {
						log.Printf("Background revalidation failed for %s: %v", q.Name, err)
						return
					}

					if newMsg, ok := res.(*dns.Msg); ok {
						r.cache.Set(key, newMsg, r.config.Cache.StaleWhileRevalidate)
						log.Printf("Successfully revalidated and updated cache for %s", q.Name)
					}
				}()
			}
			return msg, nil
		}
	}

	// Use singleflight to ensure only one lookup for a given question is in flight at once.
	res, err, _ := r.sf.Do(key, func() (interface{}, error) {
		return r.recursiveLookup(ctx, req)
	})

	if err != nil {
		return nil, err
	}

	// We need to return a copy because the result might be shared
	srcMsg := res.(*dns.Msg)
	msg := pool.GetDnsMsg()
	srcMsg.CopyTo(msg)
	msg.Id = req.Id

	// Cache the response
	r.cache.Set(key, msg, r.config.Cache.StaleWhileRevalidate)

	return msg, nil
}

// recursiveLookup performs the actual recursive DNS lookup
func (r *GoDNSResolver) recursiveLookup(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Question[0]
	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime)
		r.metrics.RecordLatency(q.Name, latency)
	}()

	// Perform the recursive lookup starting from root servers
	result, err := r.lookupRecursive(ctx, q.Name, q.Qtype, q.Qclass)
	if err != nil {
		r.metrics.IncrementUnboundErrors()
		log.Printf("Recursive resolution error for %s: %v", q.Name, err)
		// Return a SERVFAIL message when resolution fails
		msg := pool.GetDnsMsg()
		msg.SetRcode(req, dns.RcodeServerFailure)
		return msg, err
	}

	// Set up the response
	msg := pool.GetDnsMsg()
	msg.SetReply(req)
	msg.Rcode = result.Rcode

	if result.Rcode == dns.RcodeNameError {
		r.metrics.RecordNXDOMAIN(q.Name)
	}

	// Add the result records to the response
	if result.Answer != nil {
		msg.Answer = append([]dns.RR(nil), result.Answer...)
	}
	if result.Ns != nil {
		msg.Ns = append([]dns.RR(nil), result.Ns...)
	}
	if result.Extra != nil {
		msg.Extra = append([]dns.RR(nil), result.Extra...)
	}

	// We are done with result, which was likely from pool, but we don't own it here directly
	// unless we are sure. To be safe, we don't put it back here if it's reused.
	// But `lookupRecursive` returns a fresh Msg or one from pool?
	// For now, let GC handle `result` if it was allocated, or pool if we implement that deeper.
	// But wait, `result` comes from `iterativeLookup` which might return a pooled msg.

	return msg, nil
}

// lookupRecursive is the main recursive lookup function
func (r *GoDNSResolver) lookupRecursive(ctx context.Context, domain string, qtype uint16, qclass uint16) (*dns.Msg, error) {
	// Normalize the domain name
	domain = strings.ToLower(dns.Fqdn(domain))

	// Check if we're looking up one of the root servers - avoid infinite recursion
	for _, rootServer := range r.rootServers {
		serverName := strings.TrimSuffix(rootServer, ":53")
		// serverName is IP usually in config, but if it was name...
		// In my updated config, they are IPs.
		if strings.EqualFold(domain, serverName+".") {
			return r.directLookup(ctx, domain, qtype, qclass, r.rootServers)
		}
	}

	// Perform iterative resolution starting from the root
	return r.iterativeLookup(ctx, domain, qtype, qclass, r.rootServers)
}

// queryAny sends queries to multiple servers in parallel and returns the first successful response.
func (r *GoDNSResolver) queryAny(ctx context.Context, req *dns.Msg, servers []string) (*dns.Msg, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers to query")
	}
	if len(servers) == 1 {
		return r.sendQuery(ctx, req, servers[0])
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		msg *dns.Msg
		err error
	}

	shuffled := make([]string, len(servers))
	copy(shuffled, servers)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	// Process servers in batches to avoid giving up too early if the first batch fails (e.g., IPv6 connectivity issues)
	batchSize := 3
	var lastErr error

	for i := 0; i < len(shuffled); i += batchSize {
		end := i + batchSize
		if end > len(shuffled) {
			end = len(shuffled)
		}
		batch := shuffled[i:end]

		resultChan := make(chan result, len(batch))

		for _, server := range batch {
			go func(srv string) {
				resp, err := r.sendQuery(ctx, req, srv)
				select {
				case resultChan <- result{msg: resp, err: err}:
				case <-ctx.Done():
				}
			}(server)
		}

		for j := 0; j < len(batch); j++ {
			select {
			case res := <-resultChan:
				if res.err == nil && res.msg != nil {
					// Accept Success or NXDOMAIN as valid answers
					if res.msg.Rcode == dns.RcodeSuccess || res.msg.Rcode == dns.RcodeNameError {
						return res.msg, nil
					}
					lastErr = fmt.Errorf("server returned rcode %s", dns.RcodeToString[res.msg.Rcode])
				} else {
					lastErr = res.err
				}
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

        // If we found a valid answer, we returned.
        // If not, continue to next batch.
	}

	return nil, lastErr
}

// iterativeLookup performs iterative DNS resolution
func (r *GoDNSResolver) iterativeLookup(ctx context.Context, domain string, qtype uint16, qclass uint16, servers []string) (*dns.Msg, error) {
	// Limit the number of iterations to prevent infinite loops
	maxIterations := 20
	iteration := 0

	currentDomain := domain
	currentServers := servers

	for iteration < maxIterations {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Create a query for the current domain
		req := pool.GetDnsMsg()
		req.Id = dns.Id()            // Randomize Transaction ID
		req.SetQuestion(currentDomain, qtype)
		req.RecursionDesired = false // We're doing iterative resolution
		req.SetEdns0(4096, true)     // Enable DNSSEC OK

		// Send query to the current servers (Fastest Wins)
		resp, err := r.queryAny(ctx, req, currentServers)
		pool.PutDnsMsg(req)

		if err != nil {
			log.Printf("Failed to query servers for %s: %v", currentDomain, err)
			// If queryAny failed for all servers, we can't proceed.
			return nil, err
		}

		// Check the response
		switch resp.Rcode {
		case dns.RcodeSuccess:
            // If it's a referral (no answer but NS records), we must treat it as such.
            if len(resp.Answer) == 0 && len(resp.Ns) > 0 {
                // This is a referral. Fall through to referral handling.
                break
            }
			// Got a direct answer - return it
			return resp, nil
		case dns.RcodeNameError:
			// Domain doesn't exist
			return resp, nil
		case dns.RcodeServerFailure, dns.RcodeRefused:
			// Should have been handled by queryAny retry/selection logic, but if we got here, it's what we have.
			return resp, nil
		default:
			// For referral (NXDOMAIN, etc.), continue to next iteration
		}

		// If we get referrals (authority records), use them
		if len(resp.Ns) > 0 {
			nextServers, err := r.extractServers(ctx, resp.Ns, resp.Extra)
			if err != nil {
				log.Printf("Error extracting servers: %v", err)
				// If we can't extract next servers, we are stuck.
			} else if len(nextServers) > 0 {
				currentServers = nextServers
				iteration++
				continue
			}
		}

		// If there are additional records (glue records), use them (usually handled in extractServers, but logic here redundant?)
		// Actually extractServers handles glue.

		// If we got CNAME records and we're not looking up CNAME itself
		if len(resp.Answer) > 0 && qtype != dns.TypeCNAME {
			for _, ans := range resp.Answer {
				if cn, ok := ans.(*dns.CNAME); ok {
					// CNAME chasing
					// We should ideally restart resolution for the CNAME target
					log.Printf("CNAME redirect: %s -> %s", currentDomain, cn.Target)
					currentDomain = strings.ToLower(dns.Fqdn(cn.Target))
					// Restart server search from root for the new domain?
					// Or continue with current servers? CNAME usually points to another zone.
					// We should restart from root for the new CNAME target.
					currentServers = r.rootServers
					iteration++
					break
				}
			}
			// If we found a CNAME and updated currentDomain, the loop continues.
			continue
		}

		// If we got here and didn't continue, we probably have an answer or we are stuck.
		// If answer count > 0, return it.
		if len(resp.Answer) > 0 {
			return resp, nil
		}

		// If no answer, no referral, no CNAME... it's a weird response (maybe NODATA).
		return resp, nil
	}

	return nil, fmt.Errorf("max iterations reached for %s", domain)
}

// extractServers extracts server addresses from authority and additional records
func (r *GoDNSResolver) extractServers(ctx context.Context, nsRecords []dns.RR, extraRecords []dns.RR) ([]string, error) {
	var servers []string

	// First, check if we already have IP addresses in extra records
	ipMap := make(map[string][]string)
	for _, extra := range extraRecords {
		switch rr := extra.(type) {
		case *dns.A:
			names := ipMap[strings.ToLower(rr.Hdr.Name)]
			ipMap[strings.ToLower(rr.Hdr.Name)] = append(names, rr.A.String())
		case *dns.AAAA:
			names := ipMap[strings.ToLower(rr.Hdr.Name)]
			ipMap[strings.ToLower(rr.Hdr.Name)] = append(names, rr.AAAA.String())
		}
	}

	// Now match NS records with IP addresses
	for _, ns := range nsRecords {
		if nsRR, ok := ns.(*dns.NS); ok {
			name := strings.ToLower(dns.Fqdn(nsRR.Ns))
			if ips, exists := ipMap[name]; exists {
				for _, ip := range ips {
					servers = append(servers, net.JoinHostPort(ip, "53"))
				}
			} else {
				// If no IP in extra records, we need to resolve the NS name
				ips, err := r.resolveNameToIP(ctx, name)
				if err != nil {
					log.Printf("Failed to resolve NS %s: %v", name, err)
					continue
				}
				for _, ip := range ips {
					servers = append(servers, net.JoinHostPort(ip, "53"))
				}
			}
		}
	}

	return servers, nil
}

// extractGlueServers extracts server addresses from glue records
func (r *GoDNSResolver) extractGlueServers(extraRecords []dns.RR) []string {
	var servers []string

	for _, extra := range extraRecords {
		switch rr := extra.(type) {
		case *dns.A:
			servers = append(servers, net.JoinHostPort(rr.A.String(), "53"))
		case *dns.AAAA:
			servers = append(servers, net.JoinHostPort(rr.AAAA.String(), "53"))
		}
	}

	return servers
}

// resolveNameToIP resolves a name to IP addresses
func (r *GoDNSResolver) resolveNameToIP(ctx context.Context, name string) ([]string, error) {
	// Parallelize A and AAAA lookups using the full resolver (Resolve) to leverage cache and recursion.

	type result struct {
		ips []string
		err error
	}

	c := make(chan result, 2)

	queryType := func(qtype uint16) {
		req := pool.GetDnsMsg()
		defer pool.PutDnsMsg(req)
		req.Id = dns.Id() // Randomize Transaction ID
		req.SetQuestion(name, qtype)
		req.RecursionDesired = true

		// Use Resolve to get full recursive behavior + cache
		resp, err := r.Resolve(ctx, req)
		if err != nil {
			c <- result{err: err}
			return
		}
		
		var ips []string
		for _, ans := range resp.Answer {
			if qtype == dns.TypeA {
				if a, ok := ans.(*dns.A); ok {
					ips = append(ips, a.A.String())
				}
			} else if qtype == dns.TypeAAAA {
				if aaaa, ok := ans.(*dns.AAAA); ok {
					ips = append(ips, aaaa.AAAA.String())
				}
			}
		}
		c <- result{ips: ips}
	}

	go queryType(dns.TypeA)
	go queryType(dns.TypeAAAA)

	var ips []string
	var errs []error

	for i := 0; i < 2; i++ {
		res := <-c
		if res.err != nil {
			errs = append(errs, res.err)
		} else {
			ips = append(ips, res.ips...)
		}
	}

	if len(ips) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("failed to resolve %s: %v", name, errs)
	}

	return ips, nil
}

// sendQuery sends a single DNS query to the specified server
func (r *GoDNSResolver) sendQuery(ctx context.Context, req *dns.Msg, server string) (*dns.Msg, error) {
	// Create a context with a deadline for this specific query
	// Use slightly longer timeout for parallel queries to give them a chance, but overall bound by upstream timeout.
	queryCtx, cancel := context.WithTimeout(ctx, r.config.Resolver.UpstreamTimeout)
	defer cancel()

	// Use the custom DNS client to send the query
	resp, err := r.client.Exchange(queryCtx, req, server)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// directLookup is a helper to directly query specific servers
func (r *GoDNSResolver) directLookup(ctx context.Context, domain string, qtype uint16, qclass uint16, servers []string) (*dns.Msg, error) {
    // This function is now just a wrapper around queryAny with specific msg construction
	req := pool.GetDnsMsg()
	defer pool.PutDnsMsg(req)
	req.Id = dns.Id() // Randomize Transaction ID
	req.SetQuestion(dns.Fqdn(domain), qtype)
	req.RecursionDesired = true
    req.SetEdns0(4096, true)

    return r.queryAny(ctx, req, servers)
}

// LookupWithoutCache performs a recursive DNS lookup for a given request, bypassing the cache.
func (r *GoDNSResolver) LookupWithoutCache(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return r.recursiveLookup(ctx, req)
}

// Close closes the resolver and frees resources.
func (r *GoDNSResolver) Close() {
	r.client.Close()
}
