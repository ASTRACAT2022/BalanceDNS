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
	client        *dns.Client
	workerPool    *WorkerPool
	metrics       *metrics.Metrics
	rootServers   []string
	mutex         sync.RWMutex
}

// NewGoDNSResolver creates a new Go DNS resolver instance.
func NewGoDNSResolver(cfg *config.Config, c *cache.Cache, m *metrics.Metrics) *GoDNSResolver {
	r := &GoDNSResolver{
		config: cfg,
		cache:  c,
		sf:     singleflight.Group{},
		client: &dns.Client{
			Timeout: cfg.Resolver.UpstreamTimeout,
			Dialer: &net.Dialer{
				Timeout: cfg.Resolver.UpstreamTimeout,
			},
		},
		workerPool: NewWorkerPool(cfg.Resolver.MaxWorkers),
		metrics:    m,
		// Root servers list - the authoritative DNS servers for the root zone
		rootServers: []string{
			"a.root-servers.net:53",
			"b.root-servers.net:53",
			"c.root-servers.net:53",
			"d.root-servers.net:53",
			"e.root-servers.net:53",
			"f.root-servers.net:53",
			"g.root-servers.net:53",
			"h.root-servers.net:53",
			"i.root-servers.net:53",
			"j.root-servers.net:53",
			"k.root-servers.net:53",
			"l.root-servers.net:53",
			"m.root-servers.net:53",
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
	msgFromPool := pool.GetDnsMsg()
	if found, revalidate := r.cache.Get(key, msgFromPool); found {
		log.Printf("Cache hit for %s (revalidate: %t)", q.Name, revalidate)
		msgFromPool.Id = req.Id

		if revalidate {
			r.metrics.IncrementCacheRevalidations()
			// Create a deep copy for the background revalidation to avoid race conditions.
			msgForRevalidation := msgFromPool.Copy()
			// Trigger a background revalidation using the worker pool
			go func() {
				defer pool.PutDnsMsg(msgForRevalidation) // Return the copied message to the pool.
				if err := r.workerPool.Acquire(context.Background()); err != nil {
					log.Printf("Failed to acquire worker for revalidation: %v", err)
					return
				}
				defer r.workerPool.Release()

				ctx, cancel := context.WithTimeout(context.Background(), r.config.Resolver.UpstreamTimeout)
				defer cancel()

				// Use the copied message for revalidation
				res, err, _ := r.sf.Do(key+"-revalidate", func() (interface{}, error) {
					return r.recursiveLookup(ctx, msgForRevalidation)
				})
				if err != nil {
					log.Printf("Background revalidation failed for %s: %v", q.Name, err)
					return
				}

				if msg, ok := res.(*dns.Msg); ok {
					r.cache.Set(key, msg, r.config.Cache.StaleWhileRevalidate)
					log.Printf("Successfully revalidated and updated cache for %s", q.Name)
				}
			}()
		}
		// The original message is returned to the caller, who is now responsible for putting it back in the pool.
		return msgFromPool, nil
	}
	pool.PutDnsMsg(msgFromPool) // Return the message to the pool if not found in cache.

	// Use singleflight to ensure only one lookup for a given question is in flight at once.
	res, err, _ := r.sf.Do(key, func() (interface{}, error) {
		return r.recursiveLookup(ctx, req)
	})

	if err != nil {
		return nil, err
	}

	msg := res.(*dns.Msg)
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
		msg := new(dns.Msg)
		msg.SetRcode(req, dns.RcodeServerFailure)
		return msg, err
	}

	// Set up the response
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Rcode = result.Rcode

	if result.Rcode == dns.RcodeNameError {
		r.metrics.RecordNXDOMAIN(q.Name)
	}

	// Add the result records to the response
	if result.Answer != nil {
		msg.Answer = result.Answer
	}
	if result.Ns != nil {
		msg.Ns = result.Ns
	}
	if result.Extra != nil {
		msg.Extra = result.Extra
	}

	return msg, nil
}

// lookupRecursive is the main recursive lookup function
func (r *GoDNSResolver) lookupRecursive(ctx context.Context, domain string, qtype uint16, qclass uint16) (*dns.Msg, error) {
	// Normalize the domain name
	domain = strings.ToLower(dns.Fqdn(domain))

	// Check if we're looking up one of the root servers - avoid infinite recursion
	for _, rootServer := range r.rootServers {
		serverName := strings.TrimSuffix(rootServer, ":53")
		if strings.EqualFold(domain, serverName+".") {
			return r.directLookup(ctx, domain, qtype, qclass, r.rootServers)
		}
	}

	// Perform iterative resolution starting from the root
	return r.iterativeLookup(ctx, domain, qtype, qclass, r.rootServers)
}

// iterativeLookup performs iterative DNS resolution
func (r *GoDNSResolver) iterativeLookup(ctx context.Context, domain string, qtype uint16, qclass uint16, servers []string) (*dns.Msg, error) {
	// Limit the number of iterations to prevent infinite loops
	maxIterations := 20
	iteration := 0
    var lastError error

	currentDomain := domain
	currentServers := servers

	for iteration < maxIterations {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Track if any server responded in this iteration
		serverResponded := false

		// Try each server until one responds with a useful answer
		for _, server := range currentServers {
			// Create a query for the current domain
			req := new(dns.Msg)
			req.SetQuestion(currentDomain, qtype)
			req.RecursionDesired = false // We're doing iterative resolution

			// Send query to the current server
			resp, err := r.sendQuery(ctx, req, server)
			if err != nil {
				log.Printf("Failed to query %s for %s: %v", server, currentDomain, err)
				lastError = err
				continue
			}

			serverResponded = true

			// Check the response
			switch resp.Rcode {
			case dns.RcodeSuccess:
				// Got a direct answer - return it
				return resp, nil
			case dns.RcodeNameError:
				// Domain doesn't exist
				return resp, nil
			case dns.RcodeServerFailure:
				// Server failure - try next server
				lastError = fmt.Errorf("server failure from %s for %s", server, currentDomain)
				continue
			case dns.RcodeRefused:
				// Server refused - try next server
				lastError = fmt.Errorf("server refused query from %s for %s", server, currentDomain)
				continue
			default:
				// For referral (NXDOMAIN, etc.), continue to next iteration
			}

			// If we get referrals (authority records), use them
			if len(resp.Ns) > 0 {
				nextServers, err := r.extractServers(ctx, resp.Ns, resp.Extra)
				if err != nil {
					log.Printf("Error extracting servers: %v", err)
					continue
				}
				if len(nextServers) > 0 {
					currentServers = nextServers
					break // Try the new servers in the next iteration
				}
			}

			// If there are additional records (glue records), use them
			if len(resp.Extra) > 0 {
				additionalServers := r.extractGlueServers(resp.Extra)
				if len(additionalServers) > 0 {
					currentServers = additionalServers
					break // Try the new servers in the next iteration
				}
			}

			// If we got CNAME records and we're not looking up CNAME itself
			if len(resp.Answer) > 0 && qtype != dns.TypeCNAME {
				for _, ans := range resp.Answer {
					if cn, ok := ans.(*dns.CNAME); ok {
						log.Printf("CNAME redirect: %s -> %s", currentDomain, cn.Target)
						currentDomain = strings.ToLower(dns.Fqdn(cn.Target))
						break
					}
				}
			}
		}

		// If no server responded in this iteration, return the last error
		if !serverResponded && lastError != nil {
			return nil, lastError
		}

		iteration++
	}

	return nil, fmt.Errorf("max iterations reached for %s: %w", domain, lastError)
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
	// This is a simplified version - a full implementation would cache these results
	// and handle the resolution more efficiently

	// First try A record
	aReq := new(dns.Msg)
	aReq.SetQuestion(name, dns.TypeA)
	aReq.RecursionDesired = true

	aResp, err := r.directLookup(ctx, name, dns.TypeA, dns.ClassINET, r.rootServers)
	if err != nil {
		// If A fails, try AAAA
		aaaaResp, err2 := r.directLookup(ctx, name, dns.TypeAAAA, dns.ClassINET, r.rootServers)
		if err2 != nil {
			return nil, fmt.Errorf("failed to resolve %s: A failed: %v, AAAA failed: %v", name, err, err2)
		}
		
		var ips []string
		for _, ans := range aaaaResp.Answer {
			if aaaa, ok := ans.(*dns.AAAA); ok {
				ips = append(ips, aaaa.AAAA.String())
			}
		}
		return ips, nil
	}

	var ips []string
	for _, ans := range aResp.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	return ips, nil
}

// sendQuery sends a single DNS query to the specified server
func (r *GoDNSResolver) sendQuery(ctx context.Context, req *dns.Msg, server string) (*dns.Msg, error) {
	// Create a context with a deadline for this specific query
	queryCtx, cancel := context.WithTimeout(ctx, r.config.Resolver.UpstreamTimeout/3) // Use 1/3 of timeout per attempt
	defer cancel()

	// Use the client to send the query
	resp, _, err := r.client.ExchangeContext(queryCtx, req, server)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// directLookup is a helper to directly query specific servers
func (r *GoDNSResolver) directLookup(ctx context.Context, domain string, qtype uint16, qclass uint16, servers []string) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(domain), qtype)
	req.RecursionDesired = true

	// Shuffle the servers to distribute load
	shuffled := make([]string, len(servers))
	copy(shuffled, servers)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	var lastErr error
	attempts := 0
	maxAttempts := len(servers)

	for attempts < maxAttempts {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Try each server with retry logic
		for i, server := range shuffled {
			// Skip server if it's been tried already in this iteration
			if i < attempts {
				continue
			}

			resp, err := r.sendQuery(ctx, req, server)
			if err != nil {
				lastErr = err
				log.Printf("Failed to query %s for %s: %v", server, domain, err)
				continue // Try next server
			}

			return resp, nil
		}
		
		// If we've tried all servers and failed, increment attempts for exponential backoff
		if lastErr != nil {
			attempts++
			// Brief delay before trying alternative servers again
			select {
			case <-time.After(50 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	return nil, fmt.Errorf("all servers failed for %s after %d attempts: last error: %v", domain, maxAttempts, lastErr)
}

// LookupWithoutCache performs a recursive DNS lookup for a given request, bypassing the cache.
func (r *GoDNSResolver) LookupWithoutCache(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return r.recursiveLookup(ctx, req)
}

// Close closes the resolver and frees resources.
func (r *GoDNSResolver) Close() {
	// No specific cleanup needed for this implementation
}
