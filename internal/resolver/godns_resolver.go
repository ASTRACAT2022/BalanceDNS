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
			Timeout: cfg.UpstreamTimeout,
			Dialer: &net.Dialer{
				Timeout: cfg.UpstreamTimeout,
			},
		},
		workerPool: NewWorkerPool(cfg.MaxWorkers),
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
	if msg, found, revalidate := r.cache.Get(key); found {
		log.Printf("Cache hit for %s (revalidate: %t)", q.Name, revalidate)
		if msg == nil {
			log.Printf("Cache returned nil message for key %s", key)
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

					ctx, cancel := context.WithTimeout(context.Background(), r.config.UpstreamTimeout)
					defer cancel()

					// Create a new request for revalidation
					revalidationReq := new(dns.Msg)
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

					if msg, ok := res.(*dns.Msg); ok {
						r.cache.Set(key, msg, r.config.StaleWhileRevalidate)
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

	msg := res.(*dns.Msg)
	msg.Id = req.Id

	// Cache the response
	r.cache.Set(key, msg, r.config.StaleWhileRevalidate)

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
	result, err := r.lookup(ctx, q.Name, q.Qtype)
	if err != nil {
		r.metrics.IncrementUnboundErrors()
		log.Printf("Recursive resolution error for %s: %v", q.Name, err)
		// Return a SERVFAIL message when resolution fails
		msg := new(dns.Msg)
		msg.SetRcode(req, dns.RcodeServerFailure)
		return msg, err
	}

	// Create a new message and set the reply based on the original request
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

// lookup performs a recursive lookup for a given domain and query type.
func (r *GoDNSResolver) lookup(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	return r.lookupWithServers(ctx, name, qtype, r.rootServers, make(map[string]bool))
}

// lookupWithServers performs the recursive lookup using a specific set of nameservers.
func (r *GoDNSResolver) lookupWithServers(ctx context.Context, name string, qtype uint16, servers []string, queriedServers map[string]bool) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	req.RecursionDesired = false

	for _, server := range r.shuffleServers(servers) {
		if queriedServers[server] {
			continue // Skip servers we've already queried in this chain.
		}
		queriedServers[server] = true

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		resp, _, err := r.client.ExchangeContext(ctx, req, server)
		if err != nil {
			log.Printf("Failed to query %s for %s: %v", server, name, err)
			continue
		}

		if resp.Rcode == dns.RcodeSuccess {
			if len(resp.Answer) > 0 {
				// We have an answer. This could be the final answer or a CNAME.
				// Check for CNAMEs and follow them if necessary.
				for _, rr := range resp.Answer {
					if cname, ok := rr.(*dns.CNAME); ok {
						return r.lookup(ctx, cname.Target, qtype)
					}
				}
				return resp, nil // This is the final answer.
			}
		}

		if resp.Rcode == dns.RcodeNameError {
			// The authoritative server says the name doesn't exist.
			return resp, nil
		}

		// Check for referrals in the Authority section.
		if len(resp.Ns) > 0 {
			nextServers := []string{}
			glueAvailable := false

			// Check for glue records in the Additional section.
			for _, rr := range resp.Extra {
				if a, ok := rr.(*dns.A); ok {
					for _, ns := range resp.Ns {
						if ns, ok := ns.(*dns.NS); ok {
							if strings.EqualFold(ns.Ns, a.Hdr.Name) {
								nextServers = append(nextServers, net.JoinHostPort(a.A.String(), "53"))
								glueAvailable = true
							}
						}
					}
				}
				if aaaa, ok := rr.(*dns.AAAA); ok {
					for _, ns := range resp.Ns {
						if ns, ok := ns.(*dns.NS); ok {
							if strings.EqualFold(ns.Ns, aaaa.Hdr.Name) {
								nextServers = append(nextServers, net.JoinHostPort(aaaa.AAAA.String(), "53"))
								glueAvailable = true
							}
						}
					}
				}
			}

			if glueAvailable {
				// We have glue records, so we can proceed with the next iteration.
				return r.lookupWithServers(ctx, name, qtype, nextServers, queriedServers)
			}

			// No glue records. We need to resolve the nameservers' IP addresses.
			for _, ns := range resp.Ns {
				if ns, ok := ns.(*dns.NS); ok {
					// To avoid a loop, we resolve the NS records using the *original* lookup function.
					// This is a simplified approach. A more robust implementation
					// would be more careful about resolution loops.
					nsMsg, err := r.lookup(ctx, ns.Ns, dns.TypeA)
					if err != nil {
						log.Printf("Failed to resolve NS %s: %v", ns.Ns, err)
						continue
					}
					for _, ans := range nsMsg.Answer {
						if a, ok := ans.(*dns.A); ok {
							nextServers = append(nextServers, net.JoinHostPort(a.A.String(), "53"))
						}
						if aaaa, ok := ans.(*dns.AAAA); ok {
							nextServers = append(nextServers, net.JoinHostPort(aaaa.AAAA.String(), "53"))
						}
					}
				}
			}

			if len(nextServers) > 0 {
				return r.lookupWithServers(ctx, name, qtype, nextServers, queriedServers)
			}
		}
	}

	return nil, fmt.Errorf("resolution failed for %s: no servers responded", name)
}

// shuffleServers randomizes the order of a slice of servers.
func (r *GoDNSResolver) shuffleServers(servers []string) []string {
	shuffled := make([]string, len(servers))
	copy(shuffled, servers)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	return shuffled
}

// sendQuery sends a single DNS query to the specified server
func (r *GoDNSResolver) sendQuery(ctx context.Context, req *dns.Msg, server string) (*dns.Msg, error) {
	// Create a context with a deadline for this specific query
	queryCtx, cancel := context.WithTimeout(ctx, r.config.UpstreamTimeout/3) // Use 1/3 of timeout per attempt
	defer cancel()

	// Use the client to send the query
	resp, _, err := r.client.ExchangeContext(queryCtx, req, server)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// LookupWithoutCache performs a recursive DNS lookup for a given request, bypassing the cache.
func (r *GoDNSResolver) LookupWithoutCache(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return r.recursiveLookup(ctx, req)
}

// Close closes the resolver and frees resources.
func (r *GoDNSResolver) Close() {
	// No specific cleanup needed for this implementation
}