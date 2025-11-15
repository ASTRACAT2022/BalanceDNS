package resolver

import (
	"context"
	"log"
	"net"
	"strings"
	"time"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// NetResolver uses Go's standard library net.Resolver for DNS resolution
type NetResolver struct {
	config     *config.Config
	cache      *cache.Cache
	sf         singleflight.Group
	client     *net.Resolver
	workerPool *WorkerPool
	metrics    *metrics.Metrics
}

// NewNetResolver creates a new resolver using Go's standard library
func NewNetResolver(cfg *config.Config, c *cache.Cache, m *metrics.Metrics) *NetResolver {
	r := &NetResolver{
		config: cfg,
		cache:  c,
		sf:     singleflight.Group{},
		client: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: cfg.UpstreamTimeout,
				}
				return d.DialContext(ctx, network, address)
			},
		},
		workerPool: NewWorkerPool(cfg.MaxWorkers),
		metrics:    m,
	}

	return r
}

// GetSingleflightGroup returns the singleflight.Group instance.
func (r *NetResolver) GetSingleflightGroup() *singleflight.Group {
	return &r.sf
}

// GetConfig returns the resolver's configuration.
func (r *NetResolver) GetConfig() *config.Config {
	return r.config
}

// Resolve performs DNS lookup using Go's standard library
func (r *NetResolver) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Question[0]
	key := cache.Key(q)

	// Check the cache first.
	if msg, found, revalidate := r.cache.Get(key); found {
		log.Printf("Cache hit for %s (revalidate: %t)", q.Name, revalidate)
		msg.Id = req.Id

		if revalidate {
			r.metrics.IncrementCacheRevalidations()
			// Trigger a background revalidation
			go func() {
				if err := r.workerPool.Acquire(context.Background()); err != nil {
					log.Printf("Failed to acquire worker for revalidation: %v", err)
					return
				}
				defer r.workerPool.Release()

				ctx, cancel := context.WithTimeout(context.Background(), r.config.UpstreamTimeout)
				defer cancel()

				revalidationReq := new(dns.Msg)
				revalidationReq.SetQuestion(q.Name, q.Qtype)
				revalidationReq.RecursionDesired = true
				if opt := req.IsEdns0(); opt != nil {
					revalidationReq.SetEdns0(opt.UDPSize(), opt.Do())
				}

				res, err, _ := r.sf.Do(key+"-revalidate", func() (interface{}, error) {
					return r.exchange(ctx, revalidationReq)
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

	// Use singleflight to ensure only one lookup for a given question is in flight at a time.
	res, err, _ := r.sf.Do(key, func() (interface{}, error) {
		return r.exchange(ctx, req)
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

// exchange performs the actual DNS exchange using net.Resolver
func (r *NetResolver) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Question[0]
	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime)
		r.metrics.RecordLatency(q.Name, latency)
		// Record upstream query duration
		r.metrics.RecordUpstreamQueryDuration(dns.TypeToString[q.Qtype], latency)
	}()

	// Create a new response
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = dns.RcodeSuccess

	// Normalize domain name
	domain := strings.TrimSuffix(q.Name, ".")

	// Handle different query types
	switch q.Qtype {
	case dns.TypeA:
		ips, err := r.client.LookupIPAddr(ctx, domain)
		if err != nil {
			if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
				resp.Rcode = dns.RcodeNameError
				r.metrics.RecordNXDOMAIN(q.Name)
			} else {
				r.metrics.IncrementGoDNSErrors()
				log.Printf("LookupIPAddr error for %s: %v", domain, err)
				resp.Rcode = dns.RcodeServerFailure
			}
			return resp, nil
		}

		for _, ip := range ips {
			if ip.IP.To4() != nil { // IPv4
				rr := &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300, // Default TTL
					},
					A: ip.IP,
				}
				resp.Answer = append(resp.Answer, rr)
			}
		}

	case dns.TypeAAAA:
		ips, err := r.client.LookupIPAddr(ctx, domain)
		if err != nil {
			if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
				resp.Rcode = dns.RcodeNameError
				r.metrics.RecordNXDOMAIN(q.Name)
			} else {
				r.metrics.IncrementGoDNSErrors()
				log.Printf("LookupIPAddr error for %s: %v", domain, err)
				resp.Rcode = dns.RcodeServerFailure
			}
			return resp, nil
		}

		for _, ip := range ips {
			if ip.IP.To4() == nil && ip.IP.To16() != nil { // IPv6
				rr := &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    300, // Default TTL
					},
					AAAA: ip.IP,
				}
				resp.Answer = append(resp.Answer, rr)
			}
		}

	case dns.TypeNS:
		nss, err := r.client.LookupNS(ctx, domain)
		if err != nil {
			if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
				resp.Rcode = dns.RcodeNameError
				r.metrics.RecordNXDOMAIN(q.Name)
			} else {
				r.metrics.IncrementGoDNSErrors()
				log.Printf("LookupNS error for %s: %v", domain, err)
				resp.Rcode = dns.RcodeServerFailure
			}
			return resp, nil
		}

		for _, ns := range nss {
			rr := &dns.NS{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeNS,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Ns: dns.Fqdn(ns.Host),
			}
			resp.Answer = append(resp.Answer, rr)
		}

	case dns.TypeMX:
		mxs, err := r.client.LookupMX(ctx, domain)
		if err != nil {
			if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
				resp.Rcode = dns.RcodeNameError
				r.metrics.RecordNXDOMAIN(q.Name)
			} else {
				r.metrics.IncrementGoDNSErrors()
				log.Printf("LookupMX error for %s: %v", domain, err)
				resp.Rcode = dns.RcodeServerFailure
			}
			return resp, nil
		}

		for _, mx := range mxs {
			rr := &dns.MX{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeMX,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Preference: uint16(mx.Pref),
				Mx:         dns.Fqdn(mx.Host),
			}
			resp.Answer = append(resp.Answer, rr)
		}

	case dns.TypeTXT:
		txts, err := r.client.LookupTXT(ctx, domain)
		if err != nil {
			if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
				resp.Rcode = dns.RcodeNameError
				r.metrics.RecordNXDOMAIN(q.Name)
			} else {
				r.metrics.IncrementGoDNSErrors()
				log.Printf("LookupTXT error for %s: %v", domain, err)
				resp.Rcode = dns.RcodeServerFailure
			}
			return resp, nil
		}

		for _, txt := range txts {
			rr := &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Txt: splitTxt(txt),
			}
			resp.Answer = append(resp.Answer, rr)
		}

	case dns.TypeCNAME:
		cname, err := r.client.LookupCNAME(ctx, domain)
		if err != nil {
			if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
				resp.Rcode = dns.RcodeNameError
				r.metrics.RecordNXDOMAIN(q.Name)
			} else {
				r.metrics.IncrementGoDNSErrors()
				log.Printf("LookupCNAME error for %s: %v", domain, err)
				resp.Rcode = dns.RcodeServerFailure
			}
			return resp, nil
		}

		rr := &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Target: dns.Fqdn(cname),
		}
		resp.Answer = append(resp.Answer, rr)

	default:
		// For unsupported types, return Not Implemented
		resp.Rcode = dns.RcodeNotImplemented
		return resp, nil
	}

	return resp, nil
}

// splitTxt splits a TXT record according to DNS protocol limits
func splitTxt(txt string) []string {
	const maxTXTLen = 255
	var result []string

	for len(txt) > maxTXTLen {
		result = append(result, txt[:maxTXTLen])
		txt = txt[maxTXTLen:]
	}
	if len(txt) > 0 {
		result = append(result, txt)
	}

	return result
}

// LookupWithoutCache performs a DNS lookup bypassing the cache.
func (r *NetResolver) LookupWithoutCache(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return r.exchange(ctx, req)
}

// Close closes the resolver and frees resources.
func (r *NetResolver) Close() {
	// No specific cleanup needed for this implementation
}