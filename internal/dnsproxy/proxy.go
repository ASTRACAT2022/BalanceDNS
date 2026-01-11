package dnsproxy

import (
	"fmt"
	"log"
	"time"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"

	"github.com/miekg/dns"
)

// Resolver defines the interface for resolving DNS queries.
type Resolver interface {
	Resolve(question dns.Question) (*dns.Msg, error)
}

// Proxy forwards DNS queries to an upstream resolver.
type Proxy struct {
	Addr     string
	Resolver Resolver
	PM       *plugins.PluginManager
	Metrics  *metrics.Metrics
	Cache    *cache.Cache
}

// NewProxy creates a new DNS proxy.
func NewProxy(addr string, resolver Resolver, pm *plugins.PluginManager, m *metrics.Metrics, c *cache.Cache) *Proxy {
	return &Proxy{
		Addr:     addr,
		Resolver: resolver,
		PM:       pm,
		Metrics:  m,
		Cache:    c,
	}
}

// Start starts the DNS proxy server (UDP and TCP).
func (p *Proxy) Start() error {
	// TCP Server
	tcpServer := &dns.Server{Addr: p.Addr, Net: "tcp", Handler: dns.HandlerFunc(p.handleRequest)}
	go func() {
		log.Printf("Starting DNS Proxy (TCP) on %s", p.Addr)
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Printf("Failed to start TCP proxy: %v", err)
		}
	}()

	// UDP Server
	udpServer := &dns.Server{Addr: p.Addr, Net: "udp", Handler: dns.HandlerFunc(p.handleRequest)}
	log.Printf("Starting DNS Proxy (UDP) on %s", p.Addr)
	if err := udpServer.ListenAndServe(); err != nil {
		log.Printf("Failed to start UDP proxy: %v", err)
		return err
	}
	return nil
}

func (p *Proxy) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	// Record basic stats if metrics enabled
	if p.Metrics != nil && len(r.Question) > 0 {
		qName := r.Question[0].Name
		qType := dns.TypeToString[r.Question[0].Qtype]
		p.Metrics.IncrementQueries(qName)
		p.Metrics.RecordQueryType(qType)
	}

	// Forwarding Logic
	startTime := time.Now()

	var resp *dns.Msg
	var err error

	// 1. Check Policy Cache
	var decision *cache.Decision
	var found bool
	cacheKey := fmt.Sprintf("%d:%s", r.Question[0].Qtype, r.Question[0].Name)

	if p.Cache != nil {
		decision, found = p.Cache.Get(cacheKey)
	}

	if found {
		if p.Metrics != nil {
			p.Metrics.IncrementCacheHits()
		}
		// Act on Decision
		switch decision.Action {
		case cache.ActionBlock:
			// Blocked by policy
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
			w.WriteMsg(m)
			return
		case cache.ActionRewrite:
			// Rewrite logic
			m := new(dns.Msg)
			m.SetReply(r)
			rr, err := dns.NewRR(fmt.Sprintf("%s A %s", r.Question[0].Name, decision.Data))
			if err == nil {
				m.Answer = []dns.RR{rr}
			}
			w.WriteMsg(m)
			return
		case cache.ActionPass:
			// Fallthrough to resolution
		}
	} else {
		if p.Metrics != nil && p.Cache != nil {
			p.Metrics.IncrementCacheMisses()
		}

		// 2. Policy Miss: Execute Plugins
		if p.PM != nil {
			ctx := &plugins.PluginContext{
				ResponseWriter: w,
				Metrics:        p.Metrics,
			}

			// Execute Plugins
			if handled := p.PM.ExecutePlugins(ctx, w, r); handled {
				// Plugin handled it.
				// We assume blocking logic here for simple cache updates,
				// but as discussed, we skip caching "Block" for now if opaque.
				return
			}

			// Passed plugins -> Cache as Pass
			if p.Cache != nil {
				p.Cache.Set(cacheKey, &cache.Decision{Action: cache.ActionPass}, 60*time.Second)
			}
		}
	}

	// 3. Resolve (if Passed)
	resp, err = p.Resolver.Resolve(r.Question[0])
	if err != nil {
		log.Printf("Proxy Error: %v", err)
		// Send failure response
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	// Record latency and response code
	if p.Metrics != nil && len(r.Question) > 0 {
		latency := time.Since(startTime)
		qName := r.Question[0].Name
		p.Metrics.RecordLatency(qName, latency)
		p.Metrics.RecordResponseCode(dns.RcodeToString[resp.Rcode])
		if resp.Rcode == dns.RcodeNameError {
			p.Metrics.RecordNXDOMAIN(qName)
		}
	}

	// Ensure ID matches
	resp.Id = r.Id
	w.WriteMsg(resp)
}
