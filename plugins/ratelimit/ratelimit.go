package ratelimit

import (
	"dns-resolver/internal/plugins"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

// RateLimitPlugin enforces a rate limit on DNS queries.
type RateLimitPlugin struct {
	mu            sync.Mutex
	visitors      map[string]*visitor
	rate          rate.Limit
	burst         int
	cleanupInterval time.Duration
}

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// New creates a new RateLimitPlugin.
func New(r rate.Limit, b int, cleanupInterval time.Duration) *RateLimitPlugin {
	p := &RateLimitPlugin{
		visitors:      make(map[string]*visitor),
		rate:          r,
		burst:         b,
		cleanupInterval: cleanupInterval,
	}
	go p.cleanupVisitors()
	return p
}

// Name returns the name of the plugin.
func (p *RateLimitPlugin) Name() string {
	return "ratelimit"
}

// Execute applies the rate limit logic.
func (p *RateLimitPlugin) Execute(ctx *plugins.PluginContext, w dns.ResponseWriter, r *dns.Msg) (bool, error) {
	ip, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		// Can't determine IP, let it pass.
		return false, nil
	}

	limiter := p.getVisitor(ip)
	if !limiter.Allow() {
		// Return a DNS response with RCODE=REFUSED
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return true, nil // Stop processing
	}

	return false, nil // Continue processing
}

func (p *RateLimitPlugin) getVisitor(ip string) *rate.Limiter {
	p.mu.Lock()
	defer p.mu.Unlock()

	v, exists := p.visitors[ip]
	if !exists {
		limiter := rate.NewLimiter(p.rate, p.burst)
		p.visitors[ip] = &visitor{limiter, time.Now()}
		return limiter
	}

	v.lastSeen = time.Now()
	return v.limiter
}

func (p *RateLimitPlugin) cleanupVisitors() {
	ticker := time.NewTicker(p.cleanupInterval)
	for range ticker.C {
		p.mu.Lock()
		for ip, v := range p.visitors {
			if time.Since(v.lastSeen) > 3*p.cleanupInterval {
				delete(p.visitors, ip)
			}
		}
		p.mu.Unlock()
	}
}
