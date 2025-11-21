package ratelimit

import (
	"dns-resolver/internal/plugins"
	"net"
	"strconv"
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

// GetConfig returns the current configuration of the plugin.
func (p *RateLimitPlugin) GetConfig() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	return map[string]any{
		"rate":          p.rate,
		"burst":         p.burst,
		"cleanupInterval": p.cleanupInterval.String(),
	}
}

// SetConfig updates the configuration of the plugin.
func (p *RateLimitPlugin) SetConfig(config map[string]any) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if rateStr, ok := config["rate"].(string); ok {
		if rateLimit, err := strconv.ParseFloat(rateStr, 64); err == nil {
			p.rate = rate.Limit(rateLimit)
		}
	}

	if burstStr, ok := config["burst"].(string); ok {
		if burst, err := strconv.Atoi(burstStr); err == nil {
			p.burst = burst
		}
	}

	if cleanupInterval, ok := config["cleanupInterval"].(string); ok {
		duration, err := time.ParseDuration(cleanupInterval)
		if err != nil {
			return err
		}
		p.cleanupInterval = duration
	}

	// Update existing limiters
	for _, v := range p.visitors {
		v.limiter.SetLimit(p.rate)
		v.limiter.SetBurst(p.burst)
	}

	return nil
}

// GetConfigFields returns the configuration fields of the plugin.
func (p *RateLimitPlugin) GetConfigFields() []plugins.ConfigField {
	p.mu.Lock()
	defer p.mu.Unlock()
	return []plugins.ConfigField{
		{
			Name:        "rate",
			Description: "Rate limit (queries per second)",
			Type:        "number",
			Value:       p.rate,
		},
		{
			Name:        "burst",
			Description: "Burst size",
			Type:        "number",
			Value:       p.burst,
		},
		{
			Name:        "cleanupInterval",
			Description: "Cleanup interval for visitors (e.g., '1m', '30s')",
			Type:        "text",
			Value:       p.cleanupInterval.String(),
		},
	}
}
