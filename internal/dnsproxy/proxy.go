package dnsproxy

import (
	"fmt"
	"log"
	"net"
	"strings"
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

	opts     ProxyOptions
	security *securityManager
	policy   *policyEngine
}

// NewProxy creates a new DNS proxy with default options.
func NewProxy(addr string, resolver Resolver, pm *plugins.PluginManager, m *metrics.Metrics, c *cache.Cache) *Proxy {
	return NewProxyWithOptions(addr, resolver, pm, m, c, DefaultProxyOptions())
}

// NewProxyWithOptions creates a DNS proxy with custom security/policy options.
func NewProxyWithOptions(addr string, resolver Resolver, pm *plugins.PluginManager, m *metrics.Metrics, c *cache.Cache, opts ProxyOptions) *Proxy {
	return &Proxy{
		Addr:     addr,
		Resolver: resolver,
		PM:       pm,
		Metrics:  m,
		Cache:    c,
		opts:     opts,
		security: newSecurityManager(opts),
		policy:   newPolicyEngine(opts.Policy),
	}
}

// Start starts the DNS proxy server (UDP and TCP).
func (p *Proxy) Start() error {
	// TCP Server
	tcpServer := &dns.Server{
		Addr:         p.Addr,
		Net:          "tcp",
		Handler:      dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { p.handleRequest("tcp", w, r) }),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  func() time.Duration { return 30 * time.Second },
	}
	go func() {
		log.Printf("Starting DNS Proxy (TCP) on %s", p.Addr)
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Printf("Failed to start TCP proxy: %v", err)
		}
	}()

	// UDP Server
	udpServer := &dns.Server{
		Addr:         p.Addr,
		Net:          "udp",
		Handler:      dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { p.handleRequest("udp", w, r) }),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		UDPSize:      1232,
	}
	log.Printf("Starting DNS Proxy (UDP) on %s", p.Addr)
	if err := udpServer.ListenAndServe(); err != nil {
		log.Printf("Failed to start UDP proxy: %v", err)
		return err
	}
	return nil
}

func (p *Proxy) handleRequest(transport string, w dns.ResponseWriter, r *dns.Msg) {
	startTime := time.Now()
	outcome := "resolved"
	rcodeText := dns.RcodeToString[dns.RcodeSuccess]

	if p.Metrics != nil {
		p.Metrics.IncrementInflightRequests()
		defer p.Metrics.DecrementInflightRequests()
	}

	defer func() {
		if rec := recover(); rec != nil {
			outcome = "panic"
			rcodeText = dns.RcodeToString[dns.RcodeServerFailure]
			log.Printf("Proxy panic recovered: %v", rec)

			m := new(dns.Msg)
			if r != nil {
				m.SetRcode(r, dns.RcodeServerFailure)
			} else {
				m.MsgHdr.Response = true
				m.Rcode = dns.RcodeServerFailure
			}
			_ = w.WriteMsg(m)
		}

		if p.Metrics != nil {
			p.Metrics.RecordRequestOutcome(transport, outcome, rcodeText, time.Since(startTime))
		}
	}()

	clientIP := extractClientIP(w)
	if p.security != nil {
		release, denyReason := p.security.admit(clientIP)
		if denyReason != "" {
			outcome = "security_drop_" + denyReason
			rcodeText = dns.RcodeToString[dns.RcodeRefused]
			if p.Metrics != nil {
				p.Metrics.RecordSecurityDrop(denyReason, transport)
			}
			m := new(dns.Msg)
			if r != nil {
				m.SetRcode(r, dns.RcodeRefused)
			} else {
				m.MsgHdr.Response = true
				m.Rcode = dns.RcodeRefused
			}
			_ = w.WriteMsg(m)
			return
		}
		defer release()
	}

	if r == nil || len(r.Question) == 0 {
		outcome = "malformed"
		rcodeText = dns.RcodeToString[dns.RcodeFormatError]
		if p.Metrics != nil {
			p.Metrics.RecordMalformedRequest(transport)
		}

		m := new(dns.Msg)
		if r != nil {
			m.SetRcode(r, dns.RcodeFormatError)
		} else {
			m.MsgHdr.Response = true
			m.Rcode = dns.RcodeFormatError
		}
		_ = w.WriteMsg(m)
		return
	}

	if p.opts.MaxQuestionsPerRequest > 0 && len(r.Question) > p.opts.MaxQuestionsPerRequest {
		outcome = "security_drop_too_many_questions"
		rcodeText = dns.RcodeToString[dns.RcodeFormatError]
		if p.Metrics != nil {
			p.Metrics.RecordSecurityDrop("too_many_questions", transport)
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}

	question := r.Question[0]
	if p.opts.MaxQNameLength > 0 && len(question.Name) > p.opts.MaxQNameLength {
		outcome = "security_drop_qname_too_long"
		rcodeText = dns.RcodeToString[dns.RcodeFormatError]
		if p.Metrics != nil {
			p.Metrics.RecordSecurityDrop("qname_too_long", transport)
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}

	if p.opts.DropANYQueries && question.Qtype == dns.TypeANY {
		outcome = "security_drop_any_query"
		rcodeText = dns.RcodeToString[dns.RcodeRefused]
		if p.Metrics != nil {
			p.Metrics.RecordSecurityDrop("any_query", transport)
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}

	// Record basic stats if metrics enabled.
	if p.Metrics != nil {
		qName := question.Name
		qType := dns.TypeToString[question.Qtype]
		p.Metrics.IncrementQueries(qName)
		p.Metrics.RecordQueryType(qType)
	}

	if p.policy != nil {
		if msg, handled, action := p.policy.apply(r); handled {
			outcome = "policy_" + action
			rcodeText = dns.RcodeToString[msg.Rcode]
			if p.Metrics != nil {
				p.Metrics.RecordPolicyAction(action)
				if msg.Rcode == dns.RcodeNameError {
					p.Metrics.RecordNXDOMAIN(question.Name)
				}
				p.Metrics.RecordResponseCode(dns.RcodeToString[msg.Rcode])
			}
			_ = w.WriteMsg(msg)
			return
		}
	}

	// Forwarding Logic
	var resp *dns.Msg
	var err error

	// 1. Check Policy Cache
	var decision *cache.Decision
	var found bool
	cacheKey := fmt.Sprintf("%d:%s", question.Qtype, question.Name)

	if p.Cache != nil {
		decision, found = p.Cache.Get(cacheKey)
	}

	if found {
		outcome = "cache_hit"
		if p.Metrics != nil {
			p.Metrics.IncrementCacheHits()
		}
		// Act on Decision
		switch decision.Action {
		case cache.ActionBlock:
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeNameError)
			rcodeText = dns.RcodeToString[dns.RcodeNameError]
			_ = w.WriteMsg(m)
			return
		case cache.ActionRewrite:
			m := new(dns.Msg)
			m.SetReply(r)
			rr, err := dns.NewRR(fmt.Sprintf("%s A %s", question.Name, decision.Data))
			if err == nil {
				m.Answer = []dns.RR{rr}
			}
			rcodeText = dns.RcodeToString[m.Rcode]
			_ = w.WriteMsg(m)
			return
		case cache.ActionPass:
		}
	} else {
		if p.Cache != nil {
			outcome = "cache_miss"
		}
		if p.Metrics != nil && p.Cache != nil {
			p.Metrics.IncrementCacheMisses()
		}

		// 2. Policy Miss: Execute Plugins
		if p.PM != nil {
			ctx := &plugins.PluginContext{
				ResponseWriter: w,
				Metrics:        p.Metrics,
			}

			if handled := p.PM.ExecutePlugins(ctx, w, r); handled {
				outcome = "plugin_handled"
				rcodeText = dns.RcodeToString[dns.RcodeSuccess]
				return
			}

			if p.Cache != nil {
				p.Cache.Set(cacheKey, &cache.Decision{Action: cache.ActionPass}, 60*time.Second)
			}
		}
	}

	// 3. Resolve (if Passed)
	if p.Resolver == nil {
		outcome = "resolver_unavailable"
		rcodeText = dns.RcodeToString[dns.RcodeServerFailure]
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	resp, err = p.Resolver.Resolve(question)
	if err != nil {
		log.Printf("Proxy Error: %v", err)
		outcome = "resolver_error"
		rcodeText = dns.RcodeToString[dns.RcodeServerFailure]
		if p.Metrics != nil {
			p.Metrics.IncrementUnboundErrors()
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
	outcome = "resolved"
	rcodeText = dns.RcodeToString[resp.Rcode]

	if p.Metrics != nil {
		latency := time.Since(startTime)
		qName := question.Name
		p.Metrics.RecordLatency(qName, latency)
		p.Metrics.RecordResponseCode(dns.RcodeToString[resp.Rcode])
		if resp.Rcode == dns.RcodeNameError {
			p.Metrics.RecordNXDOMAIN(qName)
		}
	}

	resp.Id = r.Id
	_ = w.WriteMsg(resp)
}

func extractClientIP(w dns.ResponseWriter) string {
	if w == nil || w.RemoteAddr() == nil {
		return "unknown"
	}
	addr := w.RemoteAddr()
	switch a := addr.(type) {
	case *net.UDPAddr:
		if a.IP != nil {
			return a.IP.String()
		}
	case *net.TCPAddr:
		if a.IP != nil {
			return a.IP.String()
		}
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err == nil {
			return host
		}
		if strings.TrimSpace(addr.String()) != "" {
			return addr.String()
		}
	}
	return "unknown"
}
