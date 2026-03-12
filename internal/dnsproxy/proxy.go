package dnsproxy

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/dnsutil"
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
	mu sync.RWMutex

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
		ReusePort:    p.opts.ReusePort,
		ReuseAddr:    p.opts.ReuseAddr,
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
		ReusePort:    p.opts.ReusePort,
		ReuseAddr:    p.opts.ReuseAddr,
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

	p.mu.RLock()
	security := p.security
	policy := p.policy
	maxQuestionsPerRequest := p.opts.MaxQuestionsPerRequest
	maxQNameLength := p.opts.MaxQNameLength
	dropANYQueries := p.opts.DropANYQueries
	p.mu.RUnlock()

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
			if p.Metrics != nil {
				qName := ""
				if r != nil && len(r.Question) > 0 {
					qName = r.Question[0].Name
				}
				p.Metrics.RecordDNSResponse(qName, dns.RcodeServerFailure)
			}
			_ = p.writeResponse(transport, w, r, m)
		}

		if p.Metrics != nil {
			p.Metrics.RecordRequestOutcome(transport, outcome, rcodeText, time.Since(startTime))
		}
	}()

	clientIP := extractClientIP(w)
	if security != nil {
		release, denyReason := security.admit(clientIP)
		if denyReason != "" {
			outcome = "security_drop_" + denyReason
			rcodeText = dns.RcodeToString[dns.RcodeRefused]
			if p.Metrics != nil {
				p.Metrics.RecordSecurityDrop(denyReason, transport)
				qName := ""
				if r != nil && len(r.Question) > 0 {
					qName = r.Question[0].Name
				}
				p.Metrics.RecordDNSResponse(qName, dns.RcodeRefused)
			}
			m := new(dns.Msg)
			if r != nil {
				m.SetRcode(r, dns.RcodeRefused)
			} else {
				m.MsgHdr.Response = true
				m.Rcode = dns.RcodeRefused
			}
			_ = p.writeResponse(transport, w, r, m)
			return
		}
		defer release()
	}

	if r == nil || len(r.Question) == 0 {
		outcome = "malformed"
		rcodeText = dns.RcodeToString[dns.RcodeFormatError]
		if p.Metrics != nil {
			p.Metrics.RecordMalformedRequest(transport)
			p.Metrics.RecordDNSResponse("", dns.RcodeFormatError)
		}

		m := new(dns.Msg)
		if r != nil {
			m.SetRcode(r, dns.RcodeFormatError)
		} else {
			m.MsgHdr.Response = true
			m.Rcode = dns.RcodeFormatError
		}
		_ = p.writeResponse(transport, w, r, m)
		return
	}

	if maxQuestionsPerRequest > 0 && len(r.Question) > maxQuestionsPerRequest {
		outcome = "security_drop_too_many_questions"
		rcodeText = dns.RcodeToString[dns.RcodeFormatError]
		if p.Metrics != nil {
			p.Metrics.RecordSecurityDrop("too_many_questions", transport)
			p.Metrics.RecordDNSResponse(r.Question[0].Name, dns.RcodeFormatError)
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		_ = p.writeResponse(transport, w, r, m)
		return
	}

	question := r.Question[0]
	if p.Metrics != nil {
		p.Metrics.RecordDNSQuery(question)
	}

	if maxQNameLength > 0 && len(question.Name) > maxQNameLength {
		outcome = "security_drop_qname_too_long"
		rcodeText = dns.RcodeToString[dns.RcodeFormatError]
		if p.Metrics != nil {
			p.Metrics.RecordSecurityDrop("qname_too_long", transport)
			p.Metrics.RecordDNSResponse(question.Name, dns.RcodeFormatError)
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		_ = p.writeResponse(transport, w, r, m)
		return
	}

	if p.PM != nil {
		pluginWriter := dnsutil.NewCapturingResponseWriter(w)
		ctx := &plugins.PluginContext{
			ResponseWriter: pluginWriter,
			Metrics:        p.Metrics,
		}
		if handled := p.PM.ExecutePreflightPlugins(ctx, pluginWriter, r); handled {
			if pluginWriter.Msg != nil {
				outcome = "plugin_handled"
				rcodeText = dns.RcodeToString[pluginWriter.Msg.Rcode]
				if p.Metrics != nil {
					p.Metrics.RecordDNSResponse(question.Name, pluginWriter.Msg.Rcode)
				}
				return
			}

			outcome = "plugin_dropped"
			rcodeText = "DROPPED"
			if question.Qtype == dns.TypeANY {
				outcome = "security_drop_any_query"
				if p.Metrics != nil {
					p.Metrics.RecordSecurityDrop("any_query", transport)
				}
			}
			return
		}
	}

	if dropANYQueries && question.Qtype == dns.TypeANY {
		outcome = "security_drop_any_query"
		rcodeText = dns.RcodeToString[dns.RcodeRefused]
		if p.Metrics != nil {
			p.Metrics.RecordSecurityDrop("any_query", transport)
			p.Metrics.RecordDNSResponse(question.Name, dns.RcodeRefused)
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = p.writeResponse(transport, w, r, m)
		return
	}

	if policy != nil {
		if msg, handled, action := policy.apply(r); handled {
			outcome = "policy_" + action
			rcodeText = dns.RcodeToString[msg.Rcode]
			if p.Metrics != nil {
				p.Metrics.RecordPolicyAction(action)
				p.Metrics.RecordDNSResponse(question.Name, msg.Rcode)
			}
			_ = p.writeResponse(transport, w, r, msg)
			return
		}
	}

	// Forwarding Logic
	var resp *dns.Msg
	var err error

	// 1. Check Policy Cache
	var decision *cache.Decision
	var found bool
	cacheKey := buildDecisionCacheKey(question.Qtype, question.Name)

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
			_ = p.writeResponse(transport, w, r, m)
			return
		case cache.ActionRewrite:
			m := new(dns.Msg)
			m.SetReply(r)
			rr, err := dns.NewRR(fmt.Sprintf("%s A %s", question.Name, decision.Data))
			if err == nil {
				m.Answer = []dns.RR{rr}
			}
			rcodeText = dns.RcodeToString[m.Rcode]
			_ = p.writeResponse(transport, w, r, m)
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
			pluginWriter := dnsutil.NewCapturingResponseWriter(w)
			ctx := &plugins.PluginContext{
				ResponseWriter: pluginWriter,
				Metrics:        p.Metrics,
			}

			if handled := p.PM.ExecutePlugins(ctx, pluginWriter, r); handled {
				if pluginWriter.Msg != nil {
					outcome = "plugin_handled"
					rcodeText = dns.RcodeToString[pluginWriter.Msg.Rcode]
					if p.Metrics != nil {
						p.Metrics.RecordDNSResponse(question.Name, pluginWriter.Msg.Rcode)
					}
					return
				}

				outcome = "plugin_dropped"
				rcodeText = "DROPPED"
				if question.Qtype == dns.TypeANY {
					outcome = "security_drop_any_query"
					if p.Metrics != nil {
						p.Metrics.RecordSecurityDrop("any_query", transport)
					}
				}
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
		if p.Metrics != nil {
			p.Metrics.RecordDNSResponse(question.Name, dns.RcodeServerFailure)
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = p.writeResponse(transport, w, r, m)
		return
	}

	resp, err = p.Resolver.Resolve(question)
	if err != nil {
		log.Printf("Proxy Error: %v", err)
		outcome = "resolver_error"
		rcodeText = dns.RcodeToString[dns.RcodeServerFailure]
		if p.Metrics != nil {
			p.Metrics.IncrementUnboundErrors()
			p.Metrics.RecordDNSResponse(question.Name, dns.RcodeServerFailure)
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = p.writeResponse(transport, w, r, m)
		return
	}
	outcome = "resolved"
	rcodeText = dns.RcodeToString[resp.Rcode]

	if p.Metrics != nil {
		latency := time.Since(startTime)
		qName := question.Name
		p.Metrics.RecordLatency(qName, latency)
		p.Metrics.RecordDNSResponse(qName, resp.Rcode)
	}

	_ = p.writeResponse(transport, w, r, resp)
}

// UpdatePolicy applies a new in-memory policy configuration for subsequent requests.
func (p *Proxy) UpdatePolicy(opts ProxyPolicyOptions) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.opts.Policy = opts
	p.policy = newPolicyEngine(opts)
}

func (p *Proxy) writeResponse(transport string, w dns.ResponseWriter, req *dns.Msg, resp *dns.Msg) error {
	if w == nil {
		return nil
	}
	msg := finalizeResponse(transport, req, resp)
	return w.WriteMsg(msg)
}

func finalizeResponse(transport string, req *dns.Msg, resp *dns.Msg) *dns.Msg {
	if resp == nil {
		resp = new(dns.Msg)
		if req != nil {
			resp.SetRcode(req, dns.RcodeServerFailure)
		} else {
			resp.MsgHdr.Response = true
			resp.Rcode = dns.RcodeServerFailure
		}
	}

	out := resp.Copy()
	out.MsgHdr.Response = true
	out.RecursionAvailable = true
	out.Authoritative = false

	if req != nil {
		out.Id = req.Id
		out.Opcode = req.Opcode
		out.RecursionDesired = req.RecursionDesired
		out.CheckingDisabled = req.CheckingDisabled
		out.Question = append([]dns.Question(nil), req.Question...)
	}

	if transport == "udp" {
		maxSize := 512
		if req != nil {
			if opt := req.IsEdns0(); opt != nil && opt.UDPSize() >= 512 {
				maxSize = int(opt.UDPSize())
			}
		}
		out.Truncate(maxSize)
	}

	return out
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

func buildDecisionCacheKey(qtype uint16, qname string) string {
	buf := make([]byte, 0, len(qname)+8)
	buf = strconv.AppendUint(buf, uint64(qtype), 10)
	buf = append(buf, ':')
	buf = append(buf, qname...)
	return string(buf)
}
