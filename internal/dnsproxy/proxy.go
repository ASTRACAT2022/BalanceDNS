package dnsproxy

import (
	"log"
	"time"

	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"

	"github.com/miekg/dns"
)

// Proxy forwards DNS queries to an upstream resolver.
type Proxy struct {
	Addr     string
	Upstream string
	Client   *dns.Client
	PM       *plugins.PluginManager
	Metrics  *metrics.Metrics
}

// NewProxy creates a new DNS proxy.
func NewProxy(addr, upstream string, pm *plugins.PluginManager, m *metrics.Metrics) *Proxy {
	return &Proxy{
		Addr:     addr,
		Upstream: upstream,
		PM:       pm,
		Metrics:  m,
		Client: &dns.Client{
			Net:     "udp",
			Timeout: 2 * time.Second,
		},
	}
}

// Start starts the DNS proxy server (UDP and TCP).
func (p *Proxy) Start() error {
	log.Printf("DEBUG: dnsproxy.Start called for %s -> %s", p.Addr, p.Upstream)
	// TCP Server
	tcpServer := &dns.Server{Addr: p.Addr, Net: "tcp", Handler: dns.HandlerFunc(p.handleRequest)}
	go func() {
		log.Printf("Starting DNS Proxy (TCP) on %s -> %s", p.Addr, p.Upstream)
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Printf("Failed to start TCP proxy: %v", err)
		}
	}()

	// UDP Server
	udpServer := &dns.Server{Addr: p.Addr, Net: "udp", Handler: dns.HandlerFunc(p.handleRequest)}
	log.Printf("Starting DNS Proxy (UDP) on %s -> %s", p.Addr, p.Upstream)
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

	// Execute Plugins
	if p.PM != nil {
		ctx := &plugins.PluginContext{
			ResponseWriter: w,
			Metrics:        p.Metrics,
		}
		if handled := p.PM.ExecutePlugins(ctx, w, r); handled {
			return // Plugin handled the request (e.g. AdBlock blocked it)
		}
	}

	// Forwarding Logic
	// Determine transport
	client := new(dns.Client)
	if w.LocalAddr().Network() == "tcp" {
		client.Net = "tcp"
	} else {
		client.Net = "udp"
	}
	client.Timeout = 2 * time.Second

	startTime := time.Now()
	resp, _, err := client.Exchange(r, p.Upstream)
	if err != nil {
		log.Printf("Proxy Error: %v", err)
		// Send failure response?
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

	w.WriteMsg(resp)
}
