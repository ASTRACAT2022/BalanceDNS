package doh

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"

	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

// Server represents a DNS-over-HTTPS server.
type Server struct {
	Addr           string
	CertFile       string
	KeyFile        string
	UpstreamTarget string // e.g. "127.0.0.1:53"
	Client         *dns.Client
	PM             *plugins.PluginManager
	Metrics        *metrics.Metrics
}

// NewServer creates a new DoH server.
func NewServer(addr, certFile, keyFile, upstream string, pm *plugins.PluginManager, m *metrics.Metrics) *Server {
	return &Server{
		Addr:           addr,
		CertFile:       certFile,
		KeyFile:        keyFile,
		UpstreamTarget: upstream,
		PM:             pm,
		Metrics:        m,
		Client: &dns.Client{
			Net:     "udp",
			Timeout: 2 * time.Second,
		},
	}
}

// Start starts the DoH server.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.handleDoH)
	mux.HandleFunc("/resolve", s.handleJSONResolve)

	server := &http.Server{
		Addr:    s.Addr,
		Handler: mux,
	}

	// Enable HTTP/2
	if err := http2.ConfigureServer(server, nil); err != nil {
		return fmt.Errorf("failed to configure http2: %v", err)
	}

	log.Printf("Starting DoH Server on %s (Upstream: %s)", s.Addr, s.UpstreamTarget)
	if err := server.ListenAndServeTLS(s.CertFile, s.KeyFile); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// handleDoH handles RFC 8484 DNS queries.
func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	var msgBytes []byte
	var err error

	switch r.Method {
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}
		msgBytes, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "Missing 'dns' query parameter", http.StatusBadRequest)
			return
		}
		msgBytes, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(w, "Invalid Base64", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Unpack DNS message
	reqMsg := new(dns.Msg)
	if err := reqMsg.Unpack(msgBytes); err != nil {
		http.Error(w, "Malformed DNS message", http.StatusBadRequest)
		return
	}

	// Record request stats
	if s.Metrics != nil && len(reqMsg.Question) > 0 {
		qName := reqMsg.Question[0].Name
		qType := dns.TypeToString[reqMsg.Question[0].Qtype]
		s.Metrics.IncrementQueries(qName)
		s.Metrics.RecordQueryType(qType)
	}

	// Execute Plugins
	if s.PM != nil {
		dohWriter := &DoHResponseWriter{w: w, r: r}
		ctx := &plugins.PluginContext{
			ResponseWriter: dohWriter,
			Metrics:        s.Metrics,
		}
		if handled := s.PM.ExecutePlugins(ctx, dohWriter, reqMsg); handled {
			return // Plugin handled request (e.g. blocked)
		}
	}

	startTime := time.Now()
	// Forward to Upstream (Knot Resolver)
	respMsg, _, err := s.Client.Exchange(reqMsg, s.UpstreamTarget)
	if err != nil {
		log.Printf("DoH Upstream Error: %v", err)
		http.Error(w, "DNS Upstream Error", http.StatusBadGateway)
		return
	}

	// Record response stats
	if s.Metrics != nil && len(reqMsg.Question) > 0 {
		latency := time.Since(startTime)
		qName := reqMsg.Question[0].Name
		s.Metrics.RecordLatency(qName, latency)
		s.Metrics.RecordResponseCode(dns.RcodeToString[respMsg.Rcode])
		if respMsg.Rcode == dns.RcodeNameError {
			s.Metrics.RecordNXDOMAIN(qName)
		}
	}

	// Pack response
	packedResp, err := respMsg.Pack()
	if err != nil {
		http.Error(w, "Failed to pack response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(packedResp)
}

// DoHResponseWriter adapts http.ResponseWriter to dns.ResponseWriter interface
type DoHResponseWriter struct {
	w http.ResponseWriter
	r *http.Request
}

func (d *DoHResponseWriter) LocalAddr() net.Addr {
	// Dummy local addr
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}
}

func (d *DoHResponseWriter) RemoteAddr() net.Addr {
	host, port, _ := net.SplitHostPort(d.r.RemoteAddr)
	p, _ := net.LookupPort("tcp", port)
	return &net.TCPAddr{IP: net.ParseIP(host), Port: p}
}

func (d *DoHResponseWriter) WriteMsg(msg *dns.Msg) error {
	packed, err := msg.Pack()
	if err != nil {
		return err
	}
	d.w.Header().Set("Content-Type", "application/dns-message")
	d.w.WriteHeader(http.StatusOK)
	_, err = d.w.Write(packed)
	return err
}

func (d *DoHResponseWriter) Write(b []byte) (int, error) {
	return d.w.Write(b)
}

func (d *DoHResponseWriter) Close() error {
	return nil
}

func (d *DoHResponseWriter) TsigStatus() error {
	return nil
}

func (d *DoHResponseWriter) TsigTimersOnly(bool) {
}

func (d *DoHResponseWriter) Hijack() {
}

// handleJSONResolve handles Google-style JSON DNS queries.
func (s *Server) handleJSONResolve(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "Missing 'name' query parameter", http.StatusBadRequest)
		return
	}

	typeStr := r.URL.Query().Get("type")
	if typeStr == "" {
		typeStr = "A"
	}

	// Parse Type
	qType, ok := dns.StringToType[strings.ToUpper(typeStr)]
	if !ok {
		// Try parsing as uint16 if string lookup fails
		if t, err := strconv.Atoi(typeStr); err == nil {
			qType = uint16(t)
		} else {
			http.Error(w, "Invalid type", http.StatusBadRequest)
			return
		}
	}

	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	reqMsg := new(dns.Msg)
	reqMsg.SetQuestion(name, qType)
	reqMsg.RecursionDesired = true

	// Support CD and DO flags
	if r.URL.Query().Get("cd") == "true" {
		reqMsg.CheckingDisabled = true
	}
	if r.URL.Query().Get("do") == "true" {
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetDo()
		reqMsg.Extra = append(reqMsg.Extra, opt)
	}

	// Record request stats
	if s.Metrics != nil && len(reqMsg.Question) > 0 {
		qName := reqMsg.Question[0].Name
		qTypeStr := dns.TypeToString[reqMsg.Question[0].Qtype]
		s.Metrics.IncrementQueries(qName)
		s.Metrics.RecordQueryType(qTypeStr)
	}

	// JSON Response Writer
	jsonWriter := &JSONResponseWriter{w: w, r: r}

	// Execute Plugins
	if s.PM != nil {
		ctx := &plugins.PluginContext{
			ResponseWriter: jsonWriter,
			Metrics:        s.Metrics,
		}
		if handled := s.PM.ExecutePlugins(ctx, jsonWriter, reqMsg); handled {
			return // Plugin handled request
		}
	}

	startTime := time.Now()
	// Forward to Upstream
	respMsg, _, err := s.Client.Exchange(reqMsg, s.UpstreamTarget)
	if err != nil {
		log.Printf("DoH (JSON) Upstream Error: %v", err)
		http.Error(w, "DNS Upstream Error", http.StatusBadGateway)
		return
	}

	// Record response stats
	if s.Metrics != nil && len(reqMsg.Question) > 0 {
		latency := time.Since(startTime)
		qName := reqMsg.Question[0].Name
		s.Metrics.RecordLatency(qName, latency)
		s.Metrics.RecordResponseCode(dns.RcodeToString[respMsg.Rcode])
		if respMsg.Rcode == dns.RcodeNameError {
			s.Metrics.RecordNXDOMAIN(qName)
		}
	}

	jsonWriter.WriteMsg(respMsg)
}

// JSONResponseWriter adapts http.ResponseWriter to dns.ResponseWriter interface returning JSON
type JSONResponseWriter struct {
	w http.ResponseWriter
	r *http.Request
}

func (d *JSONResponseWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}
}

func (d *JSONResponseWriter) RemoteAddr() net.Addr {
	host, port, _ := net.SplitHostPort(d.r.RemoteAddr)
	p, _ := net.LookupPort("tcp", port)
	return &net.TCPAddr{IP: net.ParseIP(host), Port: p}
}

func (d *JSONResponseWriter) WriteMsg(msg *dns.Msg) error {
	respStruct := msgToJSON(msg)
	d.w.Header().Set("Content-Type", "application/json")
	d.w.WriteHeader(http.StatusOK)
	return json.NewEncoder(d.w).Encode(respStruct)
}

func (d *JSONResponseWriter) Write(b []byte) (int, error) {
	// If something writes raw bytes, we assume it might be an error or something else,
	// but strictly speaking dns.ResponseWriter should use WriteMsg.
	// If plugins write raw, we might break JSON format.
	return d.w.Write(b)
}

func (d *JSONResponseWriter) Close() error        { return nil }
func (d *JSONResponseWriter) TsigStatus() error   { return nil }
func (d *JSONResponseWriter) TsigTimersOnly(bool) {}
func (d *JSONResponseWriter) Hijack()             {}

// JSON Response Structures
type DNSResponseJSON struct {
	Status     int            `json:"Status"`
	TC         bool           `json:"TC"`
	RD         bool           `json:"RD"`
	RA         bool           `json:"RA"`
	AD         bool           `json:"AD"`
	CD         bool           `json:"CD"`
	Question   []QuestionJSON `json:"Question,omitempty"`
	Answer     []RecordJSON   `json:"Answer,omitempty"`
	Authority  []RecordJSON   `json:"Authority,omitempty"`
	Additional []RecordJSON   `json:"Additional,omitempty"`
}

type QuestionJSON struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

type RecordJSON struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

func msgToJSON(m *dns.Msg) DNSResponseJSON {
	resp := DNSResponseJSON{
		Status: m.Rcode,
		TC:     m.Truncated,
		RD:     m.RecursionDesired,
		RA:     m.RecursionAvailable,
		AD:     m.AuthenticatedData,
		CD:     m.CheckingDisabled,
	}

	for _, q := range m.Question {
		resp.Question = append(resp.Question, QuestionJSON{
			Name: q.Name,
			Type: q.Qtype,
		})
	}

	resp.Answer = recordsToJSON(m.Answer)
	resp.Authority = recordsToJSON(m.Ns)
	resp.Additional = recordsToJSON(m.Extra)

	return resp
}

func recordsToJSON(rrs []dns.RR) []RecordJSON {
	var result []RecordJSON
	for _, rr := range rrs {
		// Construct data string (strip header)
		// rr.String() returns full record string "name ttl class type data"
		// We want just data.
		// A cleaner way is to sprint the body or use specific types handling,
		// but standard dns RR doesn't easily give just RDATA string without header.
		// However, we can trick it by parsing string output or switching type.
		// A common robust way is using strings.Join(strings.Fields(rr.String())[4:], " ")
		// but that's risky with spaces in data (e.g. TXT).

		// For now, let's use the full string and strip the beginning.
		// The header fields are: Name, TTL, Class, Type

		// Actually, let's just use rr.String() and maybe client parses it,
		// BUT Google API returns just the data part (e.g. IP address).

		// Let's iterate and extract specific types if we want perfection,
		// or use a helper that strips the header from rr.String().

		header := rr.Header()
		fullStr := rr.String()
		// Remove Header part from string
		// Header string format: "Name TTL Class Type" (tab separated typically in rr.String())
		// Example: "google.com.	300	IN	A	142.250.185.78"

		// We can split by tab/space.
		parts := strings.SplitN(fullStr, "\t", 5)
		data := ""
		if len(parts) >= 5 {
			data = parts[4]
		} else {
			// Fallback for when tabs aren't used or other formats
			// Try fields
			fields := strings.Fields(fullStr)
			if len(fields) >= 5 {
				// Rejoin from 5th element
				data = strings.Join(fields[4:], " ")
			} else {
				data = fullStr // Fallback
			}
		}

		result = append(result, RecordJSON{
			Name: header.Name,
			Type: header.Rrtype,
			TTL:  header.Ttl,
			Data: data,
		})
	}
	return result
}
