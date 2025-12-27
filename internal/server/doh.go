package server

import (
	"encoding/base64"
	"io"
	"log"
	"net/http"

	"github.com/miekg/dns"
)

const (
	MimeTypeDoH = "application/dns-message"
)

// DoHServer handles DNS-over-HTTPS requests.
type DoHServer struct {
	upstream *UpstreamClient
	server   *http.Server
}

// NewDoHServer creates a new DoHServer.
func NewDoHServer(addr string, upstream *UpstreamClient) *DoHServer {
	mux := http.NewServeMux()
	ds := &DoHServer{
		upstream: upstream,
	}
	mux.HandleFunc("/dns-query", ds.handleDNSQuery)

	// Also handle standard root if someone hits it directly, though RFC specifies /dns-query
	// But let's stick to strict RFC for the endpoint.

	ds.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	return ds
}

// ListenAndServeTLS starts the DoH server.
func (s *DoHServer) ListenAndServeTLS(certFile, keyFile string) error {
	log.Printf("Starting DoH server on %s", s.server.Addr)
	return s.server.ListenAndServeTLS(certFile, keyFile)
}

func (s *DoHServer) handleDNSQuery(w http.ResponseWriter, r *http.Request) {
	// 1. Parse the request
	var buf []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsQuery := r.URL.Query().Get("dns")
		if dnsQuery == "" {
			http.Error(w, "Missing 'dns' query parameter", http.StatusBadRequest)
			return
		}
		buf, err = base64.RawURLEncoding.DecodeString(dnsQuery)
		if err != nil {
			http.Error(w, "Invalid base64 encoding", http.StatusBadRequest)
			return
		}

	case http.MethodPost:
		if r.Header.Get("Content-Type") != MimeTypeDoH {
			http.Error(w, "Invalid Content-Type", http.StatusUnsupportedMediaType)
			return
		}
		buf, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusInternalServerError)
			return
		}

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 2. Unpack into DNS message
	reqMsg := new(dns.Msg)
	if err := reqMsg.Unpack(buf); err != nil {
		http.Error(w, "Malformed DNS message", http.StatusBadRequest)
		return
	}

	// 3. Forward to Upstream
	respMsg, err := s.upstream.Exchange(reqMsg)
	if err != nil {
		log.Printf("DoH Upstream error: %v", err)
		http.Error(w, "DNS Upstream Error", http.StatusBadGateway)
		return
	}

	// 4. Send Response
	// RFC 8484 Section 4.1: "The Message ID in the DNS response MUST be 0."
	respMsg.Id = 0
	packed, err := respMsg.Pack()
	if err != nil {
		log.Printf("Failed to pack response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", MimeTypeDoH)
	w.WriteHeader(http.StatusOK)
	w.Write(packed)
}
