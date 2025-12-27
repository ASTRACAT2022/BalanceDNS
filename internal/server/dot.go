package server

import (
	"crypto/tls"
	"log"

	"github.com/miekg/dns"
)

// DoTServer handles DNS-over-TLS requests.
type DoTServer struct {
	addr     string
	upstream *UpstreamClient
	server   *dns.Server
}

// NewDoTServer creates a new DoTServer.
func NewDoTServer(addr string, upstream *UpstreamClient) *DoTServer {
	return &DoTServer{
		addr:     addr,
		upstream: upstream,
	}
}

// ListenAndServeTLS starts the DoT server.
func (s *DoTServer) ListenAndServeTLS(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	s.server = &dns.Server{
		Addr:      s.addr,
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
		Handler:   dns.HandlerFunc(s.handleDNSRequest),
	}

	log.Printf("Starting DoT server on %s", s.addr)
	return s.server.ListenAndServe()
}

func (s *DoTServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	resp, err := s.upstream.Exchange(r)
	if err != nil {
		log.Printf("DoT Upstream error: %v", err)
		// We can return ServFail
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}
	// Write the response back to the client
	// Note: dns.Client.Exchange returns a new ID, we must match the original ID
	resp.Id = r.Id
	// Also ensure truncated flag handling if necessary, but TCP usually handles large payloads.
	w.WriteMsg(resp)
}

// Shutdown stops the server
func (s *DoTServer) Shutdown() error {
	if s.server != nil {
		return s.server.Shutdown()
	}
	return nil
}
