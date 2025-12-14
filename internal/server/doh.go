package server

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"

	"github.com/miekg/dns"
	"sync"
)

var dohWriterPool = sync.Pool{
	New: func() interface{} {
		return &dohResponseWriter{
			headers: http.Header{},
		}
	},
}

// dohHandler is the HTTP handler for DoH requests.
func (s *Server) dohHandler(w http.ResponseWriter, r *http.Request) {
	var query []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		query, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if err != nil {
			http.Error(w, "Invalid DNS query", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}
		query, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(query); err != nil {
		http.Error(w, "Failed to unpack DNS message", http.StatusBadRequest)
		return
	}

	// Get a dummy ResponseWriter from the pool
	dummyWriter := dohWriterPool.Get().(*dohResponseWriter)
	defer dohWriterPool.Put(dummyWriter)
	dummyWriter.msg = nil // Reset the message field

	// Use the existing DNS handler
	s.handler.ServeDNS(dummyWriter, msg)

	if dummyWriter.msg == nil {
		http.Error(w, "Failed to resolve DNS query", http.StatusInternalServerError)
		return
	}

	resp, err := dummyWriter.msg.Pack()
	if err != nil {
		http.Error(w, "Failed to pack DNS response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(resp)
}

// dohResponseWriter is a dummy dns.ResponseWriter for DoH.
type dohResponseWriter struct {
	msg     *dns.Msg
	headers http.Header
}

func (w *dohResponseWriter) LocalAddr() net.Addr         { return nil }
func (w *dohResponseWriter) RemoteAddr() net.Addr        { return nil }
func (w *dohResponseWriter) WriteMsg(m *dns.Msg) error   { w.msg = m; return nil }
func (w *dohResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *dohResponseWriter) Close() error                { return nil }
func (w *dohResponseWriter) TsigStatus() error           { return nil }
func (w *dohResponseWriter) TsigTimersOnly(b bool)       {}
func (w *dohResponseWriter) Hijack()                     {}
