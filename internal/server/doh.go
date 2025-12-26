package server

import (
	"dns-resolver/internal/pool"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/miekg/dns"
)

// dohHandler is the HTTP handler for DoH requests.
func (s *Server) dohHandler(w http.ResponseWriter, r *http.Request) {
	var query []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		// DecodeString allocates, but we can't easily avoid it without a custom decoder or more complex logic.
		// For GET, the query is usually small.
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

		// We use io.ReadAll which allocates, but ensures we get the full message.
		// Optimizing this with a fixed size pool is tricky because we don't know the size upfront
		// (Content-Length might be missing) and dns messages can be up to 64KB.
		// For now, we rely on ResponseWriter and DnsMsg pooling for performance gains.
		query, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	msg := pool.GetDnsMsg()
	defer pool.PutDnsMsg(msg)

	if err := msg.Unpack(query); err != nil {
		http.Error(w, "Failed to unpack DNS message", http.StatusBadRequest)
		return
	}

	// Use pooled ResponseWriter
	dummyWriter := getDohResponseWriter()
	defer putDohResponseWriter(dummyWriter)

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

var dohResponseWriterPool = sync.Pool{
	New: func() interface{} {
		return &dohResponseWriter{
			headers: http.Header{},
		}
	},
}

func getDohResponseWriter() *dohResponseWriter {
	return dohResponseWriterPool.Get().(*dohResponseWriter)
}

func putDohResponseWriter(w *dohResponseWriter) {
	w.msg = nil
	// Reset headers? http.Header is a map. iterating to delete is slow.
	// Maybe just re-allocate map if it's dirty? Or just leave it if we don't use it much?
	// We init it with empty.
	for k := range w.headers {
		delete(w.headers, k)
	}
	dohResponseWriterPool.Put(w)
}

func (w *dohResponseWriter) LocalAddr() net.Addr         { return nil }
func (w *dohResponseWriter) RemoteAddr() net.Addr        { return nil }
func (w *dohResponseWriter) WriteMsg(m *dns.Msg) error   { w.msg = m; return nil }
func (w *dohResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *dohResponseWriter) Close() error                { return nil }
func (w *dohResponseWriter) TsigStatus() error           { return nil }
func (w *dohResponseWriter) TsigTimersOnly(b bool)       {}
func (w *dohResponseWriter) Hijack()                     {}
