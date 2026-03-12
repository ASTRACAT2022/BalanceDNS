package dnsutil

import "github.com/miekg/dns"

// CapturingResponseWriter proxies writes and keeps the last DNS message for metrics/accounting.
type CapturingResponseWriter struct {
	dns.ResponseWriter
	Msg *dns.Msg
}

func NewCapturingResponseWriter(w dns.ResponseWriter) *CapturingResponseWriter {
	if existing, ok := w.(*CapturingResponseWriter); ok {
		return existing
	}
	return &CapturingResponseWriter{ResponseWriter: w}
}

func (w *CapturingResponseWriter) WriteMsg(msg *dns.Msg) error {
	if msg != nil {
		w.Msg = msg.Copy()
	} else {
		w.Msg = nil
	}
	return w.ResponseWriter.WriteMsg(msg)
}
