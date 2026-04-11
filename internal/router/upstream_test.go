package router

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"balancedns/internal/config"
	"balancedns/internal/metrics"

	"github.com/miekg/dns"
)

func TestSelectCandidatesLongestZoneMatch(t *testing.T) {
	r, err := NewResolver([]config.Upstream{
		{Name: "default", Protocol: "udp", Addr: "8.8.8.8:53", Zones: []string{"."}, TimeoutMS: 1000},
		{Name: "ru", Protocol: "udp", Addr: "77.88.8.8:53", Zones: []string{"ru."}, TimeoutMS: 1000},
		{Name: "deep", Protocol: "udp", Addr: "1.1.1.1:53", Zones: []string{"sub.ru."}, TimeoutMS: 1000},
	}, metrics.New())
	if err != nil {
		t.Fatalf("resolver init: %v", err)
	}

	cands := r.selectCandidates("www.sub.ru.")
	if len(cands) < 3 {
		t.Fatalf("expected at least 3 candidates, got %d", len(cands))
	}
	if cands[0].Name != "deep" {
		t.Fatalf("expected deep first, got %s", cands[0].Name)
	}
	if cands[1].Name != "ru" {
		t.Fatalf("expected ru second, got %s", cands[1].Name)
	}
}

func TestForwardDoH(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(msg)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(127, 0, 0, 2),
		})
		packed, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(packed)
	}))
	defer ts.Close()

	r, err := NewResolver([]config.Upstream{
		{Name: "doh", Protocol: "doh", DoHURL: ts.URL, TLSInsecureSkipVerify: true, Zones: []string{"."}, TimeoutMS: 1000},
	}, metrics.New())
	if err != nil {
		t.Fatalf("resolver init: %v", err)
	}

	q := dns.Question{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	req := new(dns.Msg)
	req.SetQuestion(q.Name, q.Qtype)

	resp, up, err := r.Forward(context.Background(), req, q)
	if err != nil {
		t.Fatalf("forward doh: %v", err)
	}
	if up.Name != "doh" {
		t.Fatalf("unexpected upstream: %s", up.Name)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("unexpected answer count: %d", len(resp.Answer))
	}
}

func TestForwardDoT(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		if len(req.Question) > 0 {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(127, 0, 0, 3),
			})
		}
		_ = w.WriteMsg(resp)
	})

	srv := &dns.Server{
		Listener: tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}}),
		Net:      "tcp",
		Handler:  mux,
	}

	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()
	time.Sleep(50 * time.Millisecond)

	r, err := NewResolver([]config.Upstream{
		{Name: "dot", Protocol: "dot", Addr: ln.Addr().String(), TLSInsecureSkipVerify: true, Zones: []string{"."}, TimeoutMS: 1000},
	}, metrics.New())
	if err != nil {
		t.Fatalf("resolver init: %v", err)
	}

	q := dns.Question{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	req := new(dns.Msg)
	req.SetQuestion(q.Name, q.Qtype)

	resp, up, err := r.Forward(context.Background(), req, q)
	if err != nil {
		t.Fatalf("forward dot: %v", err)
	}
	if up.Name != "dot" {
		t.Fatalf("unexpected upstream: %s", up.Name)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("unexpected answer count: %d", len(resp.Answer))
	}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return tls.X509KeyPair(certPEM, keyPEM)
}
