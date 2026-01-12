package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/sync/singleflight"
)

// MockResolver implements resolver.ResolverInterface
type MockResolver struct {
	mock.Mock
}

func (m *MockResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	args := m.Called(ctx, msg)
	return args.Get(0).(*dns.Msg), args.Error(1)
}

func (m *MockResolver) Close() {
}

func (m *MockResolver) LookupWithoutCache(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*dns.Msg), args.Error(1)
}

func (m *MockResolver) GetSingleflightGroup() *singleflight.Group {
	return &singleflight.Group{}
}

func (m *MockResolver) GetConfig() *config.Config {
	return config.NewConfig()
}

// Generate self-signed cert for testing
func generateCert(t *testing.T, dir string) (string, string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	certOut, err := os.Create(filepath.Join(dir, "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.Create(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	return filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
}

func TestServer_DoT_DoH(t *testing.T) {
	// Setup Temp Dir for Certs
	tmpDir, err := os.MkdirTemp("", "dns-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	certFile, keyFile := generateCert(t, tmpDir)

	// Setup Config
	cfg := config.NewConfig()
	cfg.DoTAddr = "127.0.0.1:18853" // Ephemeral ports
	cfg.DoHAddr = "127.0.0.1:18443"
	cfg.CertFile = certFile
	cfg.KeyFile = keyFile
	cfg.ListenAddr = "127.0.0.1:18053"

	// Mock Resolver
	mockMetaRes := new(MockResolver)
	mockMetaRes.On("Resolve", mock.Anything, mock.Anything).Return(&dns.Msg{
		MsgHdr: dns.MsgHdr{
			Response: true,
			Rcode:    dns.RcodeSuccess,
		},
		Answer: []dns.RR{},
	}, nil)

	// Deps
	m := metrics.NewMetrics("/tmp/metrics_test.json")
	pm := plugins.NewPluginManager()

	srv := NewServer(cfg, m, mockMetaRes, pm)

	// Start Server components manually since ListenAndServe blocks
	go srv.startListener("tcp-tls") // DoT
	go srv.startDoHListener()       // DoH

	// Give it a moment to start
	time.Sleep(1 * time.Second)

	// 1. Test DoT
	t.Run("DoT Request", func(t *testing.T) {
		c := new(dns.Client)
		c.Net = "tcp-tls"
		c.TLSConfig = &tls.Config{InsecureSkipVerify: true} // Trust our self-signed cert

		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		r, _, err := c.Exchange(m, cfg.DoTAddr)

		assert.NoError(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, dns.RcodeSuccess, r.Rcode)
	})

	// 2. Test DoH
	t.Run("DoH Request", func(t *testing.T) {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}

		// Prepare DNS query
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		packed, _ := m.Pack()

		resp, err := client.Post(
			fmt.Sprintf("https://%s/dns-query", cfg.DoHAddr),
			"application/dns-message",
			bytes.NewReader(packed),
		)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, _ := io.ReadAll(resp.Body)
		respMsg := new(dns.Msg)
		err = respMsg.Unpack(body)
		assert.NoError(t, err)
		assert.Equal(t, dns.RcodeSuccess, respMsg.Rcode)
	})

	// 3. Test ODoH Configs
	t.Run("ODoH Configs", func(t *testing.T) {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}

		resp, err := client.Get(fmt.Sprintf("https://%s/odohconfigs", cfg.DoHAddr))
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "application/oblivious-doh-configs", resp.Header.Get("Content-Type"))
	})
}
