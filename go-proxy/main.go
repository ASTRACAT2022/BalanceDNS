package main

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)

var (
	upstreamAddr = flag.String("upstream", "127.0.0.1:53", "Upstream DNS server address (UDP)")
	dohAddr      = flag.String("doh", "0.0.0.0:443", "DoH listen address")
	dotAddr      = flag.String("dot", "0.0.0.0:853", "DoT listen address")
	certFile     = flag.String("cert", "", "Path to TLS certificate")
	keyFile      = flag.String("key", "", "Path to TLS private key")
	quiet        = flag.Bool("quiet", false, "Disable request logging")

	// ODoH Globals
	odohKeyPair odoh.ObliviousDoHKeyPair
	odohConfigs odoh.ObliviousDoHConfigs
)

func main() {
	flag.Parse()

	if *certFile == "" || *keyFile == "" {
		log.Fatal("TLS certificate and key are required for DoH/DoT")
	}

	// 1. Initialize ODoH (Generate a fresh keypair on startup)
	var err error
	odohKeyPair, err = odoh.CreateDefaultKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate ODoH keypair: %v", err)
	}
	odohConfigs = odoh.CreateObliviousDoHConfigs([]odoh.ObliviousDoHConfig{odohKeyPair.Config})
	log.Printf("ODoH Initialized with public key config")

	// 2. Prepare Upstream Client
	client := &dns.Client{
		Net:            "udp",
		Timeout:        5 * time.Second,
		SingleInflight: true,
	}

	// 3. Start DoT Server
	go func() {
		log.Printf("Starting DoT server on %s", *dotAddr)
		server := &dns.Server{
			Addr:      *dotAddr,
			Net:       "tcp-tls",
			TLSConfig: loadTLSConfig(*certFile, *keyFile),
			Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
				handleDNSRequest(w, r, client, *upstreamAddr)
			}),
		}
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("DoT Server failed: %s", err)
		}
	}()

	// 4. Start DoH Server (with ODoH support)
	log.Printf("Starting DoH/ODoH server on %s", *dohAddr)

	// Standard DoH endpoint
	http.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		handleDoHRequest(w, r, client, *upstreamAddr)
	})

	// ODoH Configs endpoint
	http.HandleFunc("/odohconfigs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/oblivious-doh-configs")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Write(odohConfigs.Marshal())
	})

	srv := &http.Server{
		Addr:      *dohAddr,
		TLSConfig: loadTLSConfig(*certFile, *keyFile),
	}
	// Enable HTTP/2
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("DoH Server failed: %s", err)
	}
}

func loadTLSConfig(cert, key string) *tls.Config {
	cer, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		log.Fatalf("Failed to load certs: %s", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS12,
	}
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg, client *dns.Client, upstream string) {
	if !*quiet {
		log.Printf("DoT Request from %s for %s", w.RemoteAddr().String(), r.Question[0].Name)
	}
	resp, _, err := client.Exchange(r, upstream)
	if err != nil {
		if !*quiet {
			log.Printf("Upstream error: %s", err)
		}
		dns.HandleFailed(w, r)
		return
	}
	if err := w.WriteMsg(resp); err != nil {
		if !*quiet {
			log.Printf("Write error: %s", err)
		}
	}
}

func handleDoHRequest(w http.ResponseWriter, r *http.Request, client *dns.Client, upstream string) {
	// Check for ODoH Content Type
	if r.Header.Get("Content-Type") == "application/oblivious-dns-message" {
		handleODoHRequest(w, r, client, upstream)
		return
	}

	if !*quiet {
		log.Printf("DoH Request from %s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
	}
	if r.Method != "POST" && r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var msg *dns.Msg
	var err error

	if r.Method == "GET" {
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "Missing dns parameter", http.StatusBadRequest)
			return
		}

		decoded, err := base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(w, "Invalid base64 parameter", http.StatusBadRequest)
			return
		}

		msg = new(dns.Msg)
		if err := msg.Unpack(decoded); err != nil {
			http.Error(w, "Invalid DNS message", http.StatusBadRequest)
			return
		}
	} else {
		// POST: read body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		msg = new(dns.Msg)
		if err := msg.Unpack(body); err != nil {
			http.Error(w, "Invalid DNS message", http.StatusBadRequest)
			return
		}
	}

	resp, _, err := client.Exchange(msg, upstream)
	if err != nil {
		http.Error(w, "Upstream error", http.StatusBadGateway)
		return
	}

	packed, err := resp.Pack()
	if err != nil {
		http.Error(w, "Pack error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(packed)
}

func handleODoHRequest(w http.ResponseWriter, r *http.Request, client *dns.Client, upstream string) {
	if !*quiet {
		log.Printf("ODoH Request from %s", r.RemoteAddr)
	}

	if r.Method != "POST" {
		http.Error(w, "ODoH requires POST", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	// 1. Unmarshal ODoH Encrypted Message
	odohMsg, err := odoh.UnmarshalDNSMessage(body)
	if err != nil {
		log.Printf("ODoH Unmarshal Error: %v", err)
		http.Error(w, "Invalid ODoH message", http.StatusBadRequest)
		return
	}

	// 2. Decrypt Query
	query, responseContext, err := odohKeyPair.DecryptQuery(odohMsg)
	if err != nil {
		log.Printf("ODoH Decrypt Error: %v", err)
		http.Error(w, "Failed to decrypt query", http.StatusBadRequest)
		return
	}

	// 3. Resolve DNS (Plain DNS)
	dnsReq := new(dns.Msg)
	if err := dnsReq.Unpack(query.Message()); err != nil {
		log.Printf("ODoH Inner DNS Unpack Error: %v", err)
		http.Error(w, "Invalid inner DNS message", http.StatusBadRequest)
		return
	}

	resp, _, err := client.Exchange(dnsReq, upstream)
	if err != nil {
		// Even if upstream fails, we should try to return a SERVFAIL inside ODoH,
		// but for simplicity here we assume success or fail hard.
		// Constructing a SERVFAIL response manually:
		resp = new(dns.Msg)
		resp.SetRcode(dnsReq, dns.RcodeServerFailure)
	}

	packedResp, err := resp.Pack()
	if err != nil {
		http.Error(w, "Pack error", http.StatusInternalServerError)
		return
	}

	// 4. Encrypt Response
	obliviousResp := odoh.CreateObliviousDNSResponse(packedResp, 0)
	encryptedResp, err := responseContext.EncryptResponse(obliviousResp)
	if err != nil {
		log.Printf("ODoH Encrypt Error: %v", err)
		http.Error(w, "Failed to encrypt response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/oblivious-dns-message")
	w.Write(encryptedResp.Marshal())
}
