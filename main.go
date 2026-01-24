package main

import (
	"log"
	"os"
	"os/signal"
	"time"

	"dns-resolver/internal/admin"
	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/dnsproxy"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"
	"dns-resolver/internal/tlsutil"
	"dns-resolver/internal/unbound"
	"dns-resolver/plugins/adblock"
	"dns-resolver/plugins/hosts"
	"dns-resolver/plugins/odoh"

	"gopkg.in/yaml.v3"
)

const (
	KresdConfigPath  = "/etc/knot-resolver/kresd.conf"
	KresdPolicyPath  = "/etc/knot-resolver/policy.lua"
	KresdSocketPath  = "/run/knot-resolver/control.sock"
	KresdBackendAddr = "127.0.0.1:5353"
)

func main() {
	log.SetOutput(os.Stdout)
	log.Println("Booting up ASTRACAT Control Plane...")

	// 1. Load configuration
	cfg := config.NewConfig()
	if _, err := os.Stat("config.yaml"); err == nil {
		log.Println("Found config.yaml, loading...")
		data, err := os.ReadFile("config.yaml")
		if err != nil {
			log.Fatalf("Failed to read config.yaml: %v", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			log.Fatalf("Failed to unmarshal config.yaml: %v", err)
		}
		log.Println("Configuration loaded successfully.")
	} else {
		log.Println("config.yaml not found, using default configuration.")
	}

	// 2. Override configuration with Environment Variables
	cfg.LoadFromEnv()

	// 3. Handle Certificate Content from Env Vars
	// This supports "Upload image to git and accept certs as text" request.
	if cfg.CertContent != "" && cfg.KeyContent != "" {
		log.Println("Detected SSL certificates in environment variables. Writing to files...")
		// Use configured paths or defaults
		certPath := cfg.CertFile
		if certPath == "" {
			certPath = "cert.pem"
		}
		keyPath := cfg.KeyFile
		if keyPath == "" {
			keyPath = "key.pem"
		}

		if err := os.WriteFile(certPath, []byte(cfg.CertContent), 0644); err != nil {
			log.Printf("Error writing cert file from env: %v", err)
		} else {
			cfg.CertFile = certPath
			log.Printf("Wrote certificate to %s", certPath)
		}

		if err := os.WriteFile(keyPath, []byte(cfg.KeyContent), 0600); err != nil {
			log.Printf("Error writing key file from env: %v", err)
		} else {
			cfg.KeyFile = keyPath
			log.Printf("Wrote private key to %s", keyPath)
		}
	} else {
		log.Println("No certificate content in environment variables.")
	}

	// 4. Initialize Unbound Resolver
	log.Println("Initializing Unbound Resolver...")
	resolver, err := unbound.NewResolver()
	if err != nil {
		log.Fatalf("Failed to initialize Unbound: %v", err)
	}
	// No defer Close() here because we want it to run until exit.
	// We could handle it in signal handling, but OS cleanup is fine for now or explicit close later.

	// 5. Initialize Metrics
	m := metrics.NewMetrics(cfg.MetricsStoragePath)
	go m.StartMetricsServer(cfg.MetricsAddr)

	// 6. Initialize Plugin Manager & Plugins
	pm := plugins.NewPluginManager()

	adBlockPlugin := adblock.New(cfg.AdblockListURLs, 24*time.Hour)
	pm.Register(adBlockPlugin)

	hostsPlugin := hosts.New(cfg.HostsPath, cfg.HostsURL, cfg.HostsUpdateInterval)
	pm.Register(hostsPlugin)

	// 7. Setup TLS and Start DoH Server

	// Determine Listen Address
	proxyAddr := cfg.ListenAddr
	if proxyAddr == "" {
		proxyAddr = "0.0.0.0:53"
	}

	// If bound to 0.0.0.0, we can reach it via 127.0.0.1:53 usually.
	dnsProxyAddr := "127.0.0.1:53"
	// (Assuming standard port or parsed from proxyAddr).

	// 5. Start DoH/DoT Service Plugin (Manages Certs & Servers)
	// dohPlugin reference removed.

	// 5.0.0 Setup TLS Manager (ACME or Static)
	tlsManager := tlsutil.NewTLSManager(cfg)
	tlsManager.StartHTTPChallengeServer()

	tlsConfig, err := tlsManager.GetTLSConfig()
	if err != nil {
		log.Printf("Warning: Failed to obtain TLS config: %v. Secure endpoints may fail.", err)
	}

	// 5.0.1 Start ODoH Service Plugin
	odohConfig := odoh.Config{
		ODoHAddr:     cfg.ODoHAddr,
		CertFile:     cfg.CertFile,
		KeyFile:      cfg.KeyFile,
		TLSConfig:    tlsConfig,
		DNSProxyAddr: dnsProxyAddr,
	}
	odohPlugin := odoh.New(odohConfig, pm, m)
	odohPlugin.Start()

	// 5.1 Initialize Hybrid Policy Cache (L1: Ristretto, L2: BoltDB)
	log.Printf("Initializing Hybrid Policy Cache (L1: %d MB, L2: %s)...", cfg.CacheRAMSize, cfg.CachePath)
	hybridCache, err := cache.NewCache(cfg.CacheRAMSize, cfg.CachePath)
	if err != nil {
		log.Printf("Warning: Failed to initialize hybrid cache: %v. Proceeding without cache.", err)
	} else {
		defer hybridCache.Close()
	}

	// 8. Start Go DNS Proxy
	log.Printf("DEBUG: Initializing DNS Proxy on %s using Embedded Unbound", proxyAddr)
	// Pass 'resolver' and 'hybridCache'
	dnsProxy := dnsproxy.NewProxy(proxyAddr, resolver, pm, m, hybridCache)
	go func() {
		if err := dnsProxy.Start(); err != nil {
			log.Printf("DNS Proxy Error: %v", err)
		}
	}()

	// 9. Initialize Admin Server
	if cfg.AdminAddr != "" {
		adminServer := admin.New(cfg.AdminAddr, m, resolver, hostsPlugin, adBlockPlugin, pm)
		go adminServer.Start()
	}

	log.Println("ASTRACAT Control Plane is running (Embedded Unbound)")

	// 10. Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	log.Println("Shutting down...")
	resolver.Close()
	if err := m.SaveHistoricalData(cfg.MetricsStoragePath); err != nil {
		log.Printf("Failed to save metrics: %v", err)
	}
	os.Exit(0)
}
