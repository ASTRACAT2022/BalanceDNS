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
	"dns-resolver/internal/unbound"
	"dns-resolver/plugins/adblock"
	"dns-resolver/plugins/doh"
	"dns-resolver/plugins/hosts"

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

	// 2. Initialize Unbound Resolver
	log.Println("Initializing Unbound Resolver...")
	resolver, err := unbound.NewResolver()
	if err != nil {
		log.Fatalf("Failed to initialize Unbound: %v", err)
	}
	// No defer Close() here because we want it to run until exit.
	// We could handle it in signal handling, but OS cleanup is fine for now or explicit close later.

	// 3. Initialize Metrics
	m := metrics.NewMetrics(cfg.MetricsStoragePath)
	go m.StartMetricsServer(cfg.MetricsAddr)

	// 4. Initialize Plugin Manager & Plugins
	pm := plugins.NewPluginManager()

	adBlockPlugin := adblock.New(cfg.AdblockListURLs, 24*time.Hour)
	pm.Register(adBlockPlugin)

	hostsPlugin := hosts.New(cfg.HostsPath, cfg.HostsURL, cfg.HostsUpdateInterval)
	pm.Register(hostsPlugin)

	// 5. Setup TLS and Start DoH Server

	// Determine Listen Address
	proxyAddr := cfg.ListenAddr
	if proxyAddr == "" {
		proxyAddr = "0.0.0.0:53"
	}

	// If bound to 0.0.0.0, we can reach it via 127.0.0.1:53 usually.
	dnsProxyAddr := "127.0.0.1:53"
	// (Assuming standard port or parsed from proxyAddr).

	// 5. Start DoH/DoT Service Plugin (Manages Certs & Servers)
	dohConfig := doh.Config{
		DoHAddr:      cfg.DoHAddr,
		DoTAddr:      cfg.DoTAddr,
		CertFile:     cfg.CertFile,
		KeyFile:      cfg.KeyFile,
		DNSProxyAddr: dnsProxyAddr,
	}
	dohPlugin := doh.New(dohConfig, pm, m)
	dohPlugin.Start()

	// 5.1 Initialize Hybrid Policy Cache (L1: Ristretto, L2: BoltDB)
	log.Printf("Initializing Hybrid Policy Cache (L1: %d MB, L2: %s)...", cfg.CacheRAMSize, cfg.CachePath)
	hybridCache, err := cache.NewCache(cfg.CacheRAMSize, cfg.CachePath)
	if err != nil {
		log.Printf("Warning: Failed to initialize hybrid cache: %v. Proceeding without cache.", err)
	} else {
		defer hybridCache.Close()
	}

	// 6. Start Go DNS Proxy
	log.Printf("DEBUG: Initializing DNS Proxy on %s using Embedded Unbound", proxyAddr)
	// Pass 'resolver' and 'hybridCache'
	dnsProxy := dnsproxy.NewProxy(proxyAddr, resolver, pm, m, hybridCache)
	go func() {
		if err := dnsProxy.Start(); err != nil {
			log.Printf("DNS Proxy Error: %v", err)
		}
	}()

	// 7. Initialize Admin Server
	if cfg.AdminAddr != "" {
		adminServer := admin.New(cfg.AdminAddr, m, resolver, hostsPlugin, adBlockPlugin, pm)
		go adminServer.Start()
	}

	log.Println("ASTRACAT Control Plane is running (Embedded Unbound)")

	// 8. Graceful shutdown
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
