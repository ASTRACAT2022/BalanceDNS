package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dns-resolver/internal/admin"
	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/dnsproxy"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"
	"dns-resolver/internal/recursor"
	"dns-resolver/internal/tlsutil"
	"dns-resolver/plugins/adblock"
	"dns-resolver/plugins/dnsdistcompat"
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
	cfg.Normalize()

	// 3. Handle Certificate Content from Env Vars
	wroteCerts, err := cfg.WriteCertFilesFromEnv()
	if err != nil {
		log.Printf("Failed to write certificates from env: %v", err)
	} else if wroteCerts {
		log.Printf("Wrote SSL certificates to %s and %s", cfg.CertFile, cfg.KeyFile)
	} else {
		log.Println("No certificate content in environment variables.")
	}

	// 4. Initialize built-in recursive resolver
	log.Println("Initializing built-in recursive resolver...")
	resolver, err := recursor.NewResolverWithOptions(recursor.Options{
		WorkerCount:      cfg.ResolverWorkers,
		QueryTimeout:     cfg.UpstreamTimeout,
		ResolveTimeout:   cfg.RequestTimeout,
		RootServers:      cfg.RecursorRootServers,
		CacheEntries:     cfg.RecursorCacheEntries,
		CacheMinTTL:      cfg.RecursorCacheMinTTL,
		CacheMaxTTL:      cfg.RecursorCacheMaxTTL,
		ValidateDNSSEC:   cfg.DNSSECValidate,
		DNSSECFailClosed: cfg.DNSSECFailClosed,
		DNSSECTrustDS:    cfg.DNSSECTrustAnchors,
	})
	if err != nil {
		log.Fatalf("Failed to initialize recursive resolver: %v", err)
	}
	log.Printf(
		"Built-in recursion configured: workers=%d query-timeout=%s resolve-timeout=%s cache-entries=%d cache-min-ttl=%s cache-max-ttl=%s dnssec-validate=%v dnssec-fail-closed=%v",
		resolver.WorkerCount(),
		cfg.UpstreamTimeout,
		cfg.RequestTimeout,
		cfg.RecursorCacheEntries,
		cfg.RecursorCacheMinTTL,
		cfg.RecursorCacheMaxTTL,
		cfg.DNSSECValidate,
		cfg.DNSSECFailClosed,
	)
	// No defer Close() here because we want it to run until exit.
	// We could handle it in signal handling, but OS cleanup is fine for now or explicit close later.

	// 5. Initialize Metrics
	m := metrics.NewMetrics(cfg.MetricsStoragePath)
	if cfg.PrometheusEnabled {
		go m.StartMetricsServer(cfg.MetricsAddr)
	} else {
		log.Println("Prometheus metrics server disabled by config.")
	}

	// 6. Initialize Plugin Manager & Plugins
	pm := plugins.NewPluginManager()

	if cfg.DNSDistCompatEnabled {
		pm.Register(dnsdistcompat.New(dnsdistcompat.Config{
			LogAll:             cfg.DNSDistCompatLogAll,
			BannedIPsPath:      cfg.DNSDistCompatBannedIPsPath,
			SNIProxyIPsPath:    cfg.DNSDistCompatSNIProxyIPsPath,
			DomainsWithSubPath: cfg.DNSDistCompatDomainsWithSubPath,
			CustomPath:         cfg.DNSDistCompatCustomPath,
			DomainsPath:        cfg.DNSDistCompatDomainsPath,
			HostsPath:          cfg.DNSDistCompatHostsPath,
			GarbagePath:        cfg.DNSDistCompatGarbagePath,
			DropSuffixes:       cfg.DNSDistCompatDropSuffixes,
			LateDropSuffixes:   cfg.DNSDistCompatLateDropSuffixes,
		}))
	}

	var adBlockPlugin *adblock.AdBlockPlugin
	if cfg.AdblockEnabled {
		adBlockPlugin = adblock.New(cfg.AdblockListURLs, 24*time.Hour)
		pm.Register(adBlockPlugin)
	} else {
		log.Println("Adblock plugin disabled by config.")
	}

	var hostsPlugin *hosts.HostsPlugin
	if cfg.HostsEnabled {
		hostsPlugin = hosts.New(cfg.HostsPath, cfg.HostsURL, cfg.HostsUpdateInterval)
		pm.Register(hostsPlugin)
	} else {
		log.Println("Hosts plugin disabled by config.")
	}

	// 7. Setup TLS and Start DoH Server

	// Determine Listen Address
	proxyAddr := cfg.ListenAddr
	if proxyAddr == "" {
		proxyAddr = "0.0.0.0:53"
	}

	dnsProxyAddr := proxyAddr
	if host, port, err := net.SplitHostPort(proxyAddr); err == nil {
		switch host {
		case "", "0.0.0.0", "::":
			dnsProxyAddr = net.JoinHostPort("127.0.0.1", port)
		default:
			dnsProxyAddr = net.JoinHostPort(host, port)
		}
	}

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
		hybridCache.SetMetricsHooks(m)
		defer hybridCache.Close()
	}

	// 8. Start Go DNS Proxy
	log.Printf("DEBUG: Initializing DNS Proxy on %s using embedded Go recursor", proxyAddr)
	proxyOptions := buildProxyOptions(cfg)
	dnsProxy := dnsproxy.NewProxyWithOptions(proxyAddr, resolver, pm, m, hybridCache, proxyOptions)
	go func() {
		if err := dnsProxy.Start(); err != nil {
			log.Printf("DNS Proxy Error: %v", err)
		}
	}()

	// 9. Initialize Admin Server
	if cfg.AdminAddr != "" {
		if cfg.AdminUsername == "" || cfg.AdminPassword == "" {
			log.Printf("Admin server disabled: set both admin_username and admin_password to enable %s", cfg.AdminAddr)
		} else {
			adminServer := admin.New(cfg, m, resolver, hostsPlugin, adBlockPlugin, pm)
			go adminServer.Start()
		}
	}

	log.Println("ASTRACAT Control Plane is running (embedded Go recursor)")

	// 10. Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("Shutting down...")
	resolver.Close()
	if err := m.SaveHistoricalData(cfg.MetricsStoragePath); err != nil {
		log.Printf("Failed to save metrics: %v", err)
	}
}

func buildProxyOptions(cfg *config.Config) dnsproxy.ProxyOptions {
	opts := dnsproxy.DefaultProxyOptions()
	opts.EnableAttackProtection = cfg.AttackProtectionEnabled
	opts.MaxGlobalInflight = cfg.MaxGlobalInflight
	opts.MaxQPSPerIP = cfg.MaxQPSPerIP
	opts.RateLimitBurstPerIP = cfg.RateLimitBurstPerIP
	opts.MaxConcurrentPerIP = cfg.MaxConcurrentPerIP
	opts.MaxQuestionsPerRequest = cfg.MaxQuestionsPerRequest
	opts.MaxQNameLength = cfg.MaxQNameLength
	opts.DropANYQueries = cfg.DropANYQueries
	if cfg.DNSDistCompatEnabled {
		// dnsdist compat plugin implements silent DropAction() for ANY.
		opts.DropANYQueries = false
	}

	opts.Policy.Enabled = cfg.PolicyEngineEnabled
	opts.Policy.BlockedDomains = append([]string(nil), cfg.PolicyBlockedDomains...)
	opts.Policy.RewriteRules = make([]dnsproxy.ProxyRewriteRule, 0, len(cfg.PolicyRewriteRules))
	for _, rw := range cfg.PolicyRewriteRules {
		opts.Policy.RewriteRules = append(opts.Policy.RewriteRules, dnsproxy.ProxyRewriteRule{
			Domain: rw.Domain,
			Type:   rw.Type,
			Value:  rw.Value,
			TTL:    rw.TTL,
		})
	}

	opts.Policy.LoadBalancers = make([]dnsproxy.ProxyLoadBalancerRule, 0, len(cfg.PolicyLoadBalancers))
	for _, lb := range cfg.PolicyLoadBalancers {
		targets := make([]dnsproxy.ProxyLoadBalancerTarget, 0, len(lb.Targets))
		for _, target := range lb.Targets {
			targets = append(targets, dnsproxy.ProxyLoadBalancerTarget{
				Value:  target.Value,
				Weight: target.Weight,
			})
		}
		opts.Policy.LoadBalancers = append(opts.Policy.LoadBalancers, dnsproxy.ProxyLoadBalancerRule{
			Domain:   lb.Domain,
			Type:     lb.Type,
			Strategy: lb.Strategy,
			TTL:      lb.TTL,
			Targets:  targets,
		})
	}

	return opts
}
