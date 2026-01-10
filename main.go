package main

import (
	"log"
	"os"
	"os/signal"
	"time"

	"dns-resolver/internal/admin"
	"dns-resolver/internal/config"
	"dns-resolver/internal/dnsproxy"
	"dns-resolver/internal/doh"
	"dns-resolver/internal/dot"
	"dns-resolver/internal/knot"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"
	"dns-resolver/internal/tlsutil"
	"dns-resolver/plugins/adblock"
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

	// 2. Generate Knot Resolver Config
	log.Println("Generating Knot Resolver configuration...")
	kresdConf, err := knot.GenerateConfig(cfg)
	if err != nil {
		log.Printf("Error generating kresd.conf: %v", err)
	} else {
		if os.Geteuid() == 0 {
			if err := os.WriteFile(KresdConfigPath, []byte(kresdConf), 0644); err != nil {
				log.Printf("Failed to write %s: %v", KresdConfigPath, err)
			}
		} else {
			log.Println("Non-root user: Skipping write to /etc/kresd/, printing config instead:")
			log.Println(kresdConf)
		}
	}

	// 3. Generate Policy (Basic)
	log.Println("Generating Policy...")
	// We generate a basic policy. Real policy management might be done via plugins later via Admin.
	policyContent, err := knot.GeneratePolicy([]string{"example-malware.com"}, nil)
	if err != nil {
		log.Printf("Error generating policy.lua: %v", err)
	} else {
		if os.Geteuid() == 0 {
			if err := os.WriteFile(KresdPolicyPath, []byte(policyContent), 0644); err != nil {
				log.Printf("Failed to write %s: %v", KresdPolicyPath, err)
			}
		}
	}

	// 4. Initialize Metrics (Needed early if plugins use it?)
	m := metrics.NewMetrics(cfg.MetricsStoragePath)
	go m.StartMetricsServer(cfg.MetricsAddr)

	// 5. Initialize Plugin Manager & Plugins
	pm := plugins.NewPluginManager()

	adBlockPlugin := adblock.New(cfg.AdblockListURLs, 24*time.Hour)
	pm.Register(adBlockPlugin)

	hostsPlugin := hosts.New(cfg.HostsPath, cfg.HostsURL, cfg.HostsUpdateInterval)
	pm.Register(hostsPlugin)

	// 6. Setup TLS and Start DoH Server
	if cfg.DoHAddr != "" {
		certFile := cfg.CertFile
		keyFile := cfg.KeyFile

		if certFile == "" {
			certFile = "cert.pem"
		}
		if keyFile == "" {
			keyFile = "key.pem"
		}

		log.Printf("Ensuring TLS certificates for DoH (%s, %s)...", certFile, keyFile)
		if err := tlsutil.EnsureCertificate(certFile, keyFile, "astracat.dns"); err != nil {
			log.Printf("Failed to generate/ensure certificates: %v. DoH might fail.", err)
		}

		// Pass 'pm' and 'm' to DoH
		dohServer := doh.NewServer(cfg.DoHAddr, certFile, keyFile, KresdBackendAddr, pm, m)
		go func() {
			if err := dohServer.Start(); err != nil {
				log.Printf("DoH Server Error: %v", err)
			}
		}()

		// Start DoT Server (if enabled)
		// User requested: Disabled by default, enabled via config changes.
		// We use the same Cert/Key as DoH.
		if cfg.DoTAddr != "" {
			dotServer := dot.NewServer(cfg.DoTAddr, certFile, keyFile, KresdBackendAddr, pm, m)
			go func() {
				if err := dotServer.Start(); err != nil {
					log.Printf("DoT Server Error: %v", err)
				}
			}()
		}
	}

	// 7. Start Go DNS Proxy (Port 53 -> Kresd 5353)
	proxyAddr := cfg.ListenAddr
	if proxyAddr == "" {
		proxyAddr = "0.0.0.0:53"
	}
	log.Printf("DEBUG: Initializing DNS Proxy on %s target %s", proxyAddr, KresdBackendAddr)
	// Pass 'pm' and 'm' to DNS Proxy
	dnsProxy := dnsproxy.NewProxy(proxyAddr, KresdBackendAddr, pm, m)
	go func() {
		if err := dnsProxy.Start(); err != nil {
			log.Printf("DNS Proxy Error: %v", err)
		}
	}()

	// 8. Initialize Knot Adapter (for Admin)
	knotAdapter := knot.NewAdapter(KresdSocketPath, 5*time.Second)

	// 9. Start the admin server
	if cfg.AdminAddr != "" {
		adminServer := admin.New(cfg.AdminAddr, m, knotAdapter, hostsPlugin, adBlockPlugin, pm)
		go adminServer.Start()
	}

	log.Println("ASTRACAT Control Plane is running (Managing Knot Resolver + DoH Proxy + DNS Proxy)")

	// 10. Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	log.Println("Shutting down...")
	if err := m.SaveHistoricalData(cfg.MetricsStoragePath); err != nil {
		log.Printf("Failed to save metrics: %v", err)
	}
	os.Exit(0)
}
