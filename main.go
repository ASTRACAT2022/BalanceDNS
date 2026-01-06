package main

import (
	"log"
	"os"
	"os/signal"

	"dns-resolver/internal/admin"
	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"
	"dns-resolver/internal/resolver"
	"dns-resolver/internal/server"
	"dns-resolver/plugins/adblock"
	"dns-resolver/plugins/example_logger"
	"dns-resolver/plugins/hosts"
	"time"

	"gopkg.in/yaml.v3"
)

// Старая функция больше не используется, так как теперь используем метод из пакета metrics

func main() {
	log.SetOutput(os.Stdout)
	log.Println("Booting up ASTRACAT Relover...")

	// Load configuration
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

	// Initialize metrics
	m := metrics.NewMetrics(cfg.MetricsStoragePath)

	// Create cache and resolver
	// BoltDB expects a file path, e.g., "cache/dns.db"
	// Ensure config.yaml provides a path that works (e.g., ends in .db or is a file)
	c := cache.NewCache(cfg.CacheSize, cache.DefaultShards, cfg.CachePath, m)
	defer c.Close()

	// Create resolver based on configuration
	res, err := resolver.NewResolver(resolver.ResolverType(cfg.ResolverType), cfg, c, m)
	if err != nil {
		log.Fatalf("Failed to create resolver: %v", err)
	}
	defer res.Close()

	// Start the metrics server
	go m.StartMetricsServer(cfg.MetricsAddr)

	// Initialize plugin manager
	pm := plugins.NewPluginManager()

	// Register the example logger plugin
	loggerPlugin := example_logger.New()
	pm.Register(loggerPlugin)

	// Initialize and register the adblock plugin
	// Use blocklists from configuration
	adBlockPlugin := adblock.New(cfg.AdblockListURLs, 24*time.Hour)
	pm.Register(adBlockPlugin)

	// Initialize and register the hosts plugin
	var hostsPlugin *hosts.HostsPlugin
	if cfg.HostsEnabled {
		hostsPlugin = hosts.New(cfg.HostsPath, cfg.HostsURL, cfg.HostsUpdateInterval)
		pm.Register(hostsPlugin)
	} else {
		// Initialize hosts plugin with default path even if not explicitly enabled
		hostsPlugin = hosts.New(cfg.HostsPath, cfg.HostsURL, cfg.HostsUpdateInterval)
		pm.Register(hostsPlugin)
	}

	// Start the admin server
	if cfg.AdminAddr != "" {
		adminServer := admin.New(cfg.AdminAddr, m, hostsPlugin, adBlockPlugin, pm)
		go adminServer.Start()
	}

	// Create and start the server
	srv := server.NewServer(cfg, m, res, pm)

	// Graceful shutdown
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
		log.Println("Shutting down...")
		if err := m.SaveHistoricalData(cfg.MetricsStoragePath); err != nil {
			log.Printf("Failed to save metrics: %v", err)
		}
		os.Exit(0)
	}()

	srv.ListenAndServe()
}
