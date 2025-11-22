package main

import (
	"log"
	"os"
	"os/signal"
	"time"

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

	"gopkg.in/yaml.v3"
)

func main() {
	log.SetOutput(os.Stdout)
	log.Println("Booting up ASTRACAT Resolver...")

	// Load configuration
	cfg := config.NewConfig()
	if _, err := os.Stat("config.yaml"); err == nil {
		data, err := os.ReadFile("config.yaml")
		if err != nil {
			log.Fatalf("Failed to read config.yaml: %v", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			log.Fatalf("Failed to unmarshal config.yaml: %v", err)
		}
	}

	// Initialize metrics
	m := metrics.NewMetrics(cfg.MetricsStoragePath)

	// Create cache and resolver
	c := cache.NewCache(cfg.Cache.Size, cache.DefaultShards, cfg.Cache.LMDBPath, m)
	defer c.Close()

	// Create resolver based on configuration
	res, err := resolver.NewResolver(resolver.ResolverType(cfg.Resolver.Type), cfg, c, m)
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
	adBlockPlugin := adblock.New(cfg.AdBlock.BlocklistURLs, 24*time.Hour)
	pm.Register(adBlockPlugin)

	// Initialize and register the hosts plugin
	hostsPlugin := hosts.New(cfg.Hosts.Path)
	pm.Register(hostsPlugin)

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
