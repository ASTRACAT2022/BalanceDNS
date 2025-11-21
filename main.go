package main

import (
	"log"
	"os"
	"os/signal"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"
	"dns-resolver/internal/resolver"
	"dns-resolver/internal/admin"
	"dns-resolver/internal/server"
	"dns-resolver/plugins/adblock"
	"dns-resolver/plugins/example_logger"
	"dns-resolver/plugins/hosts"
	"dns-resolver/plugins/ratelimit"
	"time"

	"golang.org/x/time/rate"
)

// Старая функция больше не используется, так как теперь используем метод из пакета metrics

func main() {
	log.SetOutput(os.Stdout)
	log.Println("Booting up ASTRACAT Relover...")

	// Load configuration
	cfg := config.NewConfig()

	// Initialize metrics
	m := metrics.NewMetrics(cfg.MetricsStoragePath)

	// Create cache and resolver
	c := cache.NewCache(cfg.CacheSize, cache.DefaultShards, cfg.LMDBPath, m)
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

	// Initialize and register the rate limit plugin
	rateLimitPlugin := ratelimit.New(rate.Limit(50), 20, 1*time.Minute)
	pm.Register(rateLimitPlugin)

	// Initialize and register the adblock plugin
	// We'll manage the blocklists via the admin panel later.
	adBlockPlugin := adblock.New([]string{}, 24*time.Hour)
	pm.Register(adBlockPlugin)

	// Initialize and register the hosts plugin
	var hostsPlugin *hosts.HostsPlugin
	if cfg.HostsEnabled {
		hostsPlugin = hosts.New(cfg.HostsPath)
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
