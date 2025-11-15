package main

import (
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"
	"dns-resolver/internal/resolver"
	"dns-resolver/internal/server"
	"dns-resolver/plugins/example_logger"
)

// Старая функция больше не используется, так как теперь используем метод из пакета metrics

func main() {
	// Load configuration
	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Set up logging
	logFile, err := os.OpenFile("server.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()

	switch strings.ToLower(cfg.LogLevel) {
	case "debug", "info", "warn", "error":
		log.SetOutput(logFile)
	case "none":
		log.SetOutput(ioutil.Discard)
	default:
		log.SetOutput(logFile)
	}

	log.Println("Booting up ASTRACAT Relover...")

	// Initialize metrics
	m := metrics.NewMetrics()

	// Create cache and resolver
	c := cache.NewCache(cfg.CacheSize, cache.DefaultShards, cfg.LMDBPath, m)
	defer c.Close()

	// Create resolver based on configuration
	res, err := resolver.NewResolver(resolver.ResolverType(cfg.ResolverType), cfg, c, m)
	if err != nil {
		log.Fatalf("Failed to create resolver: %v", err)
	}
	defer res.Close()

	// Start a goroutine to periodically update cache stats
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			probation, protected := c.GetCacheSize()
			m.UpdateCacheStats(probation, protected)
		}
	}()

	// Start the metrics server
	go m.StartMetricsServer(cfg.MetricsAddr)

	// Initialize plugin manager
	pm := plugins.NewPluginManager()

	// Register the example logger plugin
	loggerPlugin := example_logger.New()
	pm.Register(loggerPlugin)

	// Create and start the server
	srv := server.NewServer(cfg, m, res, pm)

	srv.ListenAndServe()
}
