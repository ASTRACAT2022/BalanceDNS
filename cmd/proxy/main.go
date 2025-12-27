package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/astracat/doh-dot-proxy/internal/config"
	"github.com/astracat/doh-dot-proxy/internal/server"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()

	log.Println("Starting Astracat DoH/DoT Proxy (Go)...")

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Determine upstream target (where the actual DNS logic lives)
	// By default, we use cfg.ListenAddr, assuming it's the main resolver.
	upstreamTarget := cfg.ListenAddr
	if upstreamTarget == "" {
		upstreamTarget = "127.0.0.1:53"
	}

	upstream := server.NewUpstreamClient(upstreamTarget)
	log.Printf("Upstream resolver set to: %s", upstreamTarget)

	var wg sync.WaitGroup

	// Start DoH if enabled
	if cfg.DoH.Enabled {
		if cfg.DoH.CertFile == "" || cfg.DoH.KeyFile == "" {
			log.Printf("DoH enabled but cert/key not provided, skipping")
		} else {
			wg.Add(1)
			go func() {
				defer wg.Done()
				doh := server.NewDoHServer(cfg.DoH.ListenAddr, upstream)
				if err := doh.ListenAndServeTLS(cfg.DoH.CertFile, cfg.DoH.KeyFile); err != nil {
					log.Printf("DoH Server Error: %v", err)
				}
			}()
		}
	}

	// Start DoT if enabled
	if cfg.DoT.Enabled {
		if cfg.DoT.CertFile == "" || cfg.DoT.KeyFile == "" {
			log.Printf("DoT enabled but cert/key not provided, skipping")
		} else {
			wg.Add(1)
			go func() {
				defer wg.Done()
				dot := server.NewDoTServer(cfg.DoT.ListenAddr, upstream)
				if err := dot.ListenAndServeTLS(cfg.DoT.CertFile, cfg.DoT.KeyFile); err != nil {
					log.Printf("DoT Server Error: %v", err)
				}
			}()
		}
	}

	// Wait for signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Printf("Received signal %v, shutting down...", s)
	// In a real app we'd gracefully shutdown servers here
	// For now, we exit, and defer wg.Done() won't even happen if we os.Exit
	// But let's let the main return
}
