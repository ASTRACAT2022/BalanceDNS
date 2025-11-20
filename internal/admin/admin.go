package admin

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"dns-resolver/internal/metrics"
	"dns-resolver/plugins/hosts"
)

// Server provides an admin web interface.
type Server struct {
	addr    string
	metrics *metrics.Metrics
	hosts   *hosts.HostsPlugin
}

// New creates a new admin server.
func New(addr string, m *metrics.Metrics, h *hosts.HostsPlugin) *Server {
	return &Server{
		addr:    addr,
		metrics: m,
		hosts:   h,
	}
}

// Start runs the admin server.
func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleStats)
	mux.HandleFunc("/api/hosts/reload", s.handleHostsReload)

	log.Printf("Starting admin server on %s", s.addr)
	if err := http.ListenAndServe(s.addr, mux); err != nil {
		log.Fatalf("Failed to start admin server: %v", err)
	}
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	// Simple HTML page with auto-refresh to display stats.
	// In a real application, you would use a template engine.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
		<!DOCTYPE html>
		<html>
		<head>
			<title>ASTRACAT DNS Resolver Stats</title>
			<meta http-equiv="refresh" content="5">
		</head>
		<body>
			<h1>ASTRACAT DNS Resolver Stats</h1>
			<pre>
Queries: %d
			</pre>
		</body>
		</html>
	`, s.metrics.GetQueries()) // Note: We will need to implement GetQueries in metrics.
}

func (s *Server) handleHostsReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := s.hosts.Reload(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to reload hosts file: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Hosts file reloaded successfully"})
}
