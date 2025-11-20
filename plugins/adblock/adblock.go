package adblock

import (
	"bufio"
	"dns-resolver/internal/plugins"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// AdBlockPlugin blocks DNS queries for domains in blocklists.
type AdBlockPlugin struct {
	mu         sync.RWMutex
	blocklists []string
	blocked    map[string]struct{}
	updateInterval time.Duration
}

// New creates a new AdBlockPlugin.
func New(blocklists []string, updateInterval time.Duration) *AdBlockPlugin {
	p := &AdBlockPlugin{
		blocklists: blocklists,
		blocked:    make(map[string]struct{}),
		updateInterval: updateInterval,
	}
	go p.updateBlocklistsLoop()
	return p
}

// Name returns the name of the plugin.
func (p *AdBlockPlugin) Name() string {
	return "adblock"
}

// Execute checks if the query domain is in the blocklist.
func (p *AdBlockPlugin) Execute(ctx *plugins.PluginContext, w dns.ResponseWriter, r *dns.Msg) (bool, error) {
	if len(r.Question) == 0 {
		return false, nil
	}
	question := r.Question[0]
	domain := strings.TrimSuffix(question.Name, ".")

	p.mu.RLock()
	_, isBlocked := p.blocked[domain]
	p.mu.RUnlock()

	if isBlocked {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
		w.WriteMsg(m)
		return true, nil // Stop processing
	}

	return false, nil // Continue processing
}

func (p *AdBlockPlugin) updateBlocklistsLoop() {
	ticker := time.NewTicker(p.updateInterval)
	p.UpdateBlocklists() // Initial update
	for range ticker.C {
		p.UpdateBlocklists()
	}
}

// GetBlocklists returns the current list of blocklist URLs.
func (p *AdBlockPlugin) GetBlocklists() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	// Return a copy to avoid race conditions on the slice
	lists := make([]string, len(p.blocklists))
	copy(lists, p.blocklists)
	return lists
}

// AddBlocklist adds a new URL to the blocklists.
func (p *AdBlockPlugin) AddBlocklist(url string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, existingURL := range p.blocklists {
		if existingURL == url {
			return // Already exists
		}
	}
	p.blocklists = append(p.blocklists, url)
}

// RemoveBlocklist removes a URL from the blocklists.
func (p *AdBlockPlugin) RemoveBlocklist(url string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var newBlocklists []string
	for _, existingURL := range p.blocklists {
		if existingURL != url {
			newBlocklists = append(newBlocklists, existingURL)
		}
	}
	p.blocklists = newBlocklists
}


// UpdateBlocklists fetches and parses the blocklists.
func (p *AdBlockPlugin) UpdateBlocklists() {
	log.Println("Updating adblock blocklists...")
	newBlocked := make(map[string]struct{})

	for _, url := range p.GetBlocklists() { // Use the thread-safe getter
		resp, err := http.Get(url)
		if err != nil {
			log.Printf("Failed to download blocklist %s: %v", url, err)
			continue
		}
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) > 0 {
				domain := parts[len(parts)-1]
				newBlocked[domain] = struct{}{}
			}
		}
	}

	p.mu.Lock()
	p.blocked = newBlocked
	p.mu.Unlock()
	log.Printf("Adblock plugin updated with %d domains.", len(p.blocked))
}
