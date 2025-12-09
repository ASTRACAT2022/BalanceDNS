package adblock

import (
	"bufio"
	"dns-resolver/internal/filter"
	"dns-resolver/internal/plugins"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// AdBlockPlugin blocks DNS queries for domains in blocklists.
type AdBlockPlugin struct {
	mu             sync.RWMutex
	blocklists     []string
	filter         *filter.DomainFilter
	updateInterval time.Duration
}

// New creates a new AdBlockPlugin.
func New(blocklists []string, updateInterval time.Duration) *AdBlockPlugin {
	p := &AdBlockPlugin{
		blocklists:     blocklists,
		filter:         filter.NewDomainFilter(),
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

	if _, ok := p.filter.Match(domain); ok {
		// Create response that returns 0.0.0.0 for A records and :: for AAAA records
		response := new(dns.Msg)
		response.SetReply(r)
		response.Authoritative = true
		response.Rcode = dns.RcodeSuccess

		for _, q := range r.Question {
			switch q.Qtype {
			case dns.TypeA:
				rr := &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    600, // 10 minutes
					},
					A: net.IPv4(0, 0, 0, 0),
				}
				response.Answer = append(response.Answer, rr)
			case dns.TypeAAAA:
				rr := &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    600, // 10 minutes
					},
					AAAA: net.ParseIP("::"),
				}
				response.Answer = append(response.Answer, rr)
			}
		}

		// If no answer was added (for other record types), return NXDOMAIN
		if len(response.Answer) == 0 {
			response.SetRcode(r, dns.RcodeNameError) // NXDOMAIN for non-A/AAAA queries
		}

		w.WriteMsg(response)

		// Use type assertion with interface to ensure metrics method is available
		type blockedDomainsIncrementer interface {
			IncrementBlockedDomains()
		}
		if metrics, ok := ctx.Metrics.(blockedDomainsIncrementer); ok {
			metrics.IncrementBlockedDomains()
		}
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

// UpdateBlocklists fetches and parses the blocklists with enhanced format support.
func (p *AdBlockPlugin) UpdateBlocklists() {
	log.Println("Updating adblock blocklists...")
	newFilter := filter.NewDomainFilter()

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
			
			// Skip empty lines and comments
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			
			// Handle different hosts file formats and adblock formats
			parts := strings.Fields(line)
			
			// For hosts file format: IP domain [additional domains]
			if len(parts) >= 2 {
				ip := net.ParseIP(parts[0])
				if ip != nil {
					// Only block domains associated with 0.0.0.0 or ::
					if ip.IsUnspecified() {
						for i := 1; i < len(parts); i++ {
							domain := strings.TrimSpace(parts[i])
							if strings.HasPrefix(domain, "#") {
								break
							}
							if domain != "" {
								newFilter.Add(domain, net.IPv4(0, 0, 0, 0))
							}
						}
					}
				} else {
					// Handle adblock-style format
					domain := strings.TrimSpace(parts[0])
					newFilter.Add(domain, net.IPv4(0, 0, 0, 0))
				}
			} else if len(parts) == 1 {
				// For simple domain lists
				domain := strings.TrimSpace(parts[0])
				if domain != "" {
					newFilter.Add(domain, net.IPv4(0, 0, 0, 0))
				}
			}
		}
	}

	p.mu.Lock()
	p.filter = newFilter
	p.mu.Unlock()

	log.Printf("Adblock plugin updated with %d blocked domains.", newFilter.Len())
}

// GetConfig returns the current configuration of the plugin.
func (p *AdBlockPlugin) GetConfig() map[string]any {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return map[string]any{
		"blocklists":     p.blocklists,
		"updateInterval": p.updateInterval.String(),
	}
}

// SetConfig updates the configuration of the plugin.
func (p *AdBlockPlugin) SetConfig(config map[string]any) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if blocklists, ok := config["blocklists"].(string); ok {
		p.blocklists = strings.Split(blocklists, "\n")
	}

	if updateInterval, ok := config["updateInterval"].(string); ok {
		duration, err := time.ParseDuration(updateInterval)
		if err != nil {
			return err
		}
		p.updateInterval = duration
	}

	return nil
}

// GetConfigFields returns the configuration fields of the plugin.
func (p *AdBlockPlugin) GetConfigFields() []plugins.ConfigField {
	return []plugins.ConfigField{
		{
			Name:        "blocklists",
			Description: "List of blocklist URLs (one per line)",
			Type:        "textarea",
			Value:       strings.Join(p.GetBlocklists(), "\n"),
		},
		{
			Name:        "updateInterval",
			Description: "Update interval for blocklists (e.g., '1h', '30m')",
			Type:        "text",
			Value:       p.updateInterval.String(),
		},
	}
}
