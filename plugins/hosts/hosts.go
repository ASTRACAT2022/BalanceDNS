package hosts

import (
	"bufio"
	"dns-resolver/internal/plugins"
	"github.com/miekg/dns"
	"log"
	"net"
	"os"
	"strings"
	"sync"
)

// HostsPlugin provides DNS resolution from a HOSTS file.
type HostsPlugin struct {
	hosts    map[string]net.IP
	mu       sync.RWMutex
	filePath string
}

// New creates a new HostsPlugin.
func New(filePath string) *HostsPlugin {
	p := &HostsPlugin{
		filePath: filePath,
	}
	if err := p.Reload(); err != nil {
		log.Printf("Failed to load hosts file on initial creation: %v", err)
	}
	return p
}

// Name returns the name of the plugin.
func (p *HostsPlugin) Name() string {
	return "Hosts"
}

// Reload re-reads the HOSTS file from disk.
func (p *HostsPlugin) Reload() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	file, err := os.Open(p.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	newHosts := make(map[string]net.IP)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		ip := net.ParseIP(parts[0])
		if ip == nil {
			continue
		}

		for i := 1; i < len(parts); i++ {
			hostname := parts[i]
			if strings.HasPrefix(hostname, "#") {
				break
			}
			newHosts[strings.ToLower(hostname)] = ip
		}
	}

	p.hosts = newHosts
	log.Printf("Loaded %d entries from hosts file: %s", len(p.hosts), p.filePath)
	return nil
}

// Execute checks if the query can be answered from the HOSTS file.
func (p *HostsPlugin) Execute(ctx *plugins.PluginContext, w dns.ResponseWriter, r *dns.Msg) (bool, error) {
	if len(r.Question) == 0 {
		return false, nil
	}

	question := r.Question[0]
	// We only handle A and AAAA queries for now.
	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		return false, nil
	}

	hostname := strings.TrimSuffix(question.Name, ".")
	hostname = strings.ToLower(hostname)
	
	p.mu.RLock()
	ip, ok := p.hosts[hostname]
	if !ok {
		// Try with trailing dot as well, in case of different DNS client behavior
		ip, ok = p.hosts[hostname+"."]
	}
	p.mu.RUnlock()

	if !ok {
		return false, nil
	}

	var rr dns.RR
	if ip.To4() != nil && question.Qtype == dns.TypeA {
		rr = &dns.A{
			Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   ip,
		}
	} else if ip.To4() == nil && question.Qtype == dns.TypeAAAA {
		rr = &dns.AAAA{
			Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600},
			AAAA: ip,
		}
	} else {
		// No match for the query type
		return false, nil
	}

	// Create a new response message instead of modifying the original
	response := new(dns.Msg)
	response.SetReply(r)
	response.Answer = append(response.Answer, rr)
	response.Rcode = dns.RcodeSuccess
	w.WriteMsg(response)
	return true, nil
}

// GetConfig returns the current configuration of the plugin.
func (p *HostsPlugin) GetConfig() map[string]any {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return map[string]any{
		"filePath": p.filePath,
	}
}

// SetConfig updates the configuration of the plugin.
func (p *HostsPlugin) SetConfig(config map[string]any) error {
	if filePath, ok := config["filePath"].(string); ok {
		p.mu.Lock()
		p.filePath = filePath
		p.mu.Unlock()
		// Reload the hosts file with the new path
		return p.Reload()
	}
	return nil
}

// GetConfigFields returns the configuration fields of the plugin.
func (p *HostsPlugin) GetConfigFields() []plugins.ConfigField {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return []plugins.ConfigField{
		{
			Name:        "filePath",
			Description: "Path to the hosts file",
			Type:        "text",
			Value:       p.filePath,
		},
	}
}

// GetFilePath returns the hosts file path
func (p *HostsPlugin) GetFilePath() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.filePath
}

// ReadFileContent reads and returns the content of the hosts file
func (p *HostsPlugin) ReadFileContent() (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	content, err := os.ReadFile(p.filePath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}
