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
func (p *HostsPlugin) Execute(ctx *plugins.PluginContext, msg *dns.Msg) (bool, error) {
	if len(msg.Question) == 0 {
		return false, nil
	}

	question := msg.Question[0]
	// We only handle A and AAAA queries for now.
	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		return false, nil
	}

	hostname := strings.TrimSuffix(question.Name, ".")
	p.mu.RLock()
	ip, ok := p.hosts[strings.ToLower(hostname)]
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

	msg.Answer = append(msg.Answer, rr)
	msg.Rcode = dns.RcodeSuccess
	return true, nil
}
