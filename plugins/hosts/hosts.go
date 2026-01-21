package hosts

import (
	"bufio"
	"bytes"
	"context"
	"dns-resolver/internal/plugins"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// HostsPlugin provides DNS resolution from a HOSTS file or remote URL.
type HostsPlugin struct {
	hosts          map[string]net.IP
	mu             sync.RWMutex
	filePath       string
	hostsURL       string
	updateInterval time.Duration
}

// New creates a new HostsPlugin.
func New(filePath string, hostsURL string, updateInterval time.Duration) *HostsPlugin {
	p := &HostsPlugin{
		filePath:       filePath,
		hostsURL:       hostsURL,
		updateInterval: updateInterval,
	}

	// Try to load from local file first (fast path)
	if err := p.loadFromFile(); err != nil {
		log.Printf("HostsPlugin: No local cache found or failed to load: %v", err)
	}

	// Start background updater if URL is provided
	// Do the first network update asynchronously to avoid blocking startup
	if hostsURL != "" && updateInterval > 0 {
		go func() {
			log.Println("HostsPlugin: Starting initial background update...")
			if err := p.UpdateHosts(); err != nil {
				log.Printf("Failed to update hosts from %s: %v", p.hostsURL, err)
			}
			p.updateLoop()
		}()
	}

	return p
}

// loadFromFile loads hosts exclusively from the local file without network.
func (p *HostsPlugin) loadFromFile() error {
	content, err := os.ReadFile(p.filePath)
	if err != nil {
		return err
	}
	return p.parseAndLoad(content)
}

// Name returns the name of the plugin.
func (p *HostsPlugin) Name() string {
	return "Hosts"
}

func (p *HostsPlugin) updateLoop() {
	ticker := time.NewTicker(p.updateInterval)
	defer ticker.Stop()
	for range ticker.C {
		if err := p.UpdateHosts(); err != nil {
			log.Printf("Failed to update hosts from %s: %v", p.hostsURL, err)
		}
	}
}

// UpdateHosts loads hosts from the configured source (URL or File).
// If URL is set, it downloads the file. Otherwise, it reads from disk.
func (p *HostsPlugin) UpdateHosts() error {
	var content []byte
	var err error

	if p.hostsURL != "" {
		content, err = p.downloadHosts()
		if err != nil {
			// Fallback to local file if download fails
			log.Printf("Remote hosts download failed (%v), trying local fallback...", err)
			content, err = os.ReadFile(p.filePath)
		} else {
			// Save downloaded content to local file for persistence/fallback
			_ = os.WriteFile(p.filePath, content, 0644)
		}
	} else {
		content, err = os.ReadFile(p.filePath)
	}

	if err != nil {
		if os.IsNotExist(err) && p.hoursEmpty() {
			// If file doesn't exist and map is empty, just return (maybe first run)
			return nil
		}
		return err
	}

	return p.parseAndLoad(content)
}

func (p *HostsPlugin) hoursEmpty() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.hosts) == 0
}

func (p *HostsPlugin) downloadHosts() ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{
					Timeout:   5 * time.Second,
					KeepAlive: 30 * time.Second,
				}

				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return dialer.DialContext(ctx, network, addr)
				}

				if net.ParseIP(host) != nil {
					return dialer.DialContext(ctx, network, addr)
				}

				// Force 8.8.8.8 for reliable resolution
				r := &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						d := net.Dialer{Timeout: 2 * time.Second}
						return d.DialContext(ctx, "udp", "8.8.8.8:53")
					},
				}

				ips, err := r.LookupHost(ctx, host)
				if err != nil {
					log.Printf("HostsPlugin: custom DNS lookup failed for %s: %v", host, err)
					return dialer.DialContext(ctx, network, addr)
				}

				for _, ip := range ips {
					conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
					if err == nil {
						return conn, nil
					}
				}
				return nil, fmt.Errorf("failed to dial any IP for %s", host)
			},
			ForceAttemptHTTP2: true,
		},
	}

	log.Printf("Downloading hosts from %s...", p.hostsURL)
	resp, err := client.Get(p.hostsURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func (p *HostsPlugin) parseAndLoad(data []byte) error {
	newHosts := make(map[string]net.IP)
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
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

	p.mu.Lock()
	p.hosts = newHosts
	p.mu.Unlock()

	log.Printf("HostsPlugin: loaded %d entries.", len(newHosts))
	return nil
}

// Reload re-reads the HOSTS file from disk/network.
func (p *HostsPlugin) Reload() error {
	return p.UpdateHosts()
}

// Execute checks if the query can be answered from the HOSTS file.
func (p *HostsPlugin) Execute(ctx *plugins.PluginContext, w dns.ResponseWriter, r *dns.Msg) (bool, error) {
	if len(r.Question) == 0 {
		return false, nil
	}

	question := r.Question[0]
	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		return false, nil
	}

	hostname := strings.TrimSuffix(question.Name, ".")
	hostname = strings.ToLower(hostname)

	p.mu.RLock()
	ip, ok := p.hosts[hostname]
	if !ok {
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
		return false, nil
	}

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
		"hostsURL": p.hostsURL,
		"interval": p.updateInterval.String(),
	}
}

// SetConfig updates the configuration of the plugin.
func (p *HostsPlugin) SetConfig(config map[string]any) error {
	p.mu.Lock()
	if filePath, ok := config["filePath"].(string); ok {
		p.filePath = filePath
	}
	if url, ok := config["hostsURL"].(string); ok {
		p.hostsURL = url
	}
	p.mu.Unlock()
	return p.Reload()
}

// GetConfigFields returns the configuration fields of the plugin.
func (p *HostsPlugin) GetConfigFields() []plugins.ConfigField {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return []plugins.ConfigField{
		{
			Name:        "filePath",
			Description: "Path to local hosts file",
			Type:        "text",
			Value:       p.filePath,
		},
		{
			Name:        "hostsURL",
			Description: "URL for remote hosts file",
			Type:        "text",
			Value:       p.hostsURL,
		},
	}
}

// GetFilePath is deprecated in favor of GetConfig
func (p *HostsPlugin) GetFilePath() string {
	return p.filePath
}

// ReadFileContent reads and returns the content of the hosts file (or what's currently loaded)
func (p *HostsPlugin) ReadFileContent() (string, error) {
	// For simplicity, just read the file on disk which mirrors the downloaded content
	content, err := os.ReadFile(p.filePath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}
