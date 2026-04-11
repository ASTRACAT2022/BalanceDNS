package hosts

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/miekg/dns"
)

type Table struct {
	records map[string][]net.IP
	ttl     uint32
}

type Answer struct {
	IPs []net.IP
	TTL uint32
}

func Load(path string, ttl uint32) (*Table, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open hosts file %q: %w", path, err)
	}
	defer f.Close()

	records := make(map[string][]net.IP)
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		if idx := strings.Index(raw, "#"); idx >= 0 {
			raw = strings.TrimSpace(raw[:idx])
		}
		if raw == "" {
			continue
		}

		fields := strings.Fields(raw)
		if len(fields) < 2 {
			continue
		}

		ip := net.ParseIP(fields[0])
		if ip == nil {
			return nil, fmt.Errorf("invalid ip at %s:%d", path, lineNo)
		}

		for _, name := range fields[1:] {
			key := strings.ToLower(dns.Fqdn(strings.TrimSpace(name)))
			if key == "." {
				continue
			}
			records[key] = append(records[key], ip)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan hosts file %q: %w", path, err)
	}

	return &Table{records: records, ttl: ttl}, nil
}

func (t *Table) Lookup(name string, qtype uint16) (Answer, bool) {
	if t == nil {
		return Answer{}, false
	}
	key := strings.ToLower(dns.Fqdn(strings.TrimSpace(name)))
	ips, ok := t.records[key]
	if !ok {
		return Answer{}, false
	}

	out := make([]net.IP, 0, len(ips))
	switch qtype {
	case dns.TypeA:
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				out = append(out, v4)
			}
		}
	case dns.TypeAAAA:
		for _, ip := range ips {
			if ip.To16() != nil && ip.To4() == nil {
				out = append(out, ip)
			}
		}
	case dns.TypeANY:
		out = append(out, ips...)
	default:
		return Answer{}, false
	}

	return Answer{IPs: out, TTL: t.ttl}, true
}
