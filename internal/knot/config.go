package knot

import (
	"bytes"
	"text/template"

	"dns-resolver/internal/config"
)

const kresdConfTemplate = `
-- AstracatDNS Generated Config
modules = {
    'hints > iterate', -- Load /etc/hosts and hints
    'policy',
    'stats',
    'predict',
}

-- Cache configuration
cache.size = {{ .CacheSizeBytes }}

-- Listen interfaces
net.listen('127.0.0.1', 5353, { kind = 'dns' })
net.listen('/run/knot-resolver/control.sock', 0, { kind = 'control' })

-- Load policy
dofile('/etc/knot-resolver/policy.lua')
`

const policyLuaTemplate = `
-- AstracatDNS Generated Policy

-- Blocklists
{{ range .Blocklists }}
policy.add(policy.suffix(policy.DENY, {
    {{ range .Domains }}'{{ . }}',{{ end }}
}))
{{ end }}

-- Custom Hosts/Overrides
{{ range .Overrides }}
hints['{{ .Domain }}'] = '{{ .IP }}'
{{ end }}

-- Default Policy
-- Recursion is enabled by default when no forwarding policy matches.
-- policy.add(policy.all(policy.FORWARD('1.1.1.1'))) -- Removed for recursion
`

// GenerateConfig generates the main kresd.conf content.
func GenerateConfig(cfg *config.Config) (string, error) {
	// Convert cache size MB to bytes
	cacheSize := cfg.CacheSize * 1024 * 1024
	if cacheSize == 0 {
		cacheSize = 100 * 1024 * 1024 // 100MB default
	}

	data := struct {
		CacheSizeBytes int
	}{
		CacheSizeBytes: cacheSize,
	}

	tmpl, err := template.New("kresd").Parse(kresdConfTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// PolicyData holds data for policy generation
type PolicyData struct {
	Blocklists []Blocklist
	Overrides  []Override
}

type Blocklist struct {
	Domains []string
}

type Override struct {
	Domain string
	IP     string
}

// GeneratePolicy generates the policy.lua content.
func GeneratePolicy(blockedDomains []string, overrides map[string]string) (string, error) {
	data := PolicyData{
		Blocklists: []Blocklist{
			{Domains: blockedDomains},
		},
	}
	for d, ip := range overrides {
		data.Overrides = append(data.Overrides, Override{Domain: d, IP: ip})
	}

	tmpl, err := template.New("policy").Parse(policyLuaTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
