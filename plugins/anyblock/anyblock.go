package anyblock

import (
	"dns-resolver/internal/plugins"
	"strings"

	"github.com/miekg/dns"
)

// Plugin drops all QTYPE=ANY queries in preflight phase.
type Plugin struct {
	enabled bool
}

func New(enabled bool) *Plugin {
	return &Plugin{enabled: enabled}
}

func (p *Plugin) Name() string {
	return "any_block"
}

func (p *Plugin) PreflightOnly() bool {
	return true
}

func (p *Plugin) Execute(_ *plugins.PluginContext, _ dns.ResponseWriter, r *dns.Msg) (bool, error) {
	if !p.enabled || r == nil || len(r.Question) == 0 {
		return false, nil
	}
	return r.Question[0].Qtype == dns.TypeANY, nil
}

func (p *Plugin) GetConfig() map[string]any {
	return map[string]any{"enabled": p.enabled}
}

func (p *Plugin) SetConfig(config map[string]any) error {
	if v, ok := config["enabled"].(bool); ok {
		p.enabled = v
		return nil
	}
	if v, ok := config["enabled"].(string); ok {
		p.enabled = strings.EqualFold(strings.TrimSpace(v), "true")
	}
	return nil
}

func (p *Plugin) GetConfigFields() []plugins.ConfigField {
	return []plugins.ConfigField{
		{
			Name:        "enabled",
			Description: "Drop all DNS ANY queries before policy/cache handling",
			Type:        "boolean",
			Value:       p.enabled,
		},
	}
}
