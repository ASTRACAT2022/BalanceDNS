package example_logger

import (
	"log"

	"dns-resolver/internal/plugins"
	"github.com/miekg/dns"
)

// LoggerPlugin is an example plugin that logs DNS queries.
type LoggerPlugin struct{}

// Name returns the name of the plugin.
func (p *LoggerPlugin) Name() string {
	return "ExampleLogger"
}

// Execute logs the details of the DNS query.
func (p *LoggerPlugin) Execute(ctx *plugins.PluginContext, w dns.ResponseWriter, r *dns.Msg) (bool, error) {
	if len(r.Question) > 0 {
		question := r.Question[0]
		log.Printf("[Plugin %s] Received query for %s, type %s", p.Name(), question.Name, dns.TypeToString[question.Qtype])
	}
	return false, nil
}

// New returns a new instance of the LoggerPlugin.
func New() *LoggerPlugin {
	return &LoggerPlugin{}
}