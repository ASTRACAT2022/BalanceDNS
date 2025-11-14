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
func (p *LoggerPlugin) Execute(ctx *plugins.PluginContext, msg *dns.Msg) error {
	if len(msg.Question) > 0 {
		question := msg.Question[0]
		log.Printf("[Plugin %s] Received query for %s, type %s", p.Name(), question.Name, dns.TypeToString[question.Qtype])
	}
	return nil
}

// New returns a new instance of the LoggerPlugin.
func New() *LoggerPlugin {
	return &LoggerPlugin{}
}