package httpsrr

import (
	"dns-resolver/internal/config"
	"dns-resolver/internal/plugins"
	"encoding/base64"
	"log"

	"github.com/miekg/dns"
)

// HttpsRRPlugin is a plugin to serve HTTPS resource records.
type HttpsRRPlugin struct {
	records map[string][]byte
}

// New creates a new HttpsRRPlugin.
func New(records []config.HttpsRRRecordConfig) *HttpsRRPlugin {
	p := &HttpsRRPlugin{
		records: make(map[string][]byte),
	}
	for _, record := range records {
		ech, err := base64.StdEncoding.DecodeString(record.ECH)
		if err != nil {
			log.Printf("httpsrr: failed to decode ECH for domain %s: %v", record.Domain, err)
			continue
		}
		p.records[dns.Fqdn(record.Domain)] = ech
	}
	return p
}

// Name returns the name of the plugin.
func (p *HttpsRRPlugin) Name() string {
	return "httpsrr"
}

// Execute handles DNS queries for the plugin.
func (p *HttpsRRPlugin) Execute(ctx *plugins.PluginContext, w dns.ResponseWriter, r *dns.Msg) (bool, error) {
	if len(r.Question) == 0 || r.Question[0].Qtype != dns.TypeHTTPS {
		return false, nil
	}

	qname := r.Question[0].Name
	ech, ok := p.records[qname]
	if !ok {
		return false, nil
	}

	rr := httpsRR(qname, ech)
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Answer = []dns.RR{rr}

	w.WriteMsg(msg)
	return true, nil
}

// GetConfig returns the current configuration of the plugin.
func (p *HttpsRRPlugin) GetConfig() map[string]any {
	// Not implemented for this plugin.
	return make(map[string]any)
}

// SetConfig applies a new configuration to the plugin.
func (p *HttpsRRPlugin) SetConfig(config map[string]any) error {
	// Not implemented for this plugin.
	return nil
}

// GetConfigFields returns the configurable fields of the plugin.
func (p *HttpsRRPlugin) GetConfigFields() []plugins.ConfigField {
	// Not implemented for this plugin.
	return make([]plugins.ConfigField, 0)
}

// httpsRR creates a new HTTPS resource record.
func httpsRR(name string, ech []byte) dns.RR {
	rr := new(dns.HTTPS)
	rr.Hdr = dns.RR_Header{
		Name:   dns.Fqdn(name),
		Rrtype: dns.TypeHTTPS,
		Class:  dns.ClassINET,
		Ttl:    300,
	}

	rr.Priority = 1
	rr.Target = "."

	rr.Value = []dns.SVCBKeyValue{
		&dns.SVCBECHConfig{
			ECH: ech,
		},
	}

	return rr
}
