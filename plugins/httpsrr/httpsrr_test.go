package httpsrr

import (
	"dns-resolver/internal/config"
	"dns-resolver/internal/plugins"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

type mockResponseWriter struct {
	dns.ResponseWriter
	writtenMsg *dns.Msg
}

func (m *mockResponseWriter) WriteMsg(msg *dns.Msg) error {
	m.writtenMsg = msg
	return nil
}

func TestHttpsRRPlugin(t *testing.T) {
	records := []config.HttpsRRRecordConfig{
		{Domain: "example.com", ECH: "AAEAAQAB//8="},
	}
	p := New(records)

	// Test case 1: Query for a configured domain
	q1 := new(dns.Msg)
	q1.SetQuestion("example.com.", dns.TypeHTTPS)
	w1 := &mockResponseWriter{}
	handled1, err1 := p.Execute(&plugins.PluginContext{}, w1, q1)
	assert.NoError(t, err1)
	assert.True(t, handled1)
	assert.NotNil(t, w1.writtenMsg)
	assert.Len(t, w1.writtenMsg.Answer, 1)
	httpsRR, ok := w1.writtenMsg.Answer[0].(*dns.HTTPS)
	assert.True(t, ok)
	assert.Equal(t, "example.com.", httpsRR.Hdr.Name)
	assert.Equal(t, uint16(dns.TypeHTTPS), httpsRR.Hdr.Rrtype)

	// Test case 2: Query for a non-configured domain
	q2 := new(dns.Msg)
	q2.SetQuestion("google.com.", dns.TypeHTTPS)
	w2 := &mockResponseWriter{}
	handled2, err2 := p.Execute(&plugins.PluginContext{}, w2, q2)
	assert.NoError(t, err2)
	assert.False(t, handled2)
	assert.Nil(t, w2.writtenMsg)

	// Test case 3: Query for a non-HTTPS type
	q3 := new(dns.Msg)
	q3.SetQuestion("example.com.", dns.TypeA)
	w3 := &mockResponseWriter{}
	handled3, err3 := p.Execute(&plugins.PluginContext{}, w3, q3)
	assert.NoError(t, err3)
	assert.False(t, handled3)
	assert.Nil(t, w3.writtenMsg)
}
