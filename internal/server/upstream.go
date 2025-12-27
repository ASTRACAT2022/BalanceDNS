package server

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// UpstreamClient handles forwarding DNS queries to the upstream resolver.
type UpstreamClient struct {
	addr   string
	client *dns.Client
}

// NewUpstreamClient creates a new UpstreamClient.
func NewUpstreamClient(addr string) *UpstreamClient {
	// If addr is 0.0.0.0, we should probably target 127.0.0.1 for the actual exchange
	// unless we are binding to an interface. But here we need the *target* address.
	// The config calls it 'listen_addr', which usually means what the resolver listens on.
	// We'll trust the config or let the caller fix it.
	host, port, err := net.SplitHostPort(addr)
	if err == nil && (host == "0.0.0.0" || host == "") {
		addr = net.JoinHostPort("127.0.0.1", port)
	}

	return &UpstreamClient{
		addr: addr,
		client: &dns.Client{
			Net:            "udp",
			Timeout:        2 * time.Second,
			SingleInflight: true,
		},
	}
}

// Exchange forwards the message to the upstream and returns the response.
func (u *UpstreamClient) Exchange(m *dns.Msg) (*dns.Msg, error) {
	resp, _, err := u.client.Exchange(m, u.addr)
	if err != nil {
		return nil, fmt.Errorf("upstream exchange failed: %w", err)
	}

	// Check if the response was truncated; if so, retry with TCP to get the full answer.
	// This is important for DoH/DoT clients which expect a complete response.
	if resp != nil && resp.Truncated {
		tcpClient := &dns.Client{
			Net:     "tcp",
			Timeout: 2 * time.Second,
		}
		respTCP, _, errTCP := tcpClient.Exchange(m, u.addr)
		if errTCP == nil {
			return respTCP, nil
		}
		// If TCP fails, we return the original truncated UDP response or log the error.
		// Usually better to return the partial info than nothing if TCP fails,
		// but let's just log or ignore and return the truncated one.
	}

	return resp, nil
}
