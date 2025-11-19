package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"sync"
	"time"
)

// dnsClientFactory defines a factory function for creating a DNS client.
type dnsClientFactory func(string) dnsClient

type dnsClient interface {
	ExchangeContext(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error)
}

type nameserver struct {
	hostname string
	addr     string

	dnsClientFactory dnsClientFactory

	metricsLock         sync.Mutex
	numberOfRequests    uint32
	totalResponseTime   time.Duration
	averageResponseTime time.Duration
	numberOfTcpRequests uint32
	protocolRatio       float32
}

func (*nameserver) defaultDnsClientFactory(protocol string) dnsClient {
	timeout := DefaultTimeoutUDP
	if protocol == "tcp" {
		timeout = DefaultTimeoutTCP
	}
	return &dns.Client{Net: protocol, Timeout: timeout}
}

func (nameserver *nameserver) exchange(ctx context.Context, m *dns.Msg) *Response {
	factory := nameserver.defaultDnsClientFactory
	if nameserver.dnsClientFactory != nil {
		factory = nameserver.dnsClientFactory
	}

	zoneName := "unknown"
	if z, ok := ctx.Value(ctxZoneName).(string); ok {
		zoneName = z
	}

	if m == nil {
		return newResponseError(fmt.Errorf("%w in zone [%s]", ErrNilMessageSentToExchange, zoneName))
	}

	// Formats correctly for both ipv4 and ipv6.
	addr := net.JoinHostPort(nameserver.addr, "53")

	r := Response{}
	for _, protocol := range []string{"udp", "tcp"} {
		client := factory(protocol)

		r.Msg, r.Duration, r.Err = client.ExchangeContext(ctx, m, addr)

		//---

		shortId := "unknown"
		iteration := uint32(0)
		if trace, _ := ctx.Value(CtxTrace).(*Trace); trace != nil {
			shortId = trace.ShortID()
			iteration = trace.Iteration()
		}
		Query(fmt.Sprintf(
			"%s-%d: %s taken querying [%s] %s in zone [%s] on %s://%s (%s)",
			shortId,
			iteration,
			r.Duration,
			m.Question[0].Name,
			TypeToString(m.Question[0].Qtype),
			zoneName,
			protocol,
			nameserver.hostname,
			addr,
		))

		go nameserver.updateMetrics(protocol, r.Duration)

		// If we got an error back, we'll continue to maybe try again.
		if r.HasError() {
			continue
		}

		// Then we can return straight away.
		if !r.Msg.Truncated {
			return &r
		}
	}

	// r here may have an error. It might be truncated. But it's the best we've got.
	return &r
}

func (nameserver *nameserver) updateMetrics(protocol string, duration time.Duration) {
	nameserver.metricsLock.Lock()

	nameserver.numberOfRequests++

	nameserver.totalResponseTime = nameserver.totalResponseTime + duration
	nameserver.averageResponseTime = nameserver.totalResponseTime / time.Duration(nameserver.numberOfRequests)

	if protocol == "tcp" {
		nameserver.numberOfTcpRequests++
	}

	nameserver.protocolRatio = float32(nameserver.numberOfTcpRequests) / float32(nameserver.numberOfRequests)

	nameserver.metricsLock.Unlock()
}
