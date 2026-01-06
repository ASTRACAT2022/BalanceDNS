package interfaces

import (
    "context"
    "time"

    "github.com/miekg/dns"
)

// DNSSECStatus represents the outcome of DNSSEC validation performed by a backend.
type DNSSECStatus string

const (
    DNSSECUnknown  DNSSECStatus = "unknown"
    DNSSECSecure   DNSSECStatus = "secure"
    DNSSECBogus    DNSSECStatus = "bogus"
    DNSSECInsecure DNSSECStatus = "insecure"
)

// Backend is an abstraction over a recursive resolver implementation.
// It is responsible for performing the actual resolution and DNSSEC validation
// and returning a fully-formed response message.
//
// Exchange should construct and return a complete dns.Msg reply for the given request.
// It should also return a DNSSECStatus describing the validation result.
// Implementations should respect context cancellation when possible.
type Backend interface {
    Exchange(ctx context.Context, req *dns.Msg) (resp *dns.Msg, dnssec DNSSECStatus, err error)
}

// BackendLatencyObserver is an optional interface that backends can implement
// to report their internal measured latency. When implemented, the resolver
// will use the provided latency value instead of measuring outside.
type BackendLatencyObserver interface {
    LastExchangeLatency() time.Duration
}
