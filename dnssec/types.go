package dnssec

import (
	"context"
	"github.com/miekg/dns"
)

type Zone interface {
	Name() string
	GetDNSKEYRecords() ([]dns.RR, error)
}

type Authenticator struct {
	ctx      context.Context
	question dns.Question

	inputBuffer    []*input
	inputBufferIdx int

	results []*result

	verify func(ctx context.Context, zone Zone, msg *dns.Msg, dsRecordsFromParent []*dns.DS) (AuthenticationResult, *result, error)
}

type input struct {
	zone Zone
	msg  *dns.Msg
}

type result struct {
	name string
	zone Zone
	msg  *dns.Msg

	keys      signatures
	answer    signatures
	authority signatures

	err error

	dsRecords []*dns.DS

	state             AuthenticationResult
	denialOfExistence DenialOfExistenceState
}

type signatures []*signature

// Represents a single signature (rrsig), along with its key, and the records is signs.
type signature struct {
	zone string

	name  string
	rtype uint16
	ttl   uint32

	key   *dns.DNSKEY
	rrsig *dns.RRSIG
	rrset []dns.RR

	wildcard bool

	verified bool
	err      error

	dsSha256 string // For debugging
}

type verifier struct {
	verifyDNSKEYs              func(ctx context.Context, r *result, keys []dns.RR, dsRecordsFromParent []*dns.DS) (AuthenticationResult, error)
	verifyRRSETs               func(ctx context.Context, r *result, keys []*dns.DNSKEY) (AuthenticationResult, error)
	validateDelegatingResponse func(ctx context.Context, r *result) (AuthenticationResult, error)
	validatePositiveResponse   func(ctx context.Context, r *result) (AuthenticationResult, error)
	validateNegativeResponse   func(ctx context.Context, r *result) (AuthenticationResult, error)
}
