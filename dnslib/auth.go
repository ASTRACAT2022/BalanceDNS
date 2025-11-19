package resolver

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver/dnssec"
	"sync"
	"sync/atomic"
)

type authenticator struct {
	ctx  context.Context
	auth *dnssec.Authenticator

	errors []error

	closeOnce  sync.Once
	queue      chan authenticatorInput
	finished   atomic.Bool
	processing *sync.WaitGroup
}

type authenticatorInput struct {
	z   zone
	msg *dns.Msg
}

func newAuthenticator(ctx context.Context, question dns.Question) *authenticator {
	a := dnssec.NewAuth(ctx, question)
	auth := &authenticator{
		ctx:        ctx,
		auth:       a,
		errors:     make([]error, 0),
		queue:      make(chan authenticatorInput, 8),
		processing: &sync.WaitGroup{},
	}
	go auth.start()
	return auth
}

func (a *authenticator) close() {
	a.closeOnce.Do(func() {
		a.finished.Store(true)
		a.processing.Wait()
		close(a.queue)
		a.queue = nil
	})
}

func (a *authenticator) addDelegationSignerLink(z zone, qname string) {
	if a.finished.Load() {
		return
	}
	a.processing.Add(1)
	go func() {
		defer a.processing.Done()

		go z.dnskeys(a.ctx)

		dsMsg := new(dns.Msg)
		dsMsg.SetQuestion(dns.Fqdn(qname), dns.TypeDS)
		dsMsg.SetEdns0(4096, true)
		dsMsg.RecursionDesired = false
		response := z.exchange(a.ctx, dsMsg)
		if !response.IsEmpty() && !response.HasError() {
			a.processing.Add(1)
			a.queue <- authenticatorInput{z, response.Msg}
		}
	}()
}

func (a *authenticator) addResponse(z zone, msg *dns.Msg) error {
	if a.finished.Load() {
		return nil
	}
	a.processing.Add(1)
	a.queue <- authenticatorInput{z, msg}
	return nil
}

func (a *authenticator) start() {
	for in := range a.queue {
		err := a.auth.AddResponse(&authZoneWrapper{ctx: a.ctx, zone: in.z}, in.msg)
		if err != nil {
			// `Errors` is only accessible from this thread when processing is !Done().
			a.errors = append(a.errors, err)
		}
		a.processing.Done()
	}
}

func (a *authenticator) result() (dnssec.AuthenticationResult, dnssec.DenialOfExistenceState, error) {
	a.finished.Store(true)
	a.processing.Wait()
	a.close()

	// `Errors` is only accessible from this thread once we've finished Wait().
	if len(a.errors) > 0 {
		if len(a.errors) == 1 {
			return 0, 0, a.errors[0]
		}
		err := errors.New("multiple errors found: ")
		for _, e := range a.errors {
			err = fmt.Errorf("%w: %w", err, e)
		}
	}

	return a.auth.Result()
}

func (a *authenticator) resultTTLAnswer(rtype uint16) (uint32, bool) {
	return a.auth.ResultTTLAnswer(rtype)
}

func (a *authenticator) resultTTLAuthority(rtype uint16) (uint32, bool) {
	return a.auth.ResultTTLAuthority(rtype)
}

// authZoneWrapper wraps our zone such that is supports the dnssec.Zone interface.
// Note that the dnssec package only needs querying support against this zone's nameservers.
// i.e. We do not need to try these queries recursively. If the nameservers for this zone do not return
// an authoritative answer themselves, we can assume that's an error.
type authZoneWrapper struct {
	ctx  context.Context
	zone zone
}

// Name returns the zone's apex domain name.
func (wrapper *authZoneWrapper) Name() string {
	return wrapper.zone.name()
}

// GetDNSKEYRecords Looks up the DNSKEY records for the given QName, in the zone.
func (wrapper *authZoneWrapper) GetDNSKEYRecords() ([]dns.RR, error) {
	return wrapper.zone.dnskeys(wrapper.ctx)
}
