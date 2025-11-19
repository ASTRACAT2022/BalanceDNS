package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver/dnssec"
	"sync/atomic"
	"time"
)

// We have a public Exchange(), so people can call it.
// And a private exchange(), to meet the exchanger interface.

func (resolver *Resolver) Exchange(ctx context.Context, qmsg *dns.Msg) *Response {
	if !qmsg.RecursionDesired {
		return newResponseError(ErrNotRecursionDesired)
	}

	// We'll copy the message we'll likely want to mutate some values.
	// And it might be confusing to the caller if the values in their instance change.
	response := resolver.exchange(ctx, qmsg.Copy())

	if !response.IsEmpty() {
		response.Msg.RecursionAvailable = true
	}

	return response
}

func (resolver *Resolver) exchange(ctx context.Context, qmsg *dns.Msg) *Response {

	//----------------------------------------------------------------------------
	// We setup our context

	start := time.Now()
	if v := ctx.Value(ctxStartTime); v == nil {
		ctx = context.WithValue(ctx, ctxStartTime, start)
	}

	//---

	trace, ok := ctx.Value(CtxTrace).(*Trace)
	if !ok {
		trace = newTraceWithStart(start)
		ctx = context.WithValue(ctx, CtxTrace, trace)
		Debug(fmt.Sprintf("New query started with Trace ID: %s", trace.ShortID()))
	}

	trace.Iterations.Add(1)

	//---

	// counter tracts the number of iterations we've seen of the main query loop - the one at the end of this function.
	// Its value persists across all call to resolver.exchange(), for a given query.
	// Its job is to detect/prevent infinite loops.
	counter, ok := ctx.Value(ctxSessionQueries).(*atomic.Uint32)
	if !ok {
		counter = new(atomic.Uint32)
		ctx = context.WithValue(ctx, ctxSessionQueries, counter)
	}

	//----------------------------------------------------------------------------
	// We setup the DNSSEC Authenticator

	// If the DO flag is set, we create a DNSSEC Authenticator.
	var auth *authenticator
	if isSetDO(qmsg) {
		auth = newAuthenticator(ctx, qmsg.Question[0])
		defer auth.close()
	}

	//----------------------------------------------------------------------------
	// We determine what zones we already know about for the QName

	// Returns a list zones that make up the QName that we already have nameservers for.
	// Items are only included is we have a valid chain from leaf to root.
	// They are ordered most specific (i.e. longest FQDN), to shortest.
	// The last element will always be the root (.).
	knownZones := resolver.zones.getZoneList(qmsg.Question[0].Name)

	if auth != nil {
		// Lookup the DNSSEC details for these zones.
		// We don't do this lookup for the root, thus len()-1.
		for i := 0; i < len(knownZones)-1; i++ {
			// We never look directly at the first zone.
			z := knownZones[i+1]
			dsName := knownZones[i].name()
			auth.addDelegationSignerLink(z, dsName)
		}
	}

	//----------------------------------------------------------------------------
	// We iterate through the QName labels, exchanging the question with each zone.

	d := newDomain(qmsg.Question[0].Name)

	// Wind past all the zones that we already know about (if any).
	if err := d.windTo(knownZones[0].name()); err != nil {
		return newResponseError(err)
	}

	var response *Response

	// We track the last zone, as that's were we pass the query for the next label.
	var z zone = knownZones[0]

	for ; d.more(); d.next() {
		if counter.Add(1) > MaxQueriesPerRequest {
			return newResponseError(fmt.Errorf("%w. value is currently set to: %d", ErrMaxQueriesPerRequestReached, MaxQueriesPerRequest))
		}

		c := d.current()
		if next := resolver.zones.get(c); next != nil && !d.last() {
			// If we already know the zone, we don't need to resolve it.
			// So as long as we're not trying to resolve the actually QName (i.e. the last part of the domain)
			// Then we can continue.
			z = next
			continue
		}

		z, response = resolver.funcs.resolveLabel(ctx, &d, z, qmsg, auth)

		if response != nil {
			Debug(fmt.Sprintf("counter at end of exchange for iteration %d is %d", trace.Iterations.Load(), counter.Load()))
			return response
		}
	}

	return newResponseError(ErrUnableToResolveAnswer)
}

func (resolver *Resolver) resolveLabel(ctx context.Context, d *domain, z zone, qmsg *dns.Msg, auth *authenticator) (zone, *Response) {
	if z == nil {
		// We must have a zone passed.
		return nil, newResponseError(fmt.Errorf("%w: zone cannot be nil", ErrInternalError))
	}

	if auth != nil {
		// If we're going to need the DNSKEY, we can pre-fetch it.
		go z.dnskeys(ctx)
	}

	response := z.exchange(ctx, qmsg)

	if response.HasError() {
		return nil, response
	}

	if response.IsEmpty() {
		return nil, newResponseError(fmt.Errorf("%w - without an error. mysterious", ErrEmptyResponse))
	}

	//---

	z = resolver.funcs.checkForMissingZones(ctx, d, z, response.Msg, auth)

	//---

	if auth != nil {
		auth.addResponse(z, response.Msg)
	}

	if len(response.Msg.Answer) == 0 && recordsOfTypeExist(response.Msg.Ns, dns.TypeNS) && !recordsOfTypeExist(response.Msg.Ns, dns.TypeSOA) {
		return resolver.funcs.processDelegation(ctx, z, response.Msg)
	}

	response = resolver.funcs.finaliseResponse(ctx, auth, qmsg, response)
	return nil, response

}

func (resolver *Resolver) checkForMissingZones(ctx context.Context, d *domain, z zone, rmsg *dns.Msg, auth *authenticator) zone {
	records := append(rmsg.Ns, rmsg.Answer...)
	if len(records) == 0 {
		return z
	}

	// We're trying to best-effort optimise here, so we'll just pick one `nextRecordsOwner`.
	// The best options is:
	// 	1 - A child of the current zone; and
	//	2 - Has the largest label count.

	// TODO: ignore DOE records below?

	nextRecordsOwner := "."
	for _, record := range records {
		option := record.Header().Name
		if nextRecordsOwner != option && dns.IsSubDomain(z.name(), option) && dns.CountLabel(option) > dns.CountLabel(nextRecordsOwner) {
			nextRecordsOwner = option
		}
	}

	// Then no options could be found.
	if nextRecordsOwner == "." {
		return z
	}

	// d.current() here is the domain we're expecting.
	// So if it's not what we get, we expect it to be included in the missing zones slice.

	missingZoneNames := d.gap(nextRecordsOwner)
	for _, missingDomain := range missingZoneNames {

		soa, err := z.soa(ctx, missingDomain)

		// If a SOA was found, then the missingDomain is its own zone.
		if err == nil && soa != nil {

			newZone := z.clone(missingDomain, z.name())

			if auth != nil {
				auth.addDelegationSignerLink(z, newZone.name())
			}

			resolver.zones.add(newZone)
			z = newZone

		}

		// We skip over these missing domains in our lookup loop.
		d.next()
	}

	return z
}

func (resolver *Resolver) processDelegation(ctx context.Context, z zone, rmsg *dns.Msg) (zone, *Response) {
	// Otherwise - onwards to the next zone...
	nameservers := extractRecords[*dns.NS](rmsg.Ns)

	if len(nameservers) == 0 {
		return nil, &Response{
			Err: fmt.Errorf("%w in the response from zone [%s]", ErrNextNameserversNotFound, z.name()),
		}
	}

	nextZoneName := canonicalName(nameservers[0].Header().Name)

	if nextZoneName == z.name() || !dns.IsSubDomain(z.name(), nextZoneName) {
		return nil, &Response{
			Err: fmt.Errorf("%w: unexpected zone [%s] after [%s]", ErrNextNameserversNotFound, nextZoneName, z.name()),
		}
	}

	newZone, err := resolver.funcs.createZone(ctx, nextZoneName, z.name(), nameservers, rmsg.Extra, resolver.funcs.getExchanger())
	if err != nil {
		return nil, newResponseError(err)
	}

	resolver.zones.add(newZone)

	return newZone, nil
}

func (resolver *Resolver) finaliseResponse(ctx context.Context, auth *authenticator, qmsg *dns.Msg, response *Response) *Response {
	if auth != nil {
		authTime := time.Now()
		response.Auth, response.Doe, response.Err = auth.result()
		Info(fmt.Sprintf("DNSSEC took %s to return an answer of %s and DOE %s", time.Since(authTime), response.Auth.String(), response.Doe.String()))

		/*
			   If the resolver accepts the RRset as authentic, the validator MUST
			   set the TTL of the RRSIG RR and each RR in the authenticated RRset to
			   a value no greater than the minimum of:
			   o  the RRset's TTL as received in the response;
			   o  the RRSIG RR's TTL as received in the response;
			   o  the value in the RRSIG RR's Original TTL field; and
			   o  the difference of the RRSIG RR's Signature Expiration time and the
				  current time.
		*/

		type rrtypeTTL struct {
			ttl   uint32
			found bool
		}

		// Cache the values so we don't need to recalculate them each time.
		ttls := make(map[uint16]rrtypeTTL)

		if response.Auth == dnssec.Secure {
			for _, rr := range response.Msg.Answer {
				rtypeTTL, found := ttls[rr.Header().Rrtype]

				if !found {
					ttl, found := auth.resultTTLAnswer(rr.Header().Rrtype)
					rtypeTTL = rrtypeTTL{ttl, found}
					ttls[rr.Header().Rrtype] = rtypeTTL
				}

				if rtypeTTL.found {
					rr.Header().Ttl = min(rtypeTTL.ttl, rr.Header().Ttl)
				}
			}

			clear(ttls)

			for _, rr := range response.Msg.Ns {
				rtypeTTL, found := ttls[rr.Header().Rrtype]

				if !found {
					ttl, found := auth.resultTTLAuthority(rr.Header().Rrtype)
					rtypeTTL = rrtypeTTL{ttl, found}
					ttls[rr.Header().Rrtype] = rtypeTTL
				}

				if rtypeTTL.found {
					rr.Header().Ttl = min(rtypeTTL.ttl, rr.Header().Ttl)
				}
			}
		}
	}

	//---

	// Follow any CNAME, if needed.
	if qmsg.Question[0].Qtype != dns.TypeCNAME && recordsOfTypeExist(response.Msg.Answer, dns.TypeCNAME) {
		// The results from this are added to `response.Msg`.
		err := resolver.funcs.cname(ctx, qmsg, response, resolver.funcs.getExchanger())
		if err != nil {
			return &Response{
				Err: err,
			}
		}
	}

	// We'll consider both of these 'normal' responses.
	if !(response.Msg.Rcode == dns.RcodeSuccess || response.Msg.Rcode == dns.RcodeNameError) {
		response.Err = fmt.Errorf("unsuccessful response code %s (%d)", RcodeToString(response.Msg.Rcode), response.Msg.Rcode)
	}

	//---

	if RemoveAuthoritySectionForPositiveAnswers && len(response.Msg.Answer) > 0 && !recordsOfTypeExist(response.Msg.Ns, dns.TypeSOA) {
		response.Msg.Ns = []dns.RR{}
	}

	if RemoveAdditionalSectionForPositiveAnswers && len(response.Msg.Answer) > 0 && !recordsOfTypeExist(response.Msg.Ns, dns.TypeSOA) {
		var opt *dns.OPT
		for _, extra := range response.Msg.Extra {
			if r, ok := extra.(*dns.OPT); ok {
				opt = r
				break
			}
		}

		if opt != nil {
			response.Msg.Extra = []dns.RR{opt}
		} else {
			response.Msg.Extra = []dns.RR{}
		}
	}

	dedup := make(map[string]dns.RR)
	if len(response.Msg.Answer) > 0 {
		response.Msg.Answer = dns.Dedup(response.Msg.Answer, dedup)
	}
	if len(response.Msg.Ns) > 0 {
		clear(dedup)
		response.Msg.Ns = dns.Dedup(response.Msg.Ns, dedup)
	}
	if len(response.Msg.Extra) > 0 {
		clear(dedup)
		response.Msg.Extra = dns.Dedup(response.Msg.Extra, dedup)
	}

	if auth != nil {

		if !qmsg.CheckingDisabled {
			response.Msg.AuthenticatedData = response.Auth == dnssec.Secure

			// If a response is Bogus, we return a Server Failure with all the response removed.
			if response.Auth == dnssec.Bogus {
				response.Msg.Rcode = dns.RcodeServerFailure
				if SuppressBogusResponseSections {
					response.Msg.Answer = []dns.RR{}
					response.Msg.Ns = []dns.RR{}
					response.Msg.Extra = []dns.RR{}
				}
			}
		}
	}

	start, _ := ctx.Value(ctxStartTime).(time.Time)
	response.Duration = time.Since(start)
	return response
}
