package dnssec

import (
	"context"
	"github.com/miekg/dns"
)

func (v verifier) verify(ctx context.Context, zone Zone, msg *dns.Msg, dsRecordsFromParent []*dns.DS) (AuthenticationResult, *result, error) {
	r := &result{
		name: zone.Name(),
		zone: zone,
		msg:  msg,
	}

	if len(dsRecordsFromParent) == 0 {
		return Insecure, r, nil // TODO: I'm not really sure this is an error. It's often expected once the chain breaks.
		//return Insecure, r, ErrNoParentDSRecords
	}

	// Verify DNSKEYS
	// Verify all other RRSETs
	// Delegating Answer check
	// Positive Answer check
	// Negative Answer check

	var status AuthenticationResult

	keys, err := zone.GetDNSKEYRecords()
	if err != nil {
		return Bogus, r, err
	}

	status, err = v.verifyDNSKEYs(ctx, r, keys, dsRecordsFromParent)
	if status != Unknown || err != nil {
		return status, r, err
	}

	status, err = v.verifyRRSETs(ctx, r, extractRecords[*dns.DNSKEY](keys))
	if status != Unknown || err != nil {
		return status, r, err
	}

	// We ignore the message header when determining the type of response, as the header is not signed.

	soaFoundInAuthority := recordsOfTypeExist(r.msg.Ns, dns.TypeSOA)

	// A Delegating Response has no Answers, no SOA, and at least one NS record in the Authority section.
	if !soaFoundInAuthority && len(r.msg.Answer) == 0 && recordsOfTypeExist(r.msg.Ns, dns.TypeNS) {
		status, err = v.validateDelegatingResponse(ctx, r)
		return status, r, err
	}

	// A positive response has at least one answer, and SOA in the Authority section.
	if !soaFoundInAuthority && len(r.msg.Answer) > 0 {
		status, err = v.validatePositiveResponse(ctx, r)
		return status, r, err
	}

	// A negative response has a SOA in the Authority section.
	if soaFoundInAuthority {
		status, err = v.validateNegativeResponse(ctx, r)
		return status, r, err
	}

	// We should never get here. If we do, the response was likely malformed. We'll fail-safe to Bogus.
	return Bogus, r, ErrFailsafeResponse
}
