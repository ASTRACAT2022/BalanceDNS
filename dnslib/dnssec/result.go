package dnssec

import (
	"github.com/miekg/dns"
)

func (a *Authenticator) Result() (AuthenticationResult, DenialOfExistenceState, error) {

	// Ensure we've processed all items in the input butter.
	for ; a.inputBufferIdx < len(a.inputBuffer); a.inputBufferIdx++ {
		if a.inputBuffer[a.inputBufferIdx] == nil {
			continue
		}
		in := a.inputBuffer[a.inputBufferIdx]
		if err := a.processResponse(in.zone, in.msg); err != nil {
			return Unknown, NotFound, err
		}
	}

	//---

	// If we have no answers at all we have nothing to go on, thus we don't know what the status is.
	if len(a.results) == 0 {
		return Unknown, NotFound, ErrNoResults
	}

	//-----------------------------------------------------------
	// If any result was Bogus, then Bogus.

	for _, r := range a.results {
		if r.state == Bogus {
			return Bogus, NotFound, r.err
		}
	}

	//-----------------------------------------------------------
	// If the chain moved from Secure to Insecure,
	// there must be Denial of Existence on the DS records, otherwise Bogus.

	for i, current := range a.results {
		if current.state == Secure {
			continue
		}

		if i == 0 {
			// If the first result was not secure, we might as well give up now.
			return current.state, current.denialOfExistence, current.err
		}

		previous := a.results[i-1]

		switch previous.denialOfExistence {
		case Nsec3OptOut, NsecMissingDS, Nsec3MissingDS:
			return Insecure, previous.denialOfExistence, current.err

		case NsecNoData, Nsec3NoData:
			previousQ := previous.msg.Question[0]

			// This is only valid if we'd specifically queried for the DS records we needed.
			// i.e. The Question we have the DOE for should match the zone apex for the current result's zone.
			if previousQ.Qtype == dns.TypeDS && dns.CanonicalName(previousQ.Name) == dns.CanonicalName(current.zone.Name()) {
				return Insecure, previous.denialOfExistence, current.err
			}

			// NsecNxDomain & Nsec3NxDomain are not accepted as the Record Owner must exist
			// if we've been delegated to its ancestor.
		}

		return Bogus, previous.denialOfExistence, current.err
	}

	//-----------------------------------------------------------
	// We're now just interested in the last result...

	last := a.results[len(a.results)-1]

	if last.state != Secure {
		// TODO: check if this can ever be called. I suspect not.
		return last.state, last.denialOfExistence, last.err
	}

	switch last.denialOfExistence {
	case Nsec3OptOut:
		return Insecure, last.denialOfExistence, last.err
	case NsecNxDomain, Nsec3NxDomain, NsecNoData, Nsec3NoData:
		return Secure, last.denialOfExistence, last.err
	default:
		return Bogus, last.denialOfExistence, last.err
	case NotFound, NsecWildcard, Nsec3Wildcard:
		// We carry on...
	}

	//-----------------------------------------------------------
	// We now expect a positive answer

	// We should see no SOA in the authority section.
	if recordsOfTypeExist(last.msg.Ns, dns.TypeSOA) {
		return Bogus, last.denialOfExistence, last.err
	}

	// We expect an answer matching the QNAme, and the QType or CNAME.
	if len(extractRecordsOfNameAndType(last.msg.Answer, a.question.Name, a.question.Qtype)) > 0 {
		return Secure, last.denialOfExistence, last.err
	}

	if len(extractRecordsOfNameAndType(last.msg.Answer, a.question.Name, dns.TypeCNAME)) > 0 {
		return Secure, last.denialOfExistence, last.err
	}

	// We default to worse case.
	return Bogus, last.denialOfExistence, last.err
}

/*
   If the resolver accepts the RRset as authentic, the validator MUST
   set the TTL of the RRSIG RR and each RR in the authenticated RRset to
   a value no greater than the minimum of:
   o  the RRset's TTL as received in the response;
   o  the RRSIG RR's TTL as received in the response;
   o  the value in the RRSIG RR's Original TTL field; and
   o  the difference of the RRSIG RR's Signature Expiration time and the current time.
*/

// ResultTTLAnswer takes a record type, and returns the TTL that should be applied to that record, based on the above.
func (a *Authenticator) ResultTTLAnswer(rtype uint16) (uint32, bool) {

	if len(a.results) == 0 {
		return 0, false
	}

	last := a.results[len(a.results)-1]

	return resultTTL(rtype, last.answer)
}

func (a *Authenticator) ResultTTLAuthority(rtype uint16) (uint32, bool) {

	if len(a.results) == 0 {
		return 0, false
	}

	last := a.results[len(a.results)-1]

	return resultTTL(rtype, last.authority)
}

func resultTTL(rtype uint16, ss signatures) (uint32, bool) {

	found := false
	ttl := MaxAllowedTTL

	for _, sig := range ss {
		if sig.rtype == rtype && sig.verified {
			found = true
			ttl = min(ttl, sig.ttl)
		}
	}

	if !found {
		return 0, false
	}

	return ttl, true
}
