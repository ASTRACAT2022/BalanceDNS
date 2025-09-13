package dnssec

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver/dnssec/doe"
)

func validateDelegatingResponse(ctx context.Context, r *result) (AuthenticationResult, error) {

	// We extract any delegation DS records in the authority.
	// Note that we'll look for DS records in the answer if, and only if, the response it a positive answer.
	r.dsRecords = r.authority.extractDSRecords()

	// If signed DS records were found, then we're done here.
	if len(r.dsRecords) > 0 {
		return Secure, nil
	}

	//---

	nsRecords := extractRecordsOfType(r.msg.Ns, dns.TypeNS)
	if !recordsHaveTheSameOwner(nsRecords) {
		// This seems an odd case. But if true, we cannot confidently know which is the delegation name.
		return Bogus, fmt.Errorf("%w: this prevents us from checking nsec(3) records", ErrNSRecordsHaveMismatchingOwners)
	}

	delegationName := nsRecords[0].Header().Name

	//---

	nsec := doe.NewDenialOfExistenceNSEC(ctx, r.zone.Name(), r.authority.extractNSECRecords())
	nsec3 := doe.NewDenialOfExistenceNSEC3(ctx, r.zone.Name(), r.authority.extractNSEC3Records())

	/*
		https://datatracker.ietf.org/doc/html/rfc5155#section-8.9
		If there is an NSEC3 RR present in the response that matches the
		delegation name, then the validator MUST ensure that the NS bit is
		set and that the DS bit is not set in the Type Bit Maps field of the
		NSEC3 RR.  The validator MUST also ensure that the NSEC3 RR is from
		the correct (i.e., parent) zone.  This is done by ensuring that the
		SOA bit is not set in the Type Bit Maps field of this NSEC3 RR.

		Note that the presence of an NS bit implies the absence of a DNAME
		bit, so there is no need to check for the DNAME bit in the Type Bit
		Maps field of the NSEC3 RR.
	*/

	if !nsec.Empty() {
		// The Type Bit Map must show there are NS records, but there are no CNAME, DS or SOA records.
		if nameSeen, typeSeen := nsec.TypeBitMapContainsAnyOf(delegationName, []uint16{dns.TypeNS}); nameSeen && typeSeen {
			if nameSeen, typeSeen = nsec.TypeBitMapContainsAnyOf(delegationName, []uint16{dns.TypeCNAME, dns.TypeDS, dns.TypeSOA}); nameSeen && !typeSeen {
				r.denialOfExistence = NsecMissingDS
				return Secure, nil
			}
		}
	}

	if !nsec3.Empty() {
		// The Type Bit Map must show there are NS records, but there are no CNAME, DS or SOA records.
		if nameSeen, typeSeen := nsec3.TypeBitMapContainsAnyOf(delegationName, []uint16{dns.TypeNS}); nameSeen && typeSeen {
			if nameSeen, typeSeen = nsec3.TypeBitMapContainsAnyOf(delegationName, []uint16{dns.TypeCNAME, dns.TypeDS, dns.TypeSOA}); nameSeen && !typeSeen {
				r.denialOfExistence = Nsec3MissingDS
				return Secure, nil
			}
		}

		if optedOut, _, _, _ := nsec3.PerformClosestEncloserProof(delegationName); optedOut {
			// We have found an opt-out, thus we will conclude any children are insecure.
			// (Although this result itself is Secure).
			r.denialOfExistence = Nsec3OptOut
			return Secure, nil
		}
	}

	// No DOE exists when expected.
	return Bogus, ErrBogusDoeRecordsNotFound
}
