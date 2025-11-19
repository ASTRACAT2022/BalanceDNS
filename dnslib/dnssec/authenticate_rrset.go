package dnssec

import (
	"fmt"
	"github.com/miekg/dns"
	"time"
)

func authenticate(zone string, rrsets []dns.RR, dnskeys []*dns.DNSKEY, section section) (signatures, error) {
	zone = dns.CanonicalName(zone)

	rrsigs := extractRecords[*dns.RRSIG](rrsets)
	signatures := make(signatures, len(rrsigs))

	for i, rrsig := range rrsigs {
		sig := signature{
			zone:  zone,
			name:  rrsig.Header().Name,
			rtype: rrsig.TypeCovered,
			rrsig: rrsig,
			rrset: extractRecordsOfNameAndType(rrsets, rrsig.Header().Name, rrsig.TypeCovered),
			ttl:   min(rrsig.Header().Ttl, rrsig.OrigTtl),
		}
		signatures[i] = &sig

		if dns.CanonicalName(sig.zone) != dns.CanonicalName(rrsig.SignerName) {
			sig.err = fmt.Errorf("%w: zone:[%s] SignerName:[%s]", ErrAuthSignerNameMismatch, sig.zone, rrsig.SignerName)
			continue
		}

		if dns.CountLabel(rrsig.Header().Name) < int(rrsig.Labels) {
			sig.err = fmt.Errorf("%w: owner name has %d labels and the rrsig labels field is %d", ErrInvalidLabelCount, dns.CountLabel(rrsig.Header().Name), rrsig.Labels)
			continue
		}

		if !rrsig.ValidityPeriod(time.Now()) {
			sig.err = fmt.Errorf("%w: msg valid %s to %s", ErrInvalidTime, dns.TimeToString(rrsig.Inception), dns.TimeToString(rrsig.Expiration))
			continue
		}

		if dns.CountLabel(rrsig.Header().Name) > int(rrsig.Labels) {
			sig.wildcard = true
		}

		//---
		// TTL cannot be greater than the time left before the signature expires (logic from dns.ValidityPeriod)

		utc := time.Now().UTC().Unix()
		mode := (int64(rrsig.Expiration) - utc) / year68
		te := int64(rrsig.Expiration) + mode*year68
		delta := uint32(te - utc)
		sig.ttl = min(sig.ttl, delta)

		for _, rr := range sig.rrset {
			sig.ttl = min(sig.ttl, rr.Header().Ttl)
		}

		//---

		// Iterate over all the DNS keys to see if one matches the signature.
		for _, key := range dnskeys {

			// https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.1
			// It is possible for more than one DNSKEY RR to match the conditions
			// above.  In this case, the validator cannot predetermine which DNSKEY
			// RR to use to authenticate the signature, and it MUST try each
			// matching DNSKEY RR until either the signature is validated or the
			// validator has run out of matching public keys to try.
			// i.e. A key can have the same owner, Flags, Protocol, Algorithm and KeyTag.

			if key.Algorithm == rrsig.Algorithm && key.KeyTag() == rrsig.KeyTag && dns.CanonicalName(key.Header().Name) == dns.CanonicalName(rrsig.SignerName) {

				sig.err = rrsig.Verify(key, sig.rrset)

				if sig.err != nil {
					// We'll wrap the error
					sig.err = fmt.Errorf("%w: %w", ErrInvalidSignature, sig.err)
				} else {
					// The signature was verified.
					sig.key = key
					sig.verified = true
					sig.dsSha256 = key.ToDS(dns.SHA256).Digest
					break
				}

			}
		}

		if !sig.verified && sig.err == nil {
			sig.err = ErrNoKeyFoundForSignature
		}
	}

	//-------------------------

	/*
		https://datatracker.ietf.org/doc/html/rfc4035#section-2.2
		There MUST be an RRSIG for each RRset...
	*/

	type combination struct {
		name   string
		rrtype uint16
	}

	combinations := make(map[combination]bool, len(signatures))

	// So the number of name/Type combinations should equal the number of signatures we have.
	for _, rrset := range rrsets {
		// We don't sign rrsig records.
		if rrset.Header().Rrtype == dns.TypeRRSIG {
			continue
		}

		// We _typically_ don't sign NS records in the authority section, but it can happen:
		// `dig @l.gtld-servers.net. naughty-nameserver.com. DS +dnssec`
		if section == authoritySection && rrset.Header().Rrtype == dns.TypeNS {
			// We check and see if we have any signatures for the NS record. If we do, we count the combination.
			if len(signatures.filterOnType(dns.TypeNS)) == 0 {
				continue
			}
		}

		combinations[combination{
			name:   rrset.Header().Name,
			rrtype: rrset.Header().Rrtype,
		}] = true
	}

	var err error
	if len(combinations) != signatures.countNameTypeCombinations() {
		err = fmt.Errorf("%w: we found %d signatures but %d rrsets", ErrUnexpectedSignatureCount, signatures.countNameTypeCombinations(), len(combinations))
	}

	return signatures, err
}
