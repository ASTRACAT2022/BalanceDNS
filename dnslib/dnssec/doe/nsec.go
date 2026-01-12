package doe

import (
	"github.com/miekg/dns"
	"slices"
)

func (doe *DenialOfExistenceNSEC) PerformQNameDoesNotExistProof(qname string) bool {
	return !doe.Empty() && (doe.verifyQNameCovered(qname) && doe.verifyWildcardCovered(qname))
}

func (doe *DenialOfExistenceNSEC) PerformExpandedWildcardProof(qname string) bool {
	return !doe.Empty() && (doe.verifyQNameCovered(qname) && !doe.verifyWildcardCovered(qname))
}

func (doe *DenialOfExistenceNSEC) verifyQNameCovered(qname string) bool {
	qname = dns.CanonicalName(qname)

	/*
		https://datatracker.ietf.org/doc/html/rfc3845#section-2.1.1
		The value of the Next Domain name field in the last NSEC record in the zone is the name of the
		zone apex (the owner name of the zone's SOA RR).
	*/

	for _, nsec := range doe.records {
		qnameAfterNsecOwnerName := canonicalCmp(nsec.Header().Name, qname) < 0
		qnameBeforeNextDomain := dns.CanonicalName(nsec.NextDomain) == doe.zone || canonicalCmp(qname, nsec.NextDomain) < 0

		if qnameAfterNsecOwnerName && qnameBeforeNextDomain {
			return true
		}
	}

	return false
}

func (doe *DenialOfExistenceNSEC) verifyWildcardCovered(qname string) bool {
	qname = dns.CanonicalName(qname)

	/*
		https://datatracker.ietf.org/doc/html/rfc3845#section-2.1.1
		The value of the Next Domain name field in the last NSEC record in the zone is the name of the
		zone apex (the owner name of the zone's SOA RR).
	*/

	wildcard := wildcardName(qname)

	for _, nsec := range doe.records {
		wildcardAfterNsecOwnerName := canonicalCmp(nsec.Header().Name, wildcard) < 0
		wildcardBeforeNextDomain := dns.CanonicalName(nsec.NextDomain) == doe.zone || canonicalCmp(wildcard, nsec.NextDomain) < 0

		if wildcardAfterNsecOwnerName && wildcardBeforeNextDomain {
			return true
		}
	}

	return false
}

func (doe *DenialOfExistenceNSEC) TypeBitMapContainsAnyOf(name string, types []uint16) (nameSeen, typeSeen bool) {

	for _, nsec := range doe.records {
		if name != dns.CanonicalName(nsec.Header().Name) {
			continue
		}

		nameSeen = true

		for _, t := range types {
			if slices.Contains(nsec.TypeBitMap, t) {
				return nameSeen, true
			}
		}
	}

	return nameSeen, false
}
