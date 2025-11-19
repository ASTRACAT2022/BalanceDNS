package doe

import (
	"github.com/miekg/dns"
	"slices"
)

func (doe *DenialOfExistenceNSEC3) PerformClosestEncloserProof(name string) (optedOut, closestEncloserProof, nextCloserNameProof, wildcardProof bool) {
	if doe.Empty() {
		return
	}

	closestEncloser, nextCloserName, ok := doe.FindClosestEncloser(name)
	if !ok {
		return
	}

	closestEncloserProof = true

	wildcardProof = doe.verifyWildcardCovered(closestEncloser)

	optedOut, nextCloserNameProof = doe.verifyNextCloserNameCovered(nextCloserName)

	return
}

func (doe *DenialOfExistenceNSEC3) PerformExpandedWildcardProof(wildcardAnswerSignatureName string, wildcardAnswerSignatureNameLabels uint8) bool {
	/*
		https://datatracker.ietf.org/doc/html/rfc5155#section-7.2.6
		7.2.6.  Wildcard Answer Responses

		If there is a wildcard match for QNAME and QTYPE, then, in addition
		to the expanded wildcard RRSet returned in the answer section of the
		response, proof that the wildcard match was valid must be returned.

		This proof is accomplished by proving that both QNAME does not exist
		and that the closest encloser of the QNAME and the immediate ancestor
		of the wildcard are the same (i.e., the correct wildcard matched).

		To this end, the NSEC3 RR that covers the "next closer" name of the
		immediate ancestor of the wildcard MUST be returned.  It is not
		necessary to return an NSEC3 RR that matches the closest encloser, as
		the existence of this closest encloser is proven by the presence of
		the expanded wildcard in the response.


		https://datatracker.ietf.org/doc/html/rfc5155#section-8.8
		8.8.  Validating Wildcard Answer Responses

		The verified wildcard answer RRSet in the response provides the
		validator with a (candidate) closest encloser for QNAME.  This
		closest encloser is the immediate ancestor to the generating
		wildcard.

		Validators MUST verify that there is an NSEC3 RR that covers the
		"next closer" name to QNAME present in the response.  This proves
		that QNAME itself did not exist and that the correct wildcard was
		used to generate the response.
	*/

	labelIndexs := dns.Split(wildcardAnswerSignatureName)
	closestEncloserIndex := len(labelIndexs) - int(wildcardAnswerSignatureNameLabels)

	// The immediate ancestor of the wildcard
	closestEncloser := wildcardAnswerSignatureName[labelIndexs[closestEncloserIndex]:]

	// The "next closer" of the immediate ancestor
	nextCloserName := wildcardAnswerSignatureName[labelIndexs[closestEncloserIndex-1]:]

	wildcardProof := doe.verifyWildcardCovered(closestEncloser) || doe.verifyWildcardMatched(closestEncloser)
	_, nextCloserNameProof := doe.verifyNextCloserNameCovered(nextCloserName)

	// We need no DOE wildcard proof (i.e. there can be a wildcard), and the nextCloserName proving the original QNAME is missing.
	return !wildcardProof && nextCloserNameProof
}

func (doe *DenialOfExistenceNSEC3) verifyWildcardCovered(closestEncloser string) (wildcardProof bool) {

	// We want Covers, not matched.

	wildcard := "*." + closestEncloser

	for _, nsec3 := range doe.records {

		if nsec3.Match(wildcard) {
			return false
		}

		if nsec3.Cover(wildcard) {
			wildcardProof = true
		}

	}

	return
}

func (doe *DenialOfExistenceNSEC3) verifyWildcardMatched(closestEncloser string) (wildcardProof bool) {

	for _, nsec3 := range doe.records {
		wildcard := "*." + closestEncloser

		if nsec3.Match(wildcard) {
			return true
		}

	}

	return
}

func (doe *DenialOfExistenceNSEC3) verifyNextCloserNameCovered(nextCloserName string) (optedOut, nextCloserNameProof bool) {

	// We want Covers, not matched.

	for _, nsec3 := range doe.records {

		if nsec3.Match(nextCloserName) {
			return false, false
		}

		if nsec3.Cover(nextCloserName) {
			nextCloserNameProof = true
			optedOut = optedOut || nsec3.Flags == 1
		}

	}

	return
}

func (doe *DenialOfExistenceNSEC3) TypeBitMapContainsAnyOf(name string, types []uint16) (nameSeen, typeSeen bool) {
	for _, nsec3 := range doe.records {
		if !nsec3.Match(name) {
			continue
		}

		nameSeen = true

		for _, t := range types {
			if slices.Contains(nsec3.TypeBitMap, t) {
				return nameSeen, true
			}
		}
	}

	return nameSeen, false
}

func (doe *DenialOfExistenceNSEC3) FindClosestEncloser(qname string) (string, string, bool) {

	// https://datatracker.ietf.org/doc/html/rfc7129#section-5.5
	//There must be an existing ancestor in the zone: a name
	//must exist that is shorter than the query name.  The resolver keeps
	//hashing increasingly shorter names from the query name until an owner
	//name of an NSEC3 matches.  This owner name is the closest encloser.

	/*
	   Once the closest encloser has been discovered, the validator MUST
	   check that the NSEC3 RR that has the closest encloser as the original
	   owner name is from the proper zone.  The DNAME type bit must not be
	   set and the NS type bit may only be set if the SOA type bit is set.
	   If this is not the case, it would be an indication that an attacker
	   is using them to falsely deny the existence of RRs for which the
	   server is not authoritative.
	*/

	type proofPair struct {
		ce  string
		ncn string
	}

	// Holds all names which are a contender to be the closest encloser.
	contenders := make([]proofPair, 0, 3)

	for _, nsec3 := range doe.records {

		last := 0
		for _, i := range dns.Split(qname) {
			name := qname[i:]

			// We ensure it's part of the expected zone.
			if !dns.IsSubDomain(doe.zone, name) {
				break
			}

			if nsec3.Match(name) {
				// Not eligible if the DNAME bit is set.
				if slices.Contains(nsec3.TypeBitMap, dns.TypeDNAME) {
					continue
				}

				// Not eligible if NS is set, without SOA being set.
				if slices.Contains(nsec3.TypeBitMap, dns.TypeNS) && !slices.Contains(nsec3.TypeBitMap, dns.TypeSOA) {
					continue
				}

				contenders = append(contenders, proofPair{
					ce:  name,
					ncn: qname[last:],
				})

				// We can move on to the next NSEC3 RR.
				break
			}
			last = i
		}

	}

	if len(contenders) == 0 {
		return "", "", false
	}

	contender := contenders[0]

	// The closest encloser is the result with the longest name.
	for i := 1; i < len(contenders); i++ {
		if len(contenders[i].ce) > len(contender.ce) {
			contender = contenders[i]
		}
	}

	return contender.ce, contender.ncn, true
}
