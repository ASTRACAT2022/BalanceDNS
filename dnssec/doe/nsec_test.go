package doe

import (
	"context"
	"github.com/miekg/dns"
	"slices"
	"testing"
)

func TestDenialOfExistenceNSEC_BitMap(t *testing.T) {

	// Assume we are querying for the AAAA record on test.example.com. It does not exist, but an A record does.
	// This also covers the common response for services using online signing for (what should be) a NXDOMAIN response. e.g. AWS Route53.

	rrset := []*dns.NSEC{
		newRR("test.example.com. 3600 IN NSEC \000.test.example.com. A RRSIG NSEC").(*dns.NSEC),
	}

	nsec := NewDenialOfExistenceNSEC(context.Background(), zoneName, rrset)

	nameSeen, typeSeen := nsec.TypeBitMapContainsAnyOf("test.example.com.", []uint16{dns.TypeA})
	if !nameSeen || !typeSeen {
		t.Error("we expect both the name and type to be seen")
	}

	nameSeen, typeSeen = nsec.TypeBitMapContainsAnyOf("test.example.com.", []uint16{dns.TypeAAAA})
	if !nameSeen || typeSeen {
		t.Error("we expect the name to be seen, but not the type")
	}

	nameSeen, typeSeen = nsec.TypeBitMapContainsAnyOf("other.example.com.", []uint16{dns.TypeA})
	if nameSeen || typeSeen {
		// Note that we only expect a type to be seen if the name is also seen.
		// i.e. we only inspect a NSEC record's BitMap if it matches the name.
		t.Error("we expect neither the name or type to be seen")
	}

}

func TestDenialOfExistenceNSEC_NXDOMAIN(t *testing.T) {

	rrset1 := []*dns.NSEC{
		newRR("example.com. 3600 IN NSEC d.example.com. SOA RRSIG NSEC").(*dns.NSEC),
	}
	rrset2 := []*dns.NSEC{
		newRR("s.example.com. 3600 IN NSEC u.example.com. A RRSIG NSEC").(*dns.NSEC),
	}

	nsec := NewDenialOfExistenceNSEC(context.Background(), zoneName, slices.Concat(rrset1, rrset2))

	// We have DOE for both the QNAME and the wildcard, so proof is valid.
	proofVerified := nsec.PerformQNameDoesNotExistProof("test.example.com.")
	if !proofVerified {
		t.Error("we expect the wildcard proof to be valid")
	}

	// An NSEC record is returned for the QNAME, thus the QNAME exists.
	proofVerified = nsec.PerformQNameDoesNotExistProof("s.example.com.")
	if proofVerified {
		t.Error("we expect the wildcard proof to not be valid")
	}

	//---

	nsec = NewDenialOfExistenceNSEC(context.Background(), zoneName, rrset1)

	// We have no DOE proof for the QNAME, thus we expect false.
	proofVerified = nsec.PerformQNameDoesNotExistProof("test.example.com.")
	if proofVerified {
		t.Error("we expect the wildcard proof to not be valid")
	}

	//---

	nsec = NewDenialOfExistenceNSEC(context.Background(), zoneName, rrset2)

	// We have no DOE proof for the wildcard, thus we expect false.
	proofVerified = nsec.PerformQNameDoesNotExistProof("test.example.com.")
	if proofVerified {
		t.Error("we expect the wildcard proof to not be valid")
	}

	//---

	//set = make(signatures, 0)
	nsec = NewDenialOfExistenceNSEC(context.Background(), zoneName, []*dns.NSEC{})

	// Should always be false if no signatures are set
	proofVerified = nsec.PerformExpandedWildcardProof("test.example.com.")
	if proofVerified {
		t.Error("we expect the wildcard proof to not be valid")
	}

}

func TestDenialOfExistenceNSEC_Wildcard(t *testing.T) {

	rrset1 := []*dns.NSEC{
		newRR("example.com. 3600 IN NSEC d.example.com. SOA RRSIG NSEC").(*dns.NSEC),
	}
	rrset2 := []*dns.NSEC{
		newRR("s.example.com. 3600 IN NSEC u.example.com. A RRSIG NSEC").(*dns.NSEC),
	}

	nsec := NewDenialOfExistenceNSEC(context.Background(), zoneName, rrset2)

	// We only have DOE for the QNAME, so we expect this to be valid.
	proofVerified := nsec.PerformExpandedWildcardProof("test.example.com.")
	if !proofVerified {
		t.Error("we expect the wildcard proof to be valid")
	}

	//---

	nsec = NewDenialOfExistenceNSEC(context.Background(), zoneName, rrset1)

	// We have a DOE for the wildcard, and no DOE for the QNAME, so this should not be valid.
	proofVerified = nsec.PerformExpandedWildcardProof("test.example.com.")
	if proofVerified {
		t.Error("we expect the wildcard proof to not be valid")
	}

	//---

	nsec = NewDenialOfExistenceNSEC(context.Background(), zoneName, slices.Concat(rrset1, rrset2))

	// We have DOE proof for the wildcard and the QName, so this should not be valid.
	proofVerified = nsec.PerformExpandedWildcardProof("test.example.com.")
	if proofVerified {
		t.Error("we expect the wildcard proof to not be valid")
	}

	//---

	nsec = NewDenialOfExistenceNSEC(context.Background(), zoneName, []*dns.NSEC{})

	// Should always be false if no signatures are set
	proofVerified = nsec.PerformExpandedWildcardProof("test.example.com.")
	if proofVerified {
		t.Error("we expect the wildcard proof to not be valid")
	}

}
