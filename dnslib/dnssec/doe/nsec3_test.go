package doe

import (
	"context"
	"github.com/miekg/dns"
	"slices"
	"testing"
)

type testNsec3RRSets struct {
	closestEncloser []*dns.NSEC3
	nextCloserName  []*dns.NSEC3
	wildcardCovers  []*dns.NSEC3
	wildcardMatches []*dns.NSEC3
	qnameMatches    []*dns.NSEC3
}

func getTestNsec3RRSets() testNsec3RRSets {
	/*
		hash(example.com.) = 111NOTAB271SNH4EA8ESDKBF1C2QINH1
		hash(*.example.com.) = 3MFPR9I7C49K59BM8VU2HM71CCR7BH0B
		hash(test.example.com.) = L72QU4B0R4USH96QN17VTCD8395QILEQ

		Generated with:
		digest := dns.HashName(domain, dns.SHA1, uint16(2), "abcdef")
	*/

	r := testNsec3RRSets{}

	// The ClosestEncloser
	r.closestEncloser = []*dns.NSEC3{
		// example.com (apex)
		newRR("111NOTAB271SNH4EA8ESDKBF1C2QINH1.example.com. 3600 IN NSEC3 1 0 2 ABCDEF 211NOTAB271SNH4EA8ESDKBF1C2QINH1 SOA RRSIG").(*dns.NSEC3),
	}

	// The Next Closer name
	r.nextCloserName = []*dns.NSEC3{
		// test. == L72QU4B0R4USH96QN17VTCD8395QILEQ
		// So we need two hashes that cover that hash.
		newRR("K72QU4B0R4USH96QN17VTCD8395QILEQ.example.com. 3600 IN NSEC3 1 0 2 ABCDEF M72QU4B0R4USH96QN17VTCD8395QILEQ A RRSIG").(*dns.NSEC3),
	}

	// The Wildcard (cover)
	r.wildcardCovers = []*dns.NSEC3{
		// *. == 3MFPR9I7C49K59BM8VU2HM71CCR7BH0B
		// So we need two hashes that cover that hash.
		newRR("2MFPR9I7C49K59BM8VU2HM71CCR7BH0B.example.com. 3600 IN NSEC3 1 0 2 ABCDEF 4MFPR9I7C49K59BM8VU2HM71CCR7BH0B A RRSIG").(*dns.NSEC3),
	}

	// The Wildcard (match)
	r.wildcardMatches = []*dns.NSEC3{
		// *.example.com
		newRR("3MFPR9I7C49K59BM8VU2HM71CCR7BH0B.example.com. 3600 IN NSEC3 1 0 2 ABCDEF 3NFPR9I7C49K59BM8VU2HM71CCR7BH0B A RRSIG").(*dns.NSEC3),
	}

	// The QName (match)
	r.qnameMatches = []*dns.NSEC3{
		// test.example.com
		newRR("L72QU4B0R4USH96QN17VTCD8395QILEQ.example.com. 3600 IN NSEC3 1 0 2 ABCDEF T0B6SHHJ0JQRI032RVVLMCGGNHCVF5UM A RRSIG").(*dns.NSEC3),
	}

	return r
}

func TestDenialOfExistenceNSEC3_BitMap(t *testing.T) {

	// NSEC3: Hash Algorithm, Flags (optout), Iterations, Salt Length, Salt, Next Hashed Owner name, Type Bit Maps

	rrset := []*dns.NSEC3{
		// test.example.com
		newRR("L72QU4B0R4USH96QN17VTCD8395QILEQ.example.com. 3600 IN NSEC3 1 0 2 ABCDEF T0B6SHHJ0JQRI032RVVLMCGGNHCVF5UM A RRSIG").(*dns.NSEC3),
	}

	nsec3 := NewDenialOfExistenceNSEC3(context.Background(), zoneName, rrset)

	nameSeen, typeSeen := nsec3.TypeBitMapContainsAnyOf("test.example.com.", []uint16{dns.TypeA})
	if !nameSeen || !typeSeen {
		t.Error("we expect both the name and type to be seen")
	}

	nameSeen, typeSeen = nsec3.TypeBitMapContainsAnyOf("test.example.com.", []uint16{dns.TypeAAAA})
	if !nameSeen || typeSeen {
		t.Error("we expect the name to be seen, but not the type")
	}

	nameSeen, typeSeen = nsec3.TypeBitMapContainsAnyOf("other.example.com.", []uint16{dns.TypeA})
	if nameSeen || typeSeen {
		// Note that we only expect a type to be seen if the name is also seen.
		// i.e. we only inspect a NSEC3 record's BitMap if it matches the name.
		t.Error("we expect neither the name or type to be seen")
	}

}

func TestDenialOfExistenceNSEC3_ClosestEncloserProof(t *testing.T) {

	r := getTestNsec3RRSets()

	nsec3 := NewDenialOfExistenceNSEC3(context.Background(), zoneName, slices.Concat(r.closestEncloser, r.nextCloserName, r.wildcardCovers))

	// We expect no optout, and the other three proofs should be true.
	optedOut, closestEncloserProof, nextCloserNameProof, wildcardProof := nsec3.PerformClosestEncloserProof("test.example.com.")
	if optedOut || !closestEncloserProof || !nextCloserNameProof || !wildcardProof {
		t.Error("we expected all 3 proofs to be met")
	}

	//---

	nsec3 = NewDenialOfExistenceNSEC3(context.Background(), zoneName, slices.Concat(r.closestEncloser, r.nextCloserName, r.wildcardCovers, r.qnameMatches))

	optedOut, closestEncloserProof, nextCloserNameProof, wildcardProof = nsec3.PerformClosestEncloserProof("test.example.com.")
	if optedOut || !closestEncloserProof || nextCloserNameProof || !wildcardProof {
		t.Error("if a nsec3 record was found to match the qname, we expect the nextCloserName proof to fail")
	}

	//---

	nsec3 = NewDenialOfExistenceNSEC3(context.Background(), zoneName, slices.Concat(r.closestEncloser, r.nextCloserName, r.wildcardCovers, r.wildcardMatches))

	optedOut, closestEncloserProof, nextCloserNameProof, wildcardProof = nsec3.PerformClosestEncloserProof("test.example.com.")
	if optedOut || !closestEncloserProof || !nextCloserNameProof || wildcardProof {
		t.Error("if a nsec3 record was found to match the wildcard, we expect the wildcardProof proof to fail")
	}

	//---

	nsec3 = NewDenialOfExistenceNSEC3(context.Background(), zoneName, slices.Concat(r.closestEncloser, r.nextCloserName))

	optedOut, closestEncloserProof, nextCloserNameProof, wildcardProof = nsec3.PerformClosestEncloserProof("test.example.com.")
	if optedOut || !closestEncloserProof || !nextCloserNameProof || wildcardProof {
		t.Error("we expected this to fail on the wildcard proof")
	}

	//---

	nsec3 = NewDenialOfExistenceNSEC3(context.Background(), zoneName, slices.Concat(r.closestEncloser, r.wildcardCovers))

	optedOut, closestEncloserProof, nextCloserNameProof, wildcardProof = nsec3.PerformClosestEncloserProof("test.example.com.")
	if optedOut || !closestEncloserProof || nextCloserNameProof || !wildcardProof {
		t.Error("we expected this to fail on the next closer name proof")
	}

	//---

	nsec3 = NewDenialOfExistenceNSEC3(context.Background(), zoneName, slices.Concat(r.nextCloserName, r.wildcardCovers))

	optedOut, closestEncloserProof, nextCloserNameProof, wildcardProof = nsec3.PerformClosestEncloserProof("test.example.com.")
	if optedOut || closestEncloserProof || nextCloserNameProof || wildcardProof {
		t.Error("when the closest enclose proof is not met, we expect everything to be false")
	}

	//---

	//set = make(signatures, 0)
	nsec3 = NewDenialOfExistenceNSEC3(context.Background(), zoneName, []*dns.NSEC3{})

	optedOut, closestEncloserProof, nextCloserNameProof, wildcardProof = nsec3.PerformClosestEncloserProof("test.example.com.")
	if optedOut || closestEncloserProof || nextCloserNameProof || wildcardProof {
		t.Error("when not signatures are set, we expect everything to be false")
	}

}

func TestDenialOfExistenceNSEC3_WildcardProof(t *testing.T) {

	r := getTestNsec3RRSets()

	// Tests assume this result is synthesised from `*.example.com.`

	//---

	nsec3 := NewDenialOfExistenceNSEC3(context.Background(), zoneName, r.nextCloserName)

	// The first set contains the wildcard signature
	verified := nsec3.PerformExpandedWildcardProof("test.example.com.", 2)
	if !verified {
		t.Error("we expected this to be valid as there's doe for the next closer name, but not the wildcard")
	}

	//---

	nsec3 = NewDenialOfExistenceNSEC3(context.Background(), zoneName, r.closestEncloser)

	// The first set contains the wildcard signature
	verified = nsec3.PerformExpandedWildcardProof("test.example.com.", 2)
	if verified {
		t.Error("we expect this to fail as there's no next closer name")
	}

	//---

	nsec3 = NewDenialOfExistenceNSEC3(context.Background(), zoneName, slices.Concat(r.nextCloserName, r.wildcardCovers))

	// The first set contains the wildcard signature
	verified = nsec3.PerformExpandedWildcardProof("test.example.com.", 2)
	if verified {
		t.Error("we expect this to fail as there's doe for the wildcard (covered) record")
	}

	//---

	nsec3 = NewDenialOfExistenceNSEC3(context.Background(), zoneName, slices.Concat(r.nextCloserName, r.wildcardMatches))

	// The first set contains the wildcard signature
	verified = nsec3.PerformExpandedWildcardProof("test.example.com.", 2)
	if verified {
		t.Error("we expect this to fail as there's doe for the wildcard (matched) record")
	}

	//---

	nsec3 = NewDenialOfExistenceNSEC3(context.Background(), zoneName, slices.Concat(r.qnameMatches))

	// The first set contains the wildcard signature
	verified = nsec3.PerformExpandedWildcardProof("test.example.com.", 2)
	if verified {
		t.Error("we expect this to fail as there's doe for the qname, so the wildcard should not have been expanded")
	}
}

func TestDenialOfExistenceNSEC3_Optout(t *testing.T) {

	// NSEC3: Hash Algorithm, Flags (optout), Iterations, Salt Length, Salt, Next Hashed Owner name, Type Bit Maps

	// We set the OptOut flag to 1 on the below.

	// The ClosestEncloser
	closestEncloser := []*dns.NSEC3{
		// example.com (apex)
		newRR("111NOTAB271SNH4EA8ESDKBF1C2QINH1.example.com. 3600 IN NSEC3 1 1 2 ABCDEF 211NOTAB271SNH4EA8ESDKBF1C2QINH1 SOA RRSIG").(*dns.NSEC3),
	}

	// Covers `test.`
	nextCloserName := []*dns.NSEC3{
		// test. == L72QU4B0R4USH96QN17VTCD8395QILEQ
		// So we need two hashes that cover that hash.
		newRR("K72QU4B0R4USH96QN17VTCD8395QILEQ.example.com. 3600 IN NSEC3 1 1 2 ABCDEF M72QU4B0R4USH96QN17VTCD8395QILEQ A RRSIG").(*dns.NSEC3),
	}

	nsec3 := NewDenialOfExistenceNSEC3(context.Background(), zoneName, slices.Concat(nextCloserName, closestEncloser))

	optedOut, _, _, _ := nsec3.PerformClosestEncloserProof("test.example.com.")
	if !optedOut {
		t.Error("we expect the proof to to state that they're opted-out")
	}

}

func TestDenialOfExistenceNSEC3_InvalidValues(t *testing.T) {

	// NSEC3 records that have an invalid hash value, or an invalid Flags field, must be ignored.

	// NSEC3: Hash Algorithm, Flags (optout), Iterations, Salt Length, Salt, Next Hashed Owner name, Type Bit Maps

	// The only allowed Hash Algorithm value is 1. Here we change it to 5.
	closestEncloser := []*dns.NSEC3{
		// example.com (apex)
		newRR("111NOTAB271SNH4EA8ESDKBF1C2QINH1.example.com. 3600 IN NSEC3 5 0 2 ABCDEF 211NOTAB271SNH4EA8ESDKBF1C2QINH1 SOA RRSIG").(*dns.NSEC3),
	}

	// The only allowed Flags values are 0 or 1. Here we change it to 5. Note that we've already tested 0 and 1 o other tests.
	nextCloserName := []*dns.NSEC3{
		// test. == L72QU4B0R4USH96QN17VTCD8395QILEQ
		// So we need two hashes that cover that hash.
		newRR("K72QU4B0R4USH96QN17VTCD8395QILEQ.example.com. 3600 IN NSEC3 1 5 2 ABCDEF M72QU4B0R4USH96QN17VTCD8395QILEQ A RRSIG").(*dns.NSEC3),
	}

	nsec3 := NewDenialOfExistenceNSEC3(context.Background(), zoneName, slices.Concat(nextCloserName, closestEncloser))

	if !nsec3.Empty() {
		t.Error("we expect there to be no nsec3 records to check as both that were passed should be ignored")
	}

	// We've tested in previous tests that proofs fail if nsec3.empty() is true.
}
