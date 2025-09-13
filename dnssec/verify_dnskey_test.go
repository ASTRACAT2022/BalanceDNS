package dnssec

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"testing"
)

func TestVerify_DNSKEYs(t *testing.T) {

	// Tests verifyDNSKEYs(). This method:
	//	- Checks we have one or more DNSKEYs, with an aligning Delegation Signer.
	//	- If yes, we check that the DNSKEY RRSet is signed by one of these keys.

	k := testEcKey()

	// When no zone keys are passed, the answer must be insecure.

	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
	}
	keys := []dns.RR{}
	dsRecordsFromParent := []*dns.DS{}

	state, err := verifyDNSKEYs(ctx, r, keys, dsRecordsFromParent)
	if err == nil {
		t.Errorf("verifyDNSKEYs returned no error. expected ErrKeysNotFound")
	}
	if state != Insecure {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Insecure, state)
	}

	//---

	// If keys are passed in, but none of them have an associated DS record from the parent, the answer must be insecure.

	keys = []dns.RR{k.key}

	// This DS record does not match the key.
	dsRecordsFromParent = []*dns.DS{
		newRR("example.com. 54775 IN DS 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A8 6764247C").(*dns.DS),
	}

	state, err = verifyDNSKEYs(ctx, r, keys, dsRecordsFromParent)
	if err == nil {
		t.Errorf("verifyDNSKEYs returned no error. expected ErrKeysNotFound")
	}
	if state != Insecure {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Insecure, state)
	}

	//---

	// We'll pass in a valid DNSKEY/DS pair, but without any RRSIG. We therefore expect authentication to fail.

	// DS record is now correct
	dsRecordsFromParent = []*dns.DS{k.ds}

	// This should now be valid
	state, err = verifyDNSKEYs(ctx, r, keys, dsRecordsFromParent)
	if !errors.Is(err, ErrBogusResultFound) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrBogusResultFound, got %v", err)
	}
	if !errors.Is(err, ErrUnexpectedSignatureCount) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrUnexpectedSignatureCount, got %v", err)
	}
	if state != Bogus {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Bogus, state)
	}

	//---

	// We'll sign the key now, so we expect the result to be valid...

	keys = append(keys, k.sign(keys, 0, 0))

	// This should now be valid
	state, err = verifyDNSKEYs(ctx, r, keys, dsRecordsFromParent)
	if err != nil {
		t.Errorf("verifyDNSKEYs returned unexpected error: %v", err)
	}
	if state != Unknown {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Unknown, state)
	}
	if len(r.keys) != 1 {
		t.Errorf("verifyDNSKEYs returned incorrect number of keys. expected 1, got %v", len(r.keys))
	}

	//---

	// If we "break" the signature, it should revert back to being Bogus.
	keys[1].(*dns.RRSIG).Labels = 0

	// This should now be valid
	state, err = verifyDNSKEYs(ctx, r, keys, dsRecordsFromParent)
	if !errors.Is(err, ErrBogusResultFound) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrBogusResultFound, got %v", err)
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrInvalidSignature, got %v", err)
	}
	if state != Bogus {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Bogus, state)
	}

}
