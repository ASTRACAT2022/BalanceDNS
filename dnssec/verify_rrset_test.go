package dnssec

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"testing"
)

func TestVerify_RRSETs(t *testing.T) {

	// Tests verifyRRSETs(). This method:
	//	- Checks any RRSigs in the Answer section are valid.
	//	- Checks any RRSigs in the Authority section are valid.
	//	- If we're at this function, we're expecting the response to be signed. Thus if neither section containers
	//		valid signatures, we conclude Bogus.

	key := testEcKey()
	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Answer: []dns.RR{},
			Ns:     []dns.RR{},
		},
	}

	keys := []*dns.DNSKEY{key.key}

	// With no signatures passed, we expect a Bogus result, with ErrSignatureSetEmpty.

	state, err := verifyRRSETs(ctx, r, keys)
	if !errors.Is(err, ErrBogusResultFound) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrBogusResultFound, got %v", err)
	}
	if !errors.Is(err, ErrSignatureSetEmpty) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrSignatureSetEmpty, got %v", err)
	}
	if state != Bogus {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Bogus, state)
	}

	//---

	// When we have a signed Answer, then we expect Unknown back.

	rrset := []dns.RR{
		newRR("ns1.example.com. 3600 IN A 192.0.2.53"),
	}

	rrset = append(rrset, key.sign(rrset, 0, 0))
	r.msg.Answer = rrset
	state, err = verifyRRSETs(ctx, r, keys)
	if err != nil {
		t.Errorf("verifyRRSETs returned unexpected error: %v", err)
	}
	if state != Unknown {
		t.Errorf("verifyRRSETs returned incorrect state. expected %v, got %v", Unknown, state)
	}
	if len(r.answer) != 1 {
		t.Errorf("expected 1 answer signature, got %d", len(r.answer))
	}

	//---

	// When we have a signed Authority, then we expect Unknown back.

	r.msg.Answer = []dns.RR{}
	r.msg.Ns = rrset

	state, err = verifyRRSETs(ctx, r, keys)
	if err != nil {
		t.Errorf("verifyRRSETs returned unexpected error: %v", err)
	}
	if state != Unknown {
		t.Errorf("verifyRRSETs returned incorrect state. expected %v, got %v", Unknown, state)
	}
	if len(r.authority) != 1 {
		t.Errorf("expected 1 authority signature, got %d", len(r.authority))
	}

	//---

	// When the Answer signature is invalid, we expect Bogus back.

	rrset[1].(*dns.RRSIG).Labels = 0

	r.msg.Answer = rrset
	r.msg.Ns = []dns.RR{}

	state, err = verifyRRSETs(ctx, r, keys)
	if !errors.Is(err, ErrBogusResultFound) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrBogusResultFound, got %v", err)
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrInvalidSignature, got %v", err)
	}
	if state != Bogus {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Bogus, state)
	}

	//---

	// When the Authority signature is invalid, we expect Bogus back.

	r.msg.Answer = []dns.RR{}
	r.msg.Ns = rrset

	state, err = verifyRRSETs(ctx, r, keys)
	if !errors.Is(err, ErrBogusResultFound) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrBogusResultFound, got %v", err)
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrInvalidSignature, got %v", err)
	}
	if state != Bogus {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Bogus, state)
	}

	//---

	// When the Answer section containers records, but they're not signed, we expect Bogus

	r.msg.Answer = []dns.RR{rrset[0]}
	r.msg.Ns = []dns.RR{}

	state, err = verifyRRSETs(ctx, r, keys)
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

	// When the Authority section containers records, but they're not signed, we expect Bogus

	r.msg.Answer = []dns.RR{}
	r.msg.Ns = []dns.RR{rrset[0]}

	state, err = verifyRRSETs(ctx, r, keys)
	if !errors.Is(err, ErrBogusResultFound) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrBogusResultFound, got %v", err)
	}
	if !errors.Is(err, ErrUnexpectedSignatureCount) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrUnexpectedSignatureCount, got %v", err)
	}
	if state != Bogus {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Bogus, state)
	}

}
