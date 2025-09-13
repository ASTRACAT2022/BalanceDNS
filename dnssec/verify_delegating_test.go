package dnssec

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"slices"
	"testing"
)

func TestVerify_DelegatingResponse(t *testing.T) {

	// When NS and DS records are passed, we get the DS record set in the result, and no DOE set.

	ds := newRR("example.com. 54775 IN DS 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A8 6764247C").(*dns.DS)

	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Ns: []dns.RR{
				ds,
				newRR("example.com. 3600 IN NS ns1.example.com."),
			},
		},
		authority: signatures{{
			rtype: dns.TypeDS,
			rrset: []dns.RR{ds},
		}},
	}

	state, err := validateDelegatingResponse(ctx, r)
	if err != nil {
		t.Errorf("validateDelegatingResponse returned unexpected error: %v", err)
	}
	if !slices.Equal(r.dsRecords, []*dns.DS{ds}) {
		t.Errorf("unexpected ds records set. expected %v, got %v", ds, r.dsRecords)
	}
	if r.denialOfExistence != NotFound {
		t.Errorf("unexpected denialOfExistence set. expected %v, got %v", NotFound, r.denialOfExistence)
	}
	if state != Secure {
		t.Errorf("unexpected state set. expected %v, got %v", Secure, state)
	}

	//---

	// If no DS or NSEC(3) records are set, we expect no DS records in the result, and a DOE state of NotFound.

	r = &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Ns: []dns.RR{
				newRR("example.com. 3600 IN NS ns1.example.com."),
			},
		},
	}

	state, err = validateDelegatingResponse(ctx, r)
	if !errors.Is(err, ErrBogusDoeRecordsNotFound) {
		t.Errorf("expecter error ErrBogusDoeRecordsNotFound, got: %v", err)
	}
	if len(r.dsRecords) != 0 {
		t.Errorf("unexpected ds records set. expected %v, got %v", 0, len(r.dsRecords))
	}
	if r.denialOfExistence != NotFound {
		t.Errorf("unexpected denialOfExistence set. expected %v, got %v", NotFound, r.denialOfExistence)
	}
	if state != Bogus {
		t.Errorf("unexpected state set. expected %v, got %v", Bogus, state)
	}

	//---

	// If the owner names of the NS records don't match, we expect an error.

	r = &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Ns: []dns.RR{
				newRR("example.com. 3600 IN NS ns1.example.com."),
				newRR("a.example.com. 3600 IN NS ns1.example.com."),
				newRR("example.com. 3600 IN NSEC \000.example.com. A RRSIG NSEC"),
			},
		},
	}

	state, err = validateDelegatingResponse(ctx, r)
	if !errors.Is(err, ErrNSRecordsHaveMismatchingOwners) {
		t.Errorf("expecter error ErrNSRecordsHaveMismatchingOwners, got: %v", err)
	}
	if state != Bogus {
		t.Errorf("unexpected state set. expected %v, got %v", Bogus, state)
	}

}

func TestVerify_DelegatingResponseNSEC(t *testing.T) {

	// Test with DS record missing, and NSEC providing DOE.

	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Ns: []dns.RR{
				newRR("example.com. 3600 IN NS ns1.example.com."),
				newRR("example.com. 3600 IN NS ns2.example.com."),
			},
		},
		authority: signatures{{
			rtype: dns.TypeNSEC,
			rrset: []dns.RR{
				newRR("example.com. 3600 IN NSEC \000.example.com. NS RRSIG NSEC"),
			},
		}},
	}

	// NSEC record including showing there are NS records, but no CNAME, DS or SOA records.

	state, err := validateDelegatingResponse(ctx, r)

	assert.NoError(t, err)
	assert.Equal(t, Secure, state)
	assert.Equal(t, NsecMissingDS, r.denialOfExistence)

	//---

	// We expect it to fail when the NS bit is not set in TypeBitMap.

	r.denialOfExistence = NotFound
	r.authority[0].rrset[0] = newRR("example.com. 3600 IN NSEC \000.example.com. RRSIG NSEC")

	state, err = validateDelegatingResponse(ctx, r)

	assert.ErrorIs(t, err, ErrBogusDoeRecordsNotFound)
	assert.Equal(t, Bogus, state)
	assert.Equal(t, NotFound, r.denialOfExistence)

	//---

	// We expect it to fail when the CNAME bit is set in TypeBitMap.

	r.denialOfExistence = NotFound
	r.authority[0].rrset[0] = newRR("example.com. 3600 IN NSEC \000.example.com. NS CNAME RRSIG NSEC")

	state, err = validateDelegatingResponse(ctx, r)

	assert.ErrorIs(t, err, ErrBogusDoeRecordsNotFound)
	assert.Equal(t, Bogus, state)
	assert.Equal(t, NotFound, r.denialOfExistence)

	//---

	// We expect it to fail when the DS bit is set in TypeBitMap.

	r.denialOfExistence = NotFound
	r.authority[0].rrset[0] = newRR("example.com. 3600 IN NSEC \000.example.com. NS DS RRSIG NSEC")

	state, err = validateDelegatingResponse(ctx, r)

	assert.ErrorIs(t, err, ErrBogusDoeRecordsNotFound)
	assert.Equal(t, Bogus, state)
	assert.Equal(t, NotFound, r.denialOfExistence)

	//---

	// We expect it to fail when the SOA bit is set in TypeBitMap.

	r.denialOfExistence = NotFound
	r.authority[0].rrset[0] = newRR("example.com. 3600 IN NSEC \000.example.com. NS SOA RRSIG NSEC")

	state, err = validateDelegatingResponse(ctx, r)

	assert.ErrorIs(t, err, ErrBogusDoeRecordsNotFound)
	assert.Equal(t, Bogus, state)
	assert.Equal(t, NotFound, r.denialOfExistence)

}

func TestVerify_DelegatingResponseNSEC3(t *testing.T) {
	// Test with DS record missing, and NSEC3 providing DOE.

	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Ns: []dns.RR{
				newRR("example.com. 3600 IN NS ns1.example.com."),
				newRR("example.com. 3600 IN NS ns2.example.com."),
			},
		},
		authority: signatures{{
			rtype: dns.TypeNSEC3,
			rrset: []dns.RR{
				// Matches `example.com.`
				newRR("111NOTAB271SNH4EA8ESDKBF1C2QINH1.example.com. 3600 IN NSEC3 1 0 2 ABCDEF 211NOTAB271SNH4EA8ESDKBF1C2QINH1 NS RRSIG"),
			},
		}},
	}

	// NSEC3 record, with no opt-out, showing there are NS records, but no CNAME, DS or SOA records.
	state, err := validateDelegatingResponse(ctx, r)

	assert.NoError(t, err)
	assert.Equal(t, Secure, state)
	assert.Equal(t, Nsec3MissingDS, r.denialOfExistence)

	//---

	// We expect it to fail when the NS bit is not set in TypeBitMap.

	r.denialOfExistence = NotFound
	r.authority[0].rrset[0] = newRR("111NOTAB271SNH4EA8ESDKBF1C2QINH1.example.com. 3600 IN NSEC3 1 0 2 ABCDEF 211NOTAB271SNH4EA8ESDKBF1C2QINH1 RRSIG")

	state, err = validateDelegatingResponse(ctx, r)

	assert.ErrorIs(t, err, ErrBogusDoeRecordsNotFound)
	assert.Equal(t, Bogus, state)
	assert.Equal(t, NotFound, r.denialOfExistence)

	//---

	// We expect it to fail when the CNAME bit is set in TypeBitMap.

	r.denialOfExistence = NotFound
	r.authority[0].rrset[0] = newRR("111NOTAB271SNH4EA8ESDKBF1C2QINH1.example.com. 3600 IN NSEC3 1 0 2 ABCDEF 211NOTAB271SNH4EA8ESDKBF1C2QINH1 NS CNAME RRSIG")

	state, err = validateDelegatingResponse(ctx, r)

	assert.ErrorIs(t, err, ErrBogusDoeRecordsNotFound)
	assert.Equal(t, Bogus, state)
	assert.Equal(t, NotFound, r.denialOfExistence)

	//---

	// We expect it to fail when the DS bit is set in TypeBitMap.

	r.denialOfExistence = NotFound
	r.authority[0].rrset[0] = newRR("111NOTAB271SNH4EA8ESDKBF1C2QINH1.example.com. 3600 IN NSEC3 1 0 2 ABCDEF 211NOTAB271SNH4EA8ESDKBF1C2QINH1 NS DS RRSIG")

	state, err = validateDelegatingResponse(ctx, r)

	assert.ErrorIs(t, err, ErrBogusDoeRecordsNotFound)
	assert.Equal(t, Bogus, state)
	assert.Equal(t, NotFound, r.denialOfExistence)

	//---

	// We expect it to fail when the SOA bit is set in TypeBitMap.

	r.denialOfExistence = NotFound
	r.authority[0].rrset[0] = newRR("111NOTAB271SNH4EA8ESDKBF1C2QINH1.example.com. 3600 IN NSEC3 1 0 2 ABCDEF 211NOTAB271SNH4EA8ESDKBF1C2QINH1 NS SOA RRSIG")

	state, err = validateDelegatingResponse(ctx, r)

	assert.ErrorIs(t, err, ErrBogusDoeRecordsNotFound)
	assert.Equal(t, Bogus, state)
	assert.Equal(t, NotFound, r.denialOfExistence)

}

func TestVerify_DelegatingResponseNSEC3Optout(t *testing.T) {

	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Ns: []dns.RR{
				newRR("test.example.com. 3600 IN NS ns1.example.com."),
				newRR("test.example.com. 3600 IN NS ns2.example.com."),
			},
		},
		authority: signatures{{
			rtype: dns.TypeNSEC3,
			rrset: []dns.RR{
				// Matches `example.com.`, (Closest Encloser)
				newRR("111NOTAB271SNH4EA8ESDKBF1C2QINH1.example.com. 3600 IN NSEC3 1 0 2 ABCDEF 211NOTAB271SNH4EA8ESDKBF1C2QINH1 NS SOA RRSIG"),
				// Covers `test.example.com.`. (Next Closer Name)
				// Note that we set the opt-out flag to 1.
				newRR("K72QU4B0R4USH96QN17VTCD8395QILEQ.example.com. 3600 IN NSEC3 1 1 2 ABCDEF M72QU4B0R4USH96QN17VTCD8395QILEQ A RRSIG"),
			},
		}},
	}

	// NSEC3 record covering the delegation name with an opt-out.
	state, err := validateDelegatingResponse(ctx, r)

	assert.NoError(t, err)
	assert.Equal(t, Secure, state)
	assert.Equal(t, Nsec3OptOut, r.denialOfExistence)
}
