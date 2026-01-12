package dnssec

import (
	"context"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerify_PositiveResponse(t *testing.T) {

	// I'll test on the assumption that a question for of example.com. DS was performed.

	ds := newRR("example.com. 54775 IN DS 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A8 6764247C").(*dns.DS)

	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Answer: []dns.RR{
				ds,
			},
		},
		answer: signatures{{
			rtype: dns.TypeDS,
			rrset: []dns.RR{ds},
		}},
	}

	state, err := validatePositiveResponse(ctx, r)
	assert.NoError(t, err)
	assert.Equal(t, Secure, state)
	assert.Equal(t, []*dns.DS{ds}, r.dsRecords)

}

func TestVerify_PositiveResponseMultipleWildcardSignatures(t *testing.T) {

	// If more than one Signature represents a wildcard, we get an error

	a1 := newRR("a1.example.com. 3600 IN A 192.0.2.53").(*dns.A)
	a2 := newRR("a2.example.com. 3600 IN A 192.0.2.53").(*dns.A)

	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Answer: []dns.RR{
				a1,
				a2,
			},
		},
		answer: signatures{
			{
				rtype:    dns.TypeA,
				rrset:    []dns.RR{a1},
				wildcard: true,
			},
			{
				rtype:    dns.TypeA,
				rrset:    []dns.RR{a2},
				wildcard: true,
			},
		},
	}

	state, err := validatePositiveResponse(ctx, r)
	assert.ErrorIs(t, err, ErrMultipleWildcardSignatures)
	assert.Equal(t, Bogus, state)
	assert.Empty(t, r.dsRecords)
}

func TestVerify_PositiveResponseNSEC(t *testing.T) {

	// Assumes the result was synthesised from a wildcard, and we have a NSEC record proving the QNAME does not exist.
	// i.e. the record matched is `*.example.com`

	a := newRR("test.example.com. 3600 IN A 192.0.2.53").(*dns.A)

	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		},
		answer: signatures{
			{
				rtype:    dns.TypeA,
				rrset:    []dns.RR{a},
				wildcard: true,
			},
		},
	}

	// First we test without the nsec record. We expect a Bogus result.

	state, err := validatePositiveResponse(ctx, r)
	assert.ErrorIs(t, err, ErrBogusWildcardDoeNotFound)
	assert.Equal(t, Bogus, state)
	assert.Empty(t, r.dsRecords)

	//---

	// Covers `test.example.com.`.
	nsec := newRR("s.example.com. 3600 IN NSEC u.example.com. A RRSIG NSEC").(*dns.NSEC)

	// With the NSEC record, it should now be valid.

	r.authority = signatures{{
		rtype: dns.TypeNSEC,
		rrset: []dns.RR{nsec},
	}}

	state, err = validatePositiveResponse(ctx, r)
	assert.NoError(t, err)
	assert.Equal(t, Secure, state)
	assert.Equal(t, NsecWildcard, r.denialOfExistence)

}

func TestVerify_PositiveResponseNSEC3(t *testing.T) {

	// Assumes the result was synthesised from a wildcard, and we have a NSEC3 record proving the QNAME does not exist.
	// i.e. the record matched is `*.example.com`

	a := newRR("test.example.com. 3600 IN A 192.0.2.53").(*dns.A)

	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		},
		answer: signatures{
			{
				name:     a.Header().Name,
				rtype:    dns.TypeA,
				rrset:    []dns.RR{a},
				wildcard: true,
				rrsig: &dns.RRSIG{
					Labels: 2, // The number of labels is needed for the NSEC3 Wildcard proof.
				},
			},
		},
	}

	// First we test without the nsec record. We expect a Bogus result.

	state, err := validatePositiveResponse(ctx, r)
	assert.ErrorIs(t, err, ErrBogusWildcardDoeNotFound)
	assert.Equal(t, Bogus, state)
	assert.Empty(t, r.dsRecords)

	//---

	// THen with a NSEC3 record, everything is fine.

	// Covers `test.example.com.`.
	nsec3 := newRR("K72QU4B0R4USH96QN17VTCD8395QILEQ.example.com. 3600 IN NSEC3 1 0 2 ABCDEF M72QU4B0R4USH96QN17VTCD8395QILEQ A RRSIG").(*dns.NSEC3)

	// With the NSEC record, it should now be valid.

	r.authority = signatures{{
		rtype: dns.TypeNSEC3,
		rrset: []dns.RR{nsec3},
	}}

	state, err = validatePositiveResponse(ctx, r)
	assert.NoError(t, err)
	assert.Equal(t, Secure, state)
	assert.Equal(t, Nsec3Wildcard, r.denialOfExistence)

}
