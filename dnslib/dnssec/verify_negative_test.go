package dnssec

import (
	"context"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerify_NegativeResponse(t *testing.T) {

	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		},
	}

	// With no NSEC(3) records set, we expect Bogus.

	state, err := validateNegativeResponse(ctx, r)
	assert.ErrorIs(t, err, ErrBogusDoeRecordsNotFound)
	assert.Equal(t, Bogus, state)
	assert.Equal(t, NotFound, r.denialOfExistence)

}

func TestVerify_NegativeResponseNSECNoData(t *testing.T) {

	// Matches `test.example.com.`.
	nsec := newRR("test.example.com. 3600 IN NSEC u.example.com. MX RRSIG NSEC").(*dns.NSEC)

	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		},
		authority: signatures{{
			rtype: dns.TypeNSEC,
			rrset: []dns.RR{nsec},
		}},
	}

	// QName matches the NSEC owner, but the QType is not included in the BitMap. Thus NODATA / Secure.

	state, err := validateNegativeResponse(ctx, r)
	assert.NoError(t, err)
	assert.Equal(t, Secure, state)
	assert.Equal(t, NsecNoData, r.denialOfExistence)

}

func TestVerify_NegativeResponseNSECNxDomain(t *testing.T) {

	// Covers `*.example.com.`.
	nsec1 := newRR("example.com. 3600 IN NSEC c.example.com. NS SOA").(*dns.NSEC)

	// Covers `test.example.com.`.
	nsec2 := newRR("s.example.com. 3600 IN NSEC u.example.com. A RRSIG NSEC").(*dns.NSEC)

	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		},
		authority: signatures{{
			rtype: dns.TypeNSEC,
			rrset: []dns.RR{nsec1},
		}, {
			rtype: dns.TypeNSEC,
			rrset: []dns.RR{nsec2},
		}},
	}

	// QName matches the NSEC owner, but the QType is not included in the BitMap. Thus NODATA / Secure.

	state, err := validateNegativeResponse(ctx, r)
	assert.NoError(t, err)
	assert.Equal(t, Secure, state)
	assert.Equal(t, NsecNxDomain, r.denialOfExistence)

}

func TestVerify_NegativeResponseNSEC3NoData(t *testing.T) {

	// Matches `test.example.com.`.
	nsec3 := newRR("L72QU4B0R4USH96QN17VTCD8395QILEQ.example.com. 3600 IN NSEC3 1 0 2 ABCDEF T0B6SHHJ0JQRI032RVVLMCGGNHCVF5UM MX RRSIG").(*dns.NSEC3)

	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		},
		authority: signatures{{
			rtype: dns.TypeNSEC3,
			rrset: []dns.RR{nsec3},
		}},
	}

	// QName matches the NSEC3 owner, but the QType is not included in the BitMap. Thus NODATA / Secure.

	state, err := validateNegativeResponse(ctx, r)
	assert.NoError(t, err)
	assert.Equal(t, Secure, state)
	assert.Equal(t, Nsec3NoData, r.denialOfExistence)

}

func TestVerify_NegativeResponseNSEC3NxDomain(t *testing.T) {

	// Matches `example.com.`.
	nsec3a := newRR("111NOTAB271SNH4EA8ESDKBF1C2QINH1.example.com. 3600 IN NSEC3 1 0 2 ABCDEF 211NOTAB271SNH4EA8ESDKBF1C2QINH1 SOA RRSIG")

	// Covers `test.example.com.`.
	nsec3b := newRR("K72QU4B0R4USH96QN17VTCD8395QILEQ.example.com. 3600 IN NSEC3 1 0 2 ABCDEF M72QU4B0R4USH96QN17VTCD8395QILEQ A RRSIG")

	// Covers `*.example.com.`.
	nsec3c := newRR("2MFPR9I7C49K59BM8VU2HM71CCR7BH0B.example.com. 3600 IN NSEC3 1 0 2 ABCDEF 4MFPR9I7C49K59BM8VU2HM71CCR7BH0B A RRSIG")

	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		},
		authority: signatures{{
			rtype: dns.TypeNSEC3,
			rrset: []dns.RR{nsec3a},
		}, {
			rtype: dns.TypeNSEC3,
			rrset: []dns.RR{nsec3b},
		}, {
			rtype: dns.TypeNSEC3,
			rrset: []dns.RR{nsec3c},
		}},
	}

	// QName matches the NSEC owner, but the QType is not included in the BitMap. Thus NODATA / Secure.

	state, err := validateNegativeResponse(ctx, r)
	assert.NoError(t, err)
	assert.Equal(t, Secure, state)
	assert.Equal(t, Nsec3NxDomain, r.denialOfExistence)

}

func TestVerify_NegativeResponseNSEC3NxDomainWildcard(t *testing.T) {

	// Matches `example.com.`.
	nsec3a := newRR("111NOTAB271SNH4EA8ESDKBF1C2QINH1.example.com. 3600 IN NSEC3 1 0 2 ABCDEF 211NOTAB271SNH4EA8ESDKBF1C2QINH1 SOA RRSIG")

	// Matches `*.example.com.`.
	nsec3b := newRR("3MFPR9I7C49K59BM8VU2HM71CCR7BH0B.example.com. 3600 IN NSEC3 1 0 2 ABCDEF 3NFPR9I7C49K59BM8VU2HM71CCR7BH0B TXT RRSIG")

	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		},
		authority: signatures{{
			rtype: dns.TypeNSEC3,
			rrset: []dns.RR{nsec3a},
		}, {
			rtype: dns.TypeNSEC3,
			rrset: []dns.RR{nsec3b},
		}},
	}

	// A match on the wildcard, but nothing covering the QName, should be Bogus.

	state, err := validateNegativeResponse(ctx, r)
	assert.ErrorIs(t, err, ErrBogusDoeRecordsNotFound)
	assert.Equal(t, Bogus, state)
	assert.Equal(t, NotFound, r.denialOfExistence)

	//---

	// Covers `test.example.com.`.
	nsec3c := newRR("K72QU4B0R4USH96QN17VTCD8395QILEQ.example.com. 3600 IN NSEC3 1 0 2 ABCDEF M72QU4B0R4USH96QN17VTCD8395QILEQ A RRSIG")

	r = &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		},
		authority: signatures{{
			rtype: dns.TypeNSEC3,
			rrset: []dns.RR{nsec3a},
		}, {
			rtype: dns.TypeNSEC3,
			rrset: []dns.RR{nsec3b},
		}, {
			rtype: dns.TypeNSEC3,
			rrset: []dns.RR{nsec3c},
		}},
	}

	state, err = validateNegativeResponse(ctx, r)
	assert.NoError(t, err)
	assert.Equal(t, Secure, state)
	assert.Equal(t, Nsec3NxDomain, r.denialOfExistence)
}
