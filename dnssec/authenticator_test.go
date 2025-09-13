package dnssec

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAuthenticator_AddNotSubdomain(t *testing.T) {

	q := dns.Question{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	a := NewAuth(context.Background(), q)

	err := a.AddResponse(&mockZone{name: "test.example.net."}, &dns.Msg{})
	assert.ErrorIs(t, err, ErrNotSubdomain, "as the TLD of the zone does not match the original qname")

	//---

	err = a.AddResponse(&mockZone{name: "example.com."}, &dns.Msg{
		Question: []dns.Question{{Name: "test.example.net.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
	)
	assert.ErrorIs(t, err, ErrNotSubdomain, "as the TLD of the response question does not match the original qname")

}

func TestAuthenticator_AddDuplicateInputForZone(t *testing.T) {

	q := dns.Question{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	a := NewAuth(context.Background(), q)

	err := a.AddResponse(&mockZone{name: "com."}, &dns.Msg{Question: []dns.Question{q}})
	assert.NoError(t, err)

	err = a.AddResponse(&mockZone{name: "example.com."}, &dns.Msg{Question: []dns.Question{q}})
	assert.NoError(t, err)

	err = a.AddResponse(&mockZone{name: "example.com."}, &dns.Msg{Question: []dns.Question{q}})
	assert.ErrorIs(t, err, ErrDuplicateInputForZone)

}

func TestAuthenticator_ProcessExpectedLastResult(t *testing.T) {

	q := dns.Question{Name: "a.b.c.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	a := NewAuth(context.Background(), q)
	a.results = append(a.results, &result{
		zone: &mockZone{name: "b.c.example.com."},
	})

	err := a.processResponse(&mockZone{name: "c.example.com."}, &dns.Msg{
		Question: []dns.Question{{Name: "c.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
	)

	// We're expecting an error here as the last result seen was from zone `b.c.example.com.`,
	// but we're now trying to add `c.example.com.`
	assert.ErrorIs(t, err, ErrNotSubdomain, "as this response should come before the last result in the chain")

	//---

	err = a.processResponse(&mockZone{name: "b.c.example.com."}, &dns.Msg{
		Question: []dns.Question{{Name: "b.c.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
	)
	assert.ErrorIs(t, err, ErrSameName, "as the zone names cannot be equal")

}

func TestAuthenticator_ProcessWithNoExpectedErrors(t *testing.T) {

	q := dns.Question{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	// Test secure with no error.

	a := NewAuth(context.Background(), q)
	a.verify = func(ctx context.Context, zone Zone, msg *dns.Msg, dsRecordsFromParent []*dns.DS) (AuthenticationResult, *result, error) {
		return Secure, &result{}, nil
	}

	err := a.processResponse(&mockZone{name: "example.com."}, &dns.Msg{
		Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
	)

	assert.NoError(t, err)
	assert.Len(t, a.results, 1)
	assert.NoError(t, a.results[0].err)
	assert.Equal(t, Secure, a.results[0].state)

	//---

	// Test Insecure with no error.

	a = NewAuth(context.Background(), q)
	a.verify = func(ctx context.Context, zone Zone, msg *dns.Msg, dsRecordsFromParent []*dns.DS) (AuthenticationResult, *result, error) {
		return Insecure, &result{}, nil
	}

	err = a.processResponse(&mockZone{name: "example.com."}, &dns.Msg{
		Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
	)
	assert.NoError(t, err)
	assert.Len(t, a.results, 1)
	assert.NoError(t, a.results[0].err)
	assert.Equal(t, Insecure, a.results[0].state)

	//---

	// If the state is unknown, we fail-safe to Bogus.

	a = NewAuth(context.Background(), q)
	a.verify = func(ctx context.Context, zone Zone, msg *dns.Msg, dsRecordsFromParent []*dns.DS) (AuthenticationResult, *result, error) {
		return Unknown, &result{}, nil
	}

	err = a.processResponse(&mockZone{name: "example.com."}, &dns.Msg{
		Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
	)
	assert.NoError(t, err)
	assert.Len(t, a.results, 1)
	assert.NoError(t, a.results[0].err)
	assert.Equal(t, Bogus, a.results[0].state)

}

func TestAuthenticator_ProcessWithExpectedErrors(t *testing.T) {
	q := dns.Question{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	// If an error is returned from verify, we expect it to be set on the result.

	expected := errors.New("mock error")

	a := NewAuth(context.Background(), q)
	a.verify = func(ctx context.Context, zone Zone, msg *dns.Msg, dsRecordsFromParent []*dns.DS) (AuthenticationResult, *result, error) {
		return Secure, &result{}, expected
	}

	err := a.processResponse(&mockZone{name: "example.com."}, &dns.Msg{
		Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
	)
	assert.NoError(t, err)
	assert.Len(t, a.results, 1)
	assert.ErrorIs(t, a.results[0].err, expected)
	assert.Equal(t, Secure, a.results[0].state)

	//---

	// If a nil result is returned, something unexpected has happened.

	a = NewAuth(context.Background(), q)
	a.verify = func(ctx context.Context, zone Zone, msg *dns.Msg, dsRecordsFromParent []*dns.DS) (AuthenticationResult, *result, error) {
		return Secure, nil, nil
	}

	err = a.processResponse(&mockZone{name: "example.com."}, &dns.Msg{
		Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
	)
	assert.ErrorIs(t, err, ErrUnknown)

}

func TestAuthenticator_MissingDSRecordError(t *testing.T) {

	// Here we test for detecting missing DS records.

	q := dns.Question{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	a := NewAuth(context.Background(), q)
	a.verify = func(ctx context.Context, zone Zone, msg *dns.Msg, dsRecordsFromParent []*dns.DS) (AuthenticationResult, *result, error) {
		return Secure, &result{}, nil
	}

	// We setup so the last DS records is for `example.com.`, thus we're expecting the next response to have a RRSIG with
	// a signerName of `example.com.`.

	r := result{
		zone: &mockZone{name: "com."},
		dsRecords: []*dns.DS{
			newRR("example.com. 54775 IN DS 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A8 6764247C").(*dns.DS),
		},
	}
	a.results = append(a.results, &r)

	//---

	// Unexpected next RRSIG - missmatch on signerName
	case1 := newRR("test.example.com. 955 IN RRSIG A 13 2 3600 20241102170341 20241012065317 19367 test.example.com. XMyTWC8y9WecF5ST67DyRUK3Ptvfpy/+Oetha9r6ZU0RJ4aclvY32uKCojUsjCUHaejma032va/7Z4Yd3Krq8Q==").(*dns.RRSIG)

	err := a.processResponse(&mockZone{name: "example.com."}, &dns.Msg{
		Question: []dns.Question{q},
		Answer:   []dns.RR{case1},
	})

	var missing *MissingDSRecordError
	assert.ErrorAs(t, err, &missing)
	if missing != nil {
		assert.Equal(t, "test.example.com.", missing.RName())
	}

	//---

	// Unexpected next RRSIG - signerName is not a subdomain of the question.
	case2 := newRR("test.example.com. 955 IN RRSIG A 13 2 3600 20241102170341 20241012065317 19367 example.net. XMyTWC8y9WecF5ST67DyRUK3Ptvfpy/+Oetha9r6ZU0RJ4aclvY32uKCojUsjCUHaejma032va/7Z4Yd3Krq8Q==").(*dns.RRSIG)

	err = a.processResponse(&mockZone{name: "example.com."}, &dns.Msg{
		Question: []dns.Question{q},
		Answer:   []dns.RR{case2},
	})
	assert.ErrorIs(t, err, ErrNotSubdomain)

	// Expected next RRSIG
	case3 := newRR("test.example.com. 955 IN RRSIG A 13 2 3600 20241102170341 20241012065317 19367 example.com. XMyTWC8y9WecF5ST67DyRUK3Ptvfpy/+Oetha9r6ZU0RJ4aclvY32uKCojUsjCUHaejma032va/7Z4Yd3Krq8Q==").(*dns.RRSIG)

	err = a.processResponse(&mockZone{name: "example.com."}, &dns.Msg{
		Question: []dns.Question{q},
		Answer:   []dns.RR{case3},
	})
	assert.NoError(t, err)
}
