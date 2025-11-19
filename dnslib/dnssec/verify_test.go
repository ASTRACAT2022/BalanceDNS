package dnssec

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"testing"
)

var initErr = errors.New("init error")
var testErr = errors.New("test error")

// We'll use a unique state so we can ensure it's coming from a mock.
const initState = AuthenticationResult(^uint8(0) - 1)
const testState = AuthenticationResult(^uint8(0))

func getVerifier() verifier {
	return verifier{
		verifyDNSKEYs: func(ctx context.Context, r *result, keys []dns.RR, dsRecordsFromParent []*dns.DS) (AuthenticationResult, error) {
			return initState, initErr
		},
		verifyRRSETs: func(ctx context.Context, r *result, keys []*dns.DNSKEY) (AuthenticationResult, error) {
			return initState, initErr
		},
		validateDelegatingResponse: func(ctx context.Context, r *result) (AuthenticationResult, error) {
			return initState, initErr
		},
		validatePositiveResponse: func(ctx context.Context, r *result) (AuthenticationResult, error) {
			return initState, initErr
		},
		validateNegativeResponse: func(ctx context.Context, r *result) (AuthenticationResult, error) {
			return initState, initErr
		},
	}
}

func getVerifierWithKeyAndSetResponses() verifier {
	v := getVerifier()

	v.verifyDNSKEYs = func(ctx context.Context, r *result, keys []dns.RR, dsRecordsFromParent []*dns.DS) (AuthenticationResult, error) {
		return Unknown, nil
	}

	v.verifyRRSETs = func(ctx context.Context, r *result, keys []*dns.DNSKEY) (AuthenticationResult, error) {
		return Unknown, nil
	}

	return v
}

func TestVerify_VerifyNoDSRecords(t *testing.T) {

	ctx := context.Background()
	zone := &mockZone{name: zoneName}
	msg := &dns.Msg{}
	ds := make([]*dns.DS, 0)

	// When no parent DS records are passed, it's always Insecure.
	// Note that it's not an error, as we don't assume here that we expected DS records. That's checked in Result().

	state, r, err := getVerifier().verify(ctx, zone, msg, ds)
	assert.NoError(t, err)
	assert.NotNil(t, r)
	assert.Equal(t, Insecure, state)

}

func TestVerify_VerifyGetDNSKEYRecords(t *testing.T) {

	ctx := context.Background()
	v := getVerifier()
	zone := &mockZone{name: zoneName}
	msg := &dns.Msg{}

	ds := newRR("example.com. 300 IN DS 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A8 6764247C").(*dns.DS)
	dsSet := []*dns.DS{ds}

	// Mock GetDNSKEYRecords() returning this error
	zone.err = errors.New("test error")

	state, r, err := v.verify(ctx, zone, msg, dsSet)
	assert.ErrorIs(t, err, zone.err)
	assert.NotNil(t, r)
	assert.Equal(t, Bogus, state)

	//---

	// When there's no error, we expect the keys returned, plus the DS records, to be passed to verifyDNSKEYs().

	// Set error back to nil
	zone.err = nil

	// Mock GetDNSKEYRecords() returning this rrset
	k := newRR("example.com. 300 IN DNSKEY 257 3 13 kXKkvWU3vGYfTJGl3qBd4qhiWp5aRs7YtkCJxD2d+t7KXqwahww5IgJtxJT2yFItlggazyfXqJEVOmMJ3qT0tQ==").(*dns.DNSKEY)
	zone.set = []dns.RR{k}

	var keysSeen []dns.RR
	var dsRecordsFromParentSeen []*dns.DS
	v.verifyDNSKEYs = func(ctx context.Context, r *result, keys []dns.RR, dsRecordsFromParent []*dns.DS) (AuthenticationResult, error) {
		keysSeen = keys
		dsRecordsFromParentSeen = dsRecordsFromParent
		return testState, testErr
	}

	_, _, _ = v.verify(ctx, zone, msg, dsSet)
	assert.Equal(t, []dns.RR{k}, keysSeen)
	assert.Equal(t, dsSet, dsRecordsFromParentSeen)
}

func TestVerify_VerifyDNSKEYsAndRRSETs(t *testing.T) {

	ctx := context.Background()
	v := getVerifier()
	zone := &mockZone{name: zoneName}
	msg := &dns.Msg{}
	dsSet := []*dns.DS{newRR("example.com. 300 IN DS 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A8 6764247C").(*dns.DS)}

	// Test that when a state other than Unknown is, that state should be returned to us.
	v.verifyDNSKEYs = func(ctx context.Context, r *result, keys []dns.RR, dsRecordsFromParent []*dns.DS) (AuthenticationResult, error) {
		return testState, nil
	}

	state, r, err := v.verify(ctx, zone, msg, dsSet)
	assert.NoError(t, err)
	assert.NotNil(t, r)
	assert.Equal(t, testState, state)

	//---

	// Test that when Unknown and an error is returned, that error should be returned to us.
	v.verifyDNSKEYs = func(ctx context.Context, r *result, keys []dns.RR, dsRecordsFromParent []*dns.DS) (AuthenticationResult, error) {
		return Unknown, testErr
	}

	state, r, err = v.verify(ctx, zone, msg, dsSet)
	assert.ErrorIs(t, err, testErr)
	assert.NotNil(t, r)
	assert.Equal(t, Unknown, state)

	//---

	// When Unknown/nil is returned, we expect verifyRRSETs() to then be called.
	v.verifyDNSKEYs = func(ctx context.Context, r *result, keys []dns.RR, dsRecordsFromParent []*dns.DS) (AuthenticationResult, error) {
		return Unknown, nil
	}

	called := false
	v.verifyRRSETs = func(ctx context.Context, r *result, keys []*dns.DNSKEY) (AuthenticationResult, error) {
		called = true
		return testState, nil
	}

	state, r, err = v.verify(ctx, zone, msg, dsSet)
	assert.NoError(t, err)
	assert.NotNil(t, r)
	assert.Equal(t, testState, state)
	assert.True(t, called)

	//---

	// If Unknown and an error is returned, we should get those values back.
	v.verifyRRSETs = func(ctx context.Context, r *result, keys []*dns.DNSKEY) (AuthenticationResult, error) {
		called = true
		return Unknown, testErr
	}

	state, r, err = v.verify(ctx, zone, msg, dsSet)
	assert.ErrorIs(t, err, testErr)
	assert.NotNil(t, r)
	assert.Equal(t, Unknown, state)
}

func TestVerify_VerifyFailsafe(t *testing.T) {
	ctx := context.Background()
	v := getVerifierWithKeyAndSetResponses()
	zone := &mockZone{name: zoneName}
	msg := &dns.Msg{}
	dsSet := []*dns.DS{newRR("example.com. 300 IN DS 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A8 6764247C").(*dns.DS)}

	// With no answers or authority set, we expect a Bogus Result
	state, r, err := v.verify(ctx, zone, msg, dsSet)
	assert.ErrorIs(t, err, ErrFailsafeResponse)
	assert.NotNil(t, r)
	assert.Equal(t, Bogus, state)
}

func TestVerify_VerifyDelegatingResponse(t *testing.T) {
	ctx := context.Background()
	v := getVerifierWithKeyAndSetResponses()
	zone := &mockZone{name: zoneName}
	msg := &dns.Msg{}
	dsSet := []*dns.DS{newRR("example.com. 300 IN DS 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A8 6764247C").(*dns.DS)}

	// NS records in the authority, but no SOA, and no Answers, means we should try validating as a DelegatingResponse.

	msg.Ns = []dns.RR{newRR("example.com. 3600 IN NS ns1.example.com.")}

	called := false
	v.validateDelegatingResponse = func(ctx context.Context, r *result) (AuthenticationResult, error) {
		called = true
		return testState, testErr
	}

	state, r, err := v.verify(ctx, zone, msg, dsSet)
	assert.ErrorIs(t, err, testErr)
	assert.NotNil(t, r)
	assert.Equal(t, testState, state)
	assert.True(t, called)

	//---

	// It should not be called if there was a SOA record included.

	msg.Ns = []dns.RR{
		newRR("example.com. 3600 IN NS ns1.example.com."),
		newRR("example.com. 3600 IN SOA ns1.example.com. noc.example.com. 2024081434 7200 3600 1209600 3600"),
	}

	called = false
	v.validateDelegatingResponse = func(ctx context.Context, r *result) (AuthenticationResult, error) {
		called = true
		return testState, testErr
	}

	v.verify(ctx, zone, msg, dsSet)
	assert.False(t, called)

	//---

	// It should not be called if there was an Answer.

	msg.Answer = []dns.RR{newRR("test.example.com. 3600 IN A 192.0.2.53")}
	msg.Ns = []dns.RR{newRR("example.com. 3600 IN NS ns1.example.com.")}

	called = false
	v.validateDelegatingResponse = func(ctx context.Context, r *result) (AuthenticationResult, error) {
		called = true
		return testState, testErr
	}

	v.verify(ctx, zone, msg, dsSet)
	assert.False(t, called)

}

func TestVerify_VerifyPositiveResponse(t *testing.T) {

	ctx := context.Background()
	v := getVerifierWithKeyAndSetResponses()
	zone := &mockZone{name: zoneName}
	msg := &dns.Msg{}
	dsSet := []*dns.DS{newRR("example.com. 300 IN DS 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A8 6764247C").(*dns.DS)}

	// If there's an answer, no SOA, and we didn't attempt to validate as a DelegatingResponse,
	// then we validate it as a positive response.

	msg.Answer = []dns.RR{newRR("test.example.com. 3600 IN A 192.0.2.53")}

	called := false
	v.validatePositiveResponse = func(ctx context.Context, r *result) (AuthenticationResult, error) {
		called = true
		return testState, testErr
	}

	state, r, err := v.verify(ctx, zone, msg, dsSet)
	assert.ErrorIs(t, err, testErr)
	assert.NotNil(t, r)
	assert.Equal(t, testState, state)
	assert.True(t, called)

	//---

	// If there was a SOA, we do not expect this to be called.

	msg.Answer = []dns.RR{newRR("test.example.com. 3600 IN A 192.0.2.53")}
	msg.Ns = []dns.RR{newRR("example.com. 3600 IN SOA ns1.example.com. noc.example.com. 2024081434 7200 3600 1209600 3600")}

	called = false
	v.validatePositiveResponse = func(ctx context.Context, r *result) (AuthenticationResult, error) {
		called = true
		return testState, testErr
	}

	v.verify(ctx, zone, msg, dsSet)
	assert.False(t, called)

	//---

	// If there was no answer, we don't expect this to be called.

	msg.Answer = []dns.RR{}
	msg.Ns = []dns.RR{newRR("example.com. 3600 IN SOA ns1.example.com. noc.example.com. 2024081434 7200 3600 1209600 3600")}

	called = false
	v.validatePositiveResponse = func(ctx context.Context, r *result) (AuthenticationResult, error) {
		called = true
		return testState, testErr
	}

	v.verify(ctx, zone, msg, dsSet)
	assert.False(t, called)

	//---

	// If the response also looks like a DelegatingResponse, we don't expect this to be called.

	msg.Answer = []dns.RR{}
	msg.Ns = []dns.RR{newRR("example.com. 3600 IN NS ns1.example.com.")}

	called = false
	v.validatePositiveResponse = func(ctx context.Context, r *result) (AuthenticationResult, error) {
		called = true
		return testState, testErr
	}

	v.verify(ctx, zone, msg, dsSet)
	assert.False(t, called)

}

func TestVerify_VerifyNegativeResponse(t *testing.T) {

	ctx := context.Background()
	v := getVerifierWithKeyAndSetResponses()
	zone := &mockZone{name: zoneName}
	msg := &dns.Msg{}
	dsSet := []*dns.DS{newRR("example.com. 300 IN DS 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A8 6764247C").(*dns.DS)}

	// If a response includes a SOA, we treat it as a negative response.
	msg.Ns = []dns.RR{newRR("example.com. 3600 IN SOA ns1.example.com. noc.example.com. 2024081434 7200 3600 1209600 3600")}

	called := false
	v.validateNegativeResponse = func(ctx context.Context, r *result) (AuthenticationResult, error) {
		called = true
		return testState, testErr
	}

	state, r, err := v.verify(ctx, zone, msg, dsSet)
	assert.ErrorIs(t, err, testErr)
	assert.NotNil(t, r)
	assert.Equal(t, testState, state)
	assert.True(t, called)

}
