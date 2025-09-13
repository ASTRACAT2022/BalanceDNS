package dnssec

import (
	"errors"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"slices"
	"testing"
)

func TestSignatures_FilterOnTypeAndExtractDSRecords(t *testing.T) {

	ds := newRR("example.com. 54775 IN DS 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A8 6764247C")
	nsec := newRR("test.example.com. 3600 IN NSEC \000.test.example.com. A RRSIG NSEC")
	nsec3 := newRR("L72QU4B0R4USH96QN17VTCD8395QILEQ.example.com. 3600 IN NSEC3 1 0 2 ABCDEF T0B6SHHJ0JQRI032RVVLMCGGNHCVF5UM A RRSIG")

	expectedDS := []*dns.DS{ds.(*dns.DS)}
	expectedNSEC := []*dns.NSEC{nsec.(*dns.NSEC)}
	expectedNSEC3 := []*dns.NSEC3{nsec3.(*dns.NSEC3)}

	set := signatures{
		{
			rtype: dns.TypeA,
		},
		{
			rtype: dns.TypeA,
		},
		{
			rtype: dns.TypeNSEC,
			rrset: []dns.RR{nsec},
		},
		{
			rtype: dns.TypeNSEC3,
			rrset: []dns.RR{nsec3},
		},
		{
			rtype: dns.TypeDS,
			rrset: []dns.RR{
				newRR("example.com. 3600 IN NS ns1.example.com."),
				newRR("example.com. 3600 IN NS ns2.example.com."),
				ds,
			},
		},
	}

	if len(set.filterOnType(dns.TypeA)) != 2 {
		t.Errorf("expected 1 RR got %d", len(set.filterOnType(dns.TypeA)))
	}
	if len(set.filterOnType(dns.TypeNSEC3)) != 1 {
		t.Errorf("expected 1 RR got %d", len(set.filterOnType(dns.TypeNSEC3)))
	}
	if len(set.filterOnType(dns.TypeDS)) != 1 {
		t.Errorf("expected 1 RR got %d", len(set.filterOnType(dns.TypeDS)))
	}

	dsSet := set.filterOnType(dns.TypeDS)

	// We expect both of these to return the same results, the one DS record.
	if !slices.Equal(dsSet.extractDSRecords(), expectedDS) {
		t.Errorf("expected DS records to be extracted but got %v", dsSet.extractDSRecords())
	}
	if !slices.Equal(set.extractDSRecords(), expectedDS) {
		t.Errorf("expected DS records to be extracted but got %v", set.extractDSRecords())
	}

	if !slices.Equal(set.extractNSECRecords(), expectedNSEC) {
		t.Errorf("expected NSEC records to be extracted but got %v", set.extractNSECRecords())
	}
	if !slices.Equal(set.extractNSEC3Records(), expectedNSEC3) {
		t.Errorf("expected NSEC3 records to be extracted but got %v", set.extractNSEC3Records())
	}

}

func TestSignatures_ValidAndVerify_RequireAllSignaturesValid(t *testing.T) {

	RequireAllSignaturesValid = true

	// An empty set is not a valid set.

	set := signatures{}

	if set.Valid() {
		t.Error("expected invalid signature")
	}
	err := set.Verify()
	if err == nil {
		t.Errorf("expected signature error got %v", err)
	}
	if !errors.Is(err, ErrSignatureSetEmpty) {
		t.Errorf("expected error to be ErrSignatureSetEmpty")
	}

	//---

	// When all signatures are valid, the whole set is valid.

	set = signatures{
		{
			rtype:    dns.TypeA,
			verified: true,
		},
		{
			rtype:    dns.TypeMX,
			verified: true,
		},
	}

	if !set.Valid() {
		t.Error("expected valid signature")
	}
	if err := set.Verify(); err != nil {
		t.Errorf("expected valid signature error got %v", err)
	}

	//---

	// When one signature is invalid, the whole set is invalid.

	ErrTest1 := errors.New("test error 1")

	set = slices.Concat(set, signatures{
		{
			rtype:    dns.TypeMX,
			verified: false,
			err:      ErrTest1,
		},
	})

	if set.Valid() {
		t.Error("expected invalid signature")
	}
	err = set.Verify()
	if err == nil {
		t.Errorf("expected signature error got %v", err)
	}
	if !errors.Is(err, ErrVerifyFailed) {
		t.Errorf("expected error to be ErrVerifyFailed")
	}
	if !errors.Is(err, ErrTest1) {
		t.Errorf("expected error to be ErrTest1")
	}

	//---

	// When many signature is invalid, we expect to get all the errors back.

	ErrTest2 := errors.New("test error 2")
	ErrTest3 := errors.New("test error 3")

	set = slices.Concat(set, signatures{
		{
			rtype:    dns.TypeMX,
			verified: false,
			err:      ErrTest2,
		},
		{
			rtype:    dns.TypeMX,
			verified: false,
			err:      ErrTest3,
		},
	})

	if set.Valid() {
		t.Error("expected invalid signature")
	}
	err = set.Verify()
	if err == nil {
		t.Errorf("expected signature error got %v", err)
	}
	if !errors.Is(err, ErrVerifyFailed) {
		t.Errorf("expected error to be ErrVerifyFailed")
	}
	if !errors.Is(err, ErrTest1) {
		t.Errorf("expected error to be ErrTest1")
	}
	if !errors.Is(err, ErrTest2) {
		t.Errorf("expected error to be ErrTest2")
	}
	if !errors.Is(err, ErrTest3) {
		t.Errorf("expected error to be ErrTest3")
	}

	// As all invalid signatures have a specific error message, we don't expect this generic error to be returned.
	if errors.Is(err, ErrUnableToVerify) {
		t.Errorf("expected error to be ErrUnableToVerify")
	}

	//---

	// If a signature is invalid, but has no error, we expect a generic ErrUnableToVerify error to be included.

	set = slices.Concat(set, signatures{
		{
			rtype:    dns.TypeMX,
			verified: false,
		},
	})
	err = set.Verify()
	if !errors.Is(err, ErrUnableToVerify) {
		t.Errorf("expected error to be ErrUnableToVerify")
	}

	RequireAllSignaturesValid = DefaultRequireAllSignaturesValid
}

func TestSignatures_ValidAndVerify_verifyOneOrMoreRRSigPerRRSet_ZeroAndOneSignature(t *testing.T) {

	ErrTest1 := errors.New("test error 1")

	// An empty set is not a valid set.

	set := signatures{}

	if set.Valid() {
		t.Error("expected invalid signature")
	}
	err := set.Verify()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSignatureSetEmpty)

	//---

	// When there is one RRSET, and it's valid, we're valid overall.

	set = signatures{
		{
			rtype:    dns.TypeA,
			verified: true,
		},
	}

	assert.True(t, set.Valid())

	err = set.Verify()
	assert.NoError(t, err)

	//---

	// When there is one RRSET, and it's not valid, we're not valid overall.
	// When no error is set in the signature, we expect to see the default error: ErrUnableToVerify

	set = signatures{
		{
			rtype:    dns.TypeA,
			verified: false,
		},
	}

	assert.False(t, set.Valid())

	err = set.Verify()
	assert.ErrorIs(t, err, ErrVerifyFailed)
	assert.ErrorIs(t, err, ErrUnableToVerify)

	//---

	// When there is one RRSET, and it's not valid, we're not valid overall.
	// When an error is set, we expect that error back.

	set = signatures{
		{
			rtype:    dns.TypeA,
			verified: false,
			err:      ErrTest1,
		},
	}

	assert.False(t, set.Valid())

	err = set.Verify()
	assert.ErrorIs(t, err, ErrVerifyFailed)
	assert.ErrorIs(t, err, ErrTest1)

}

func TestSignatures_ValidAndVerify_verifyOneOrMoreRRSigPerRRSet_MoreThanOneSignature(t *testing.T) {

	ErrTest1 := errors.New("test error 1")
	ErrTest2 := errors.New("test error 2")

	// When there's one valid signature per type, overall we're valid.

	set := signatures{
		{
			rtype:    dns.TypeA,
			verified: true,
		},
		{
			rtype:    dns.TypeMX,
			verified: true,
		},
		{
			rtype:    dns.TypeAAAA,
			verified: true,
		},
	}

	assert.True(t, set.Valid())
	err := set.Verify()
	assert.NoError(t, err)

	//---

	// When there's one type that does not have a valid signature, then overall we're invalid.
	// If there was no custom error set on the invalid signature, we see the default.

	set = signatures{
		{
			rtype:    dns.TypeA,
			verified: true,
		},
		{
			rtype:    dns.TypeMX,
			verified: false,
		},
		{
			rtype:    dns.TypeAAAA,
			verified: true,
		},
	}

	assert.False(t, set.Valid())
	err = set.Verify()
	assert.ErrorIs(t, err, ErrVerifyFailed)
	assert.ErrorIs(t, err, ErrUnableToVerify)

	//---

	// When there's one type that does not have a valid signature, then overall we're invalid.
	// If there was a custom error on the invalid signature, we see this error.

	set = signatures{
		{
			rtype:    dns.TypeA,
			verified: true,
		},
		{
			rtype:    dns.TypeMX,
			verified: false,
			err:      ErrTest1,
		},
		{
			rtype:    dns.TypeAAAA,
			verified: true,
		},
	}

	assert.False(t, set.Valid())
	err = set.Verify()
	assert.ErrorIs(t, err, ErrVerifyFailed)
	assert.ErrorIs(t, err, ErrTest1)

	//---

	// When all types have at least one valid signature, the overall response is valid.
	// Variation 1

	set = signatures{
		{
			rtype:    dns.TypeA,
			verified: true,
		},
		{
			rtype:    dns.TypeMX,
			verified: false,
			err:      ErrTest1,
		},
		{
			rtype:    dns.TypeMX,
			verified: true,
		},
		{
			rtype:    dns.TypeMX,
			verified: false,
			err:      ErrTest2,
		},
		{
			rtype:    dns.TypeAAAA,
			verified: true,
		},
	}

	assert.True(t, set.Valid())
	err = set.Verify()
	assert.NoError(t, err)

	//---

	// When all types have at least one valid signature, the overall response is valid.
	// Variation 2

	set = signatures{
		{
			rtype:    dns.TypeA,
			verified: true,
		},
		{
			rtype:    dns.TypeMX,
			verified: true,
		},
		{
			rtype:    dns.TypeMX,
			verified: false,
			err:      ErrTest1,
		},
		{
			rtype:    dns.TypeMX,
			verified: true,
		},
		{
			rtype:    dns.TypeAAAA,
			verified: true,
		},
	}

	assert.True(t, set.Valid())
	err = set.Verify()
	assert.NoError(t, err)

}

func TestSignatures_ValidAndVerify_verifyOneOrMoreRRSigPerRRSet_ErrorWrapping(t *testing.T) {
	ErrTest1 := errors.New("test error 1")
	ErrTest2 := errors.New("test error 2")
	ErrTest3 := errors.New("test error 3")

	// We expect to see all 2 custom tests errors, plus the default error returned.

	set := signatures{
		{
			rtype:    dns.TypeA,
			verified: false,
			err:      ErrTest1,
		},
		{
			rtype:    dns.TypeMX,
			verified: true,
		},
		{
			rtype:    dns.TypeMX,
			verified: false,
			err:      ErrTest2,
		},
		{
			rtype:    dns.TypeMX,
			verified: true,
		},
		{
			rtype:    dns.TypeAAAA,
			verified: false,
			err:      ErrTest3,
		},
		{
			rtype:    dns.TypeTXT,
			verified: false,
		},
	}

	assert.False(t, set.Valid())
	err := set.Verify()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrVerifyFailed)
	assert.ErrorIs(t, err, ErrTest1)

	// We don't expect to see this as are is at least one valid signature of MX.
	assert.NotErrorIs(t, err, ErrTest2)

	assert.ErrorIs(t, err, ErrTest3)
	assert.ErrorIs(t, err, ErrUnableToVerify)

}

func TestSignatures_CountUniqueTypes(t *testing.T) {
	set := signatures{
		{
			rtype: dns.TypeA,
		},
		{
			rtype: dns.TypeNSEC,
		},
		{
			rtype: dns.TypeNSEC3,
		},
		{
			rtype: dns.TypeDS,
		},
	}
	assert.Equal(t, 4, set.countNameTypeCombinations())

	set = signatures{
		{
			rtype: dns.TypeA,
		},
		{
			rtype: dns.TypeA,
		},
		{
			rtype: dns.TypeA,
		},
		{
			rtype: dns.TypeDS,
		},
	}
	assert.Equal(t, 2, set.countNameTypeCombinations())

	set = signatures{}
	assert.Equal(t, 0, set.countNameTypeCombinations())

	set = signatures{
		{
			name:  "a.example.com.",
			rtype: dns.TypeA,
		},
		{
			name:  "a.example.com.",
			rtype: dns.TypeA,
		},
		{
			name:  "b.example.com.",
			rtype: dns.TypeA,
		},
		{
			name:  "a.example.com.",
			rtype: dns.TypeDS,
		},
	}
	assert.Equal(t, 3, set.countNameTypeCombinations())
}
