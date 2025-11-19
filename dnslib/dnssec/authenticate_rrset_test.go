package dnssec

import (
	"errors"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestAuthenticate_ValidRSA(t *testing.T) {
	rrset := []dns.RR{
		newRR("example.com. 3600 IN MX 10 mx1.example.com."),
		newRR("example.com. 3600 IN MX 10 mx2.example.com."),
	}

	key := testRsaKey()

	rrset = append(rrset, key.sign(rrset, 0, 0))

	set, err := authenticate(zoneName, rrset, []*dns.DNSKEY{key.key}, answerSection)
	if err != nil {
		t.Error(err)
	}

	if len(set) != 1 {
		t.Errorf("expected length of set to be 1, but got %d", len(set))
	}

	if err := set.Verify(); err != nil {
		t.Errorf("unexpected error when calling Verify(): %s", err.Error())
	}

	if valid := set.Valid(); !valid {
		t.Error("expected set to be valid")
	}

	if set[0].wildcard == true {
		t.Error("expected wildcard to be false")
	}
}

func TestAuthenticate_ValidSECDSA(t *testing.T) {
	rrset := []dns.RR{
		newRR("example.com. 3600 IN MX 10 mx1.example.com."),
		newRR("example.com. 3600 IN MX 10 mx2.example.com."),
	}

	key := testEcKey()

	rrset = append(rrset, key.sign(rrset, 0, 0))

	set, err := authenticate(zoneName, rrset, []*dns.DNSKEY{key.key}, answerSection)
	if err != nil {
		t.Error(err)
	}

	if len(set) != 1 {
		t.Errorf("expected length of set to be 1, but got %d", len(set))
	}

	if err := set.Verify(); err != nil {
		t.Errorf("unexpected error when calling Verify(): %s", err.Error())
	}

	if valid := set.Valid(); !valid {
		t.Error("expected set to be valid")
	}

	if set[0].wildcard == true {
		t.Error("expected wildcard to be false")
	}
}

func TestAuthenticate_ValidWithTwoKeysAndTwoRRSets(t *testing.T) {
	// We pass two different RRSETs, signed by two different DNSKEYs.

	rrset1 := []dns.RR{
		newRR("example.com. 3600 IN MX 10 mx1.example.com."),
		newRR("example.com. 3600 IN MX 10 mx2.example.com."),
	}
	rrset2 := []dns.RR{
		newRR("mx1.example.com. 3600 IN A 192.0.2.53"),
	}

	key1 := testEcKey()
	key2 := testRsaKey()

	rrset1 = append(rrset1, key1.sign(rrset1, 0, 0))
	rrset2 = append(rrset2, key2.sign(rrset2, 0, 0))

	set, err := authenticate(zoneName, slices.Concat(rrset1, rrset2), []*dns.DNSKEY{key1.key, key2.key}, answerSection)
	if err != nil {
		t.Error(err)
	}

	if len(set) != 2 {
		t.Errorf("expected length of set to be 2, but got %d", len(set))
	}

	if err := set.Verify(); err != nil {
		t.Errorf("unexpected error when calling Verify(): %s", err.Error())
	}

	if valid := set.Valid(); !valid {
		t.Error("expected set to be valid")
	}
}

func TestAuthenticate_ValidWildcard(t *testing.T) {
	rrset := []dns.RR{newRR("*.example.com. 3600 IN A 192.0.2.53")}
	key := testEcKey()

	rrset = append(rrset, key.sign(rrset, 0, 0))

	// After it's signed, we'll replace `*` with a 'real' label.
	rrset[0].Header().Name = dns.Fqdn("test.example.com.") // A records
	rrset[1].Header().Name = dns.Fqdn("test.example.com.") // RRSIG record

	set, err := authenticate(zoneName, rrset, []*dns.DNSKEY{key.key}, answerSection)
	if err != nil {
		t.Error(err)
	}

	if len(set) != 1 {
		t.Errorf("expected length of set to be 1, but got %d", len(set))
	}

	if err := set.Verify(); err != nil {
		t.Errorf("unexpected error when calling Verify(): %s", err.Error())
	}

	if valid := set.Valid(); !valid {
		t.Error("expected set to be valid")
	}

	if set[0].wildcard != true {
		t.Error("expected wildcard to be true")
	}
}

func TestAuthenticate_InvalidSignature(t *testing.T) {
	rr, _ := newRR("example.com. 3600 IN MX 10 mx1.example.com.").(*dns.MX)
	rrset := []dns.RR{rr}

	key := testEcKey()

	rrset = append(rrset, key.sign(rrset, 0, 0))

	// We amend the record so it should no longer match the signature.
	rr.Preference = 20

	set, err := authenticate(zoneName, rrset, []*dns.DNSKEY{key.key}, answerSection)
	if err != nil {
		t.Error(err)
	}

	if len(set) != 1 {
		t.Errorf("expected length of set to be 1, but got %d", len(set))
	}

	if valid := set.Valid(); valid {
		t.Error("expected set to not be valid")
	}

	err = set.Verify()
	if err == nil {
		t.Error("expected error but not found")
	}

	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected error to be ErrInvalidSignature. got: %s", err.Error())
	}

	if set[0].wildcard == true {
		t.Error("expected wildcard to be false")
	}
}

func TestAuthenticate_InvalidTimePeriod(t *testing.T) {
	rr, _ := newRR("example.com. 3600 IN MX 10 mx1.example.com.").(*dns.MX)
	rrset := []dns.RR{rr}

	key := testEcKey()

	//---------------------------------
	// Future inception

	inception := time.Now().Add(time.Hour * 24).Unix()
	expiration := time.Now().Add(time.Hour * 48).Unix()
	rrset1 := append(rrset, key.sign(rrset, inception, expiration))

	set, err := authenticate(zoneName, rrset1, []*dns.DNSKEY{key.key}, answerSection)
	if err != nil {
		t.Error(err)
	}

	if len(set) != 1 {
		t.Errorf("expected length of set to be 1, but got %d", len(set))
	}

	if valid := set.Valid(); valid {
		t.Error("expected set to not be valid")
	}

	err = set.Verify()
	if err == nil {
		t.Error("expected error but not found")
	}

	if !errors.Is(err, ErrInvalidTime) {
		t.Errorf("expected error to be ErrInvalidTime. got: %s", err.Error())
	}

	if set[0].wildcard == true {
		t.Error("expected wildcard to be false")
	}

	//---------------------------------
	// Past expiration

	inception = time.Now().Add(time.Hour * -48).Unix()
	expiration = time.Now().Add(time.Hour * -24).Unix()
	rrset2 := append(rrset, key.sign(rrset, inception, expiration))

	set, err = authenticate(zoneName, rrset2, []*dns.DNSKEY{key.key}, answerSection)
	if err != nil {
		t.Error(err)
	}

	if len(set) != 1 {
		t.Errorf("expected length of set to be 1, but got %d", len(set))
	}

	if valid := set.Valid(); valid {
		t.Error("expected set to not be valid")
	}

	err = set.Verify()
	if err == nil {
		t.Error("expected error but not found")
	}

	if !errors.Is(err, ErrInvalidTime) {
		t.Errorf("expected error to be ErrInvalidTime. got: %s", err.Error())
	}

	if set[0].wildcard == true {
		t.Error("expected wildcard to be false")
	}
}

func TestAuthenticate_InvalidSignerName(t *testing.T) {
	rrset := []dns.RR{newRR("example.com. 3600 IN MX 10 mx1.example.com.")}

	key := testEcKey()

	rrset = append(rrset, key.sign(rrset, 0, 0))

	// We'll change the expected zone to .net, thus it won't match the signer name of example.com.
	set, err := authenticate("example.net.", rrset, []*dns.DNSKEY{key.key}, answerSection)
	if err != nil {
		t.Error(err)
	}

	if len(set) != 1 {
		t.Errorf("expected length of set to be 1, but got %d", len(set))
	}

	if valid := set.Valid(); valid {
		t.Error("expected set to not be valid")
	}

	err = set.Verify()
	if err == nil {
		t.Error("expected error but not found")
	}

	if !errors.Is(err, ErrAuthSignerNameMismatch) {
		t.Errorf("expected error to be ErrAuthSignerNameMismatch. got: %s", err.Error())
	}

	if set[0].wildcard == true {
		t.Error("expected wildcard to be false")
	}
}

func TestAuthenticate_InvalidLabelCount(t *testing.T) {
	// The number of labels in the owner name cannot be less than the RRSIG's label value.

	// We'll add some labels temporarily so the label value in the RRSIG is high.
	rrset := []dns.RR{newRR("a.b.c.example.com. 3600 IN MX 10 mx1.example.com.")}

	key := testEcKey()

	rrset = append(rrset, key.sign(rrset, 0, 0))

	// Changing this back will mean the label value is now greater than the count of the owner name.
	rrset[0].Header().Name = "example.com."
	rrset[1].Header().Name = "example.com."

	// We'll change the expected zone to .net, thus it won't match the signer name of example.com.
	set, err := authenticate(zoneName, rrset, []*dns.DNSKEY{key.key}, answerSection)
	if err != nil {
		t.Error(err)
	}

	if len(set) != 1 {
		t.Errorf("expected length of set to be 1, but got %d", len(set))
	}

	if valid := set.Valid(); valid {
		t.Error("expected set to not be valid")
	}

	err = set.Verify()
	if err == nil {
		t.Error("expected error but not found")
	}

	if !errors.Is(err, ErrInvalidLabelCount) {
		t.Errorf("expected error to be ErrInvalidLabelCount. got: %s", err.Error())
	}

	if set[0].wildcard == true {
		t.Error("expected wildcard to be false")
	}
}

func TestAuthenticate_InvalidWithMultipleErrors(t *testing.T) {
	// Both RRSIGs will be invalid

	rrset1 := []dns.RR{
		newRR("example.com. 3600 IN MX 10 mx1.example.com."),
		newRR("example.com. 3600 IN MX 10 mx2.example.com."),
	}

	rr, _ := newRR("mx1.example.com. 3600 IN A 192.0.2.53").(*dns.A)
	rrset2 := []dns.RR{rr}

	key1 := testEcKey()
	key2 := testRsaKey()

	inception := time.Now().Add(time.Hour * 24).Unix()
	expiration := time.Now().Add(time.Hour * 48).Unix()

	// Invalid due to time period
	rrset1 = append(rrset1, key1.sign(rrset1, inception, expiration))

	// Will be invalid due to the IP address changing.
	rrset2 = append(rrset2, key2.sign(rrset2, 0, 0))
	rr.A = net.ParseIP("192.0.2.54").To4()

	set, err := authenticate(zoneName, slices.Concat(rrset1, rrset2), []*dns.DNSKEY{key1.key, key2.key}, answerSection)
	if err != nil {
		t.Error(err)
	}

	if len(set) != 2 {
		t.Errorf("expected length of set to be 2, but got %d", len(set))
	}

	if valid := set.Valid(); valid {
		t.Error("expected set to not be valid")
	}

	err = set.Verify()
	if err == nil {
		t.Error("expected error but not found")
	}

	// We expect the error to be both of these.
	if !errors.Is(err, ErrInvalidTime) {
		t.Errorf("expected error to be ErrInvalidTime. got: %s", err.Error())
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected error to be ErrInvalidSignature. got: %s", err.Error())
	}
}

func TestAuthenticate_ValidWithManyClashingKeys(t *testing.T) {
	// These keys are deliberately committed for testing purposes.
	// They all have the identical Flags, Protocol, Algorithm *and Tag*.
	//
	// To understand how they were generated, see:
	// https://gist.github.com/nsmithuk/aecbffeb3dbbd20279181d3b57ba9de9.
	//
	// These keys are pre-generated because finding matching keys is a non-deterministic task so we cannot
	// reliably assume we'll always be able to generate them in a timely manner during a test.
	//
	// Format: Public Key => Private Key.
	var clashingKeys = map[string]string{
		"QyNAHERauLBiVZua+9W1iIw+WG73bKMct3s8X9Phymc=": `Private-key-format: v1.3
Algorithm: 15 (ED25519)
PrivateKey: lSRmSnXyVc1qQO+RJDft2cCnFONshJtWkKqrBsuqK7I=`,

		"OM3lk6zh0Dl1PqbNar3hsdlzOE1QdDyi9CYN4TNqaLI=": `Private-key-format: v1.3
Algorithm: 15 (ED25519)
PrivateKey: Imk2wqR4GvwwRZ0BQpb31G17VMCGf30eTTAFGqrFUFI=`,

		"F1qCyN28RWK062XB30OsVAoG4iaSA8KxdDMf6vYDEmk=": `Private-key-format: v1.3
Algorithm: 15 (ED25519)
PrivateKey: WSTJy/U+3PwhtCGTHgjldrOO1LfOWoI78fnmUEtF4Zg=`,

		"5fPWnkeiYYVBvqG3nU4EGXEyqUC6XJ1sE74LRgV0v6c=": `Private-key-format: v1.3
Algorithm: 15 (ED25519)
PrivateKey: PfkPtaI+WMRGAb6H127uf5iSazdQ+/ymkC4Bbqtm3c4=`,

		"7Dm/9pFgK7nrgclE01lFNLR2EwIb50nH/6UXOugD3kk=": `Private-key-format: v1.3
Algorithm: 15 (ED25519)
PrivateKey: miJcdKkOR61lea87kOkKK4DZvrZPI4gc9QB+qmQ+gBc=`,

		"w/IhaJ69VP2sC7QgMG+auWujvOg2GN9mzk4XXaFUd30=": `Private-key-format: v1.3
Algorithm: 15 (ED25519)
PrivateKey: JenzYPD2q3ldCbCyhkqsX0e/WwHjGdTDIsL37BNNLUs=`,

		"k00ebWli/edH73cz7Ip4RTTjRYvuMU21Udu/jzyX/6M=": `Private-key-format: v1.3
Algorithm: 15 (ED25519)
PrivateKey: ho9mEVla4jjpbC5DoebVqsmvqWtFc074kENkCW86gPg=`,
	}

	keys := make([]*testKey, 0, len(clashingKeys))
	dnskeys := make([]*dns.DNSKEY, 0, len(clashingKeys))
	for public, secret := range clashingKeys {
		key := testED25519KeyFromReader(strings.NewReader(public), strings.NewReader(secret))
		keys = append(keys, key)
		dnskeys = append(dnskeys, key.key)
	}

	rrset := []dns.RR{
		newRR("example.com. 3600 IN MX 10 mx1.example.com."),
		newRR("example.com. 3600 IN MX 10 mx2.example.com."),
	}

	// We sign it with the last key, thus it'll try verifying with all the others first.
	rrset = append(rrset, keys[6].sign(rrset, 0, 0))

	set, err := authenticate(zoneName, rrset, dnskeys, answerSection)
	if err != nil {
		t.Error(err)
	}

	if len(set) != 1 {
		t.Errorf("expected length of set to be 1, but got %d", len(set))
	}

	if err := set.Verify(); err != nil {
		t.Errorf("unexpected error when calling Verify(): %s", err.Error())
	}

	if valid := set.Valid(); !valid {
		t.Error("expected set to be valid")
	}

	if set[0].wildcard == true {
		t.Error("expected wildcard to be false")
	}

	if set[0].err != nil {
		// This is worth checking as it will, at times, not be nil as it cycles through the keys.
		// But we exlect it to be nil by the end of the verify.
		t.Error("expected signature error to be nil")
	}
}

func TestAuthenticate_ValidWithUnsignedNSRecords(t *testing.T) {
	// When authenticating the authority section at the point of a delegation, we don't
	// always expect the NS records to be signed, but the DS records should be.
	// Note that DS records not being signed is optional - they _can_ be signed.
	// We also test ErrUnexpectedSignatureCount here as the same records in the answer section should fail.

	rrset1 := []dns.RR{
		newRR("example.com. 3600 IN NS ns1.example.com."),
		newRR("example.com. 3600 IN NS ns2.example.com."),
	}
	rrset2 := []dns.RR{
		newRR("example.com. 3600 IN DS 14056 13 2 5BF7C0CBEC31298BD4BACDE9EBCE1C3A990576D9B581191D6FFBC87FC552AC61"),
	}

	key := testEcKey()

	rrset2 = append(rrset2, key.sign(rrset2, 0, 0))

	set, err := authenticate(zoneName, slices.Concat(rrset1, rrset2), []*dns.DNSKEY{key.key}, authoritySection)
	if err != nil {
		t.Error(err)
	}

	if len(set) != 1 {
		t.Errorf("expected length of set to be 1, but got %d", len(set))
	}

	if err := set.Verify(); err != nil {
		t.Errorf("unexpected error when calling Verify(): %s", err.Error())
	}

	if valid := set.Valid(); !valid {
		t.Error("expected set to be valid")
	}

	//---

	// If the same records were part of an answer section, we'd expect it to fail as not all RRSETs have a RRSIG.

	_, err = authenticate(zoneName, slices.Concat(rrset1, rrset2), []*dns.DNSKEY{key.key}, answerSection)
	if err == nil {
		t.Error("error expected but not found")
	}

	if !errors.Is(err, ErrUnexpectedSignatureCount) {
		t.Errorf("expected error to be ErrUnexpectedSignatureCount")
	}

}

func TestAuthenticate_ValidWithSignedNSRecords(t *testing.T) {
	// Test the edge case where NS records in the authority section are signed.
	// For example: dig @l.gtld-servers.net. naughty-nameserver.com. DS +dnssec

	rrset1 := []dns.RR{
		newRR("example.com. 3600 IN NS ns1.example.com."),
		newRR("example.com. 3600 IN NS ns2.example.com."),
	}
	rrset2 := []dns.RR{
		newRR("example.com. 3600 IN DS 14056 13 2 5BF7C0CBEC31298BD4BACDE9EBCE1C3A990576D9B581191D6FFBC87FC552AC61"),
	}

	key := testEcKey()

	rrset1 = append(rrset1, key.sign(rrset1, 0, 0))
	rrset2 = append(rrset2, key.sign(rrset2, 0, 0))

	set, err := authenticate(zoneName, slices.Concat(rrset1, rrset2), []*dns.DNSKEY{key.key}, authoritySection)
	if err != nil {
		t.Error(err)
	}

	if len(set) != 2 {
		t.Errorf("expected length of set to be 2, but got %d", len(set))
	}

	if err := set.Verify(); err != nil {
		t.Errorf("unexpected error when calling Verify(): %s", err.Error())
	}

	if valid := set.Valid(); !valid {
		t.Error("expected set to be valid")
	}

}

func TestAuthenticate_ValidWithMultipleRRSigsForSameRRSet(t *testing.T) {
	/*
		For example:
		dig glb.nist.gov. DNSKEY +dnssec

		; <<>> DiG 9.10.6 <<>> glb.nist.gov. DNSKEY +dnssec
		;; global options: +cmd
		;; Got answer:
		;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1580
		;; flags: qr rd ra ad; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 1

		;; OPT PSEUDOSECTION:
		; EDNS: version: 0, flags: do; udp: 1232
		;; QUESTION SECTION:
		;glb.nist.gov.			IN	DNSKEY

		;; ANSWER SECTION:
		glb.nist.gov.		86400	IN	DNSKEY	256 3 7 AwEAAdPuokc5nFzMaxwm9AuuHdZc1ECf7VZjMBW0/rDREonG+8sTihJ6 Vq9nw/yJ8dCzYvlwAyJ224OnfFeU5i8nz17xawYa6Ebhvj3XX4P8CAWB EIi5EJKxP1aYhm+jghiEL3jEoRDTIphY5koEq4O2g+WfRTmTshGbB2/T f89mSAw5
		glb.nist.gov.		86400	IN	DNSKEY	257 3 7 AwEAAbPrgxVFi42DjlUUzWeFZ3HH6DzpYGI5yO89vD4IPrZFYiemBn51 PaCU9SzdbsDhH8jlEUo95ViKHlQW4Ktplj4IHYCugiHy+EC5UC62FK6F TDfGLEHIbOf8A3/Nlkc6xtJ/J6xcxxTeM3Qn8nUJIt33w7bfZmxBC+qH oRHBJU9CuZikAnAdPkYuKvp2plxpHbu+eqofiTrvlynU84jLukco0/J5 IeTt5bdpgdaOV/GrGnqwdm1B/1rmMyapRHdsfpxXaFcp6oYwhcsiL5yY izjSmm3CiHQ7lOZFEQYdCzd7f/tM1vMJQN5ocVoQe4YzwicrtT+Pj4Is X7ZBjnKjmCk=
		glb.nist.gov.		86400	IN	DNSKEY	257 3 7 AwEAAay9EcPmXxaHuWKjwZCesahBer2Mbp+ySbo/830nIQqIIYYaQLg+ J5lbBtnbXTd51uKjXrqGr3hwgt3efXtWeivkYpNp86j7PvwQn+AodfcO p6SHzZDLihXZY/mfwW5uO6Uzm8u78Op+tdRP9MX/oo47DqLPTw40VB36 B718A9PDCq+TXfaqo3tFJxZgaRswTPF83+8pmbMYwjHNfwgdzYAyV4yb WxCYnNb3q1Xd7pNA3FScjqpyCcBOoIKM/5qSYkAUIhqDk4GtzwLQfkk7 PdkwjTi4nxuNYzqLdQkuzrBQPw9uQsUqCM69WmGwflJCe7EghPlBhDOo n4KBR/2+1a0=
		glb.nist.gov.		86400	IN	RRSIG	DNSKEY 7 3 86400 20241111063157 20241104053157 49100 glb.nist.gov. iXsJkPzlJl1FkBX1NCF9LhSsUnfd/Mh2NRQb6ahOj220Xp3QZzX9yfuR EJgwQoe9+8dYDU5njJ+mA3SwdskyM9CKjDVsH9NWgJVIUszzAuneVN3i XOW6oUkbeWvvlGEUy5XMwqgMQBxKUJCf9/RW+jYYk3kOQjn3d6i399AC +FE=
		glb.nist.gov.		86400	IN	RRSIG	DNSKEY 7 3 86400 20241109063156 20241101053156 56235 glb.nist.gov. LwSFwMJqkte7m1eS+wUhRE5gxOLrq+jkDIispIkL4c72sdP3ZYlMK+NW ZGNYtL1syES47LPqfOWvhIb6hLpKUbpwWNGpw0cpB21/eb9LAP0sYP0R p30YYYvOJuBE0YxNdhWq/KF5CMagVfOYkpBsCsA0z12kBrO1VK7NpsXj kziCfKQUrlxXxECkSwr16FcKvkXc8OpM7CaIZhIYi95uBuuImjWjPUDD 1aYani9RqYqnzJpcmNE9OhLEGGcV5xknU59FV9Qb3XvAV1ndstpy8U2O +lwqIYm0SQr+FD73D+dyL1MTGmdU3v4/cXTVc5+CTbaUJppkVa1JntG+ RaDXXQ==
		glb.nist.gov.		86400	IN	RRSIG	DNSKEY 7 3 86400 20241109063156 20241101053156 57306 glb.nist.gov. h1SV0GVgKc0HHDyKTKfqJZQXXlMAhlOFuFPxXkEjW3t9CtMhc6BQYAdf 6Wl0sv/RL44Ll4f3Y3n6ge+fpyvQya2BvcLK0GgHCFQuYfub8/stGxbE AH6yamoO30BDL/D967jaO0wfHMoTCueph6zwcYD1FOXAsl2BIenY5v/4 FqWfcxrUKmGhm4g1GrR0yTj8THGnkBPcYn8QowoVCjqKKR3rPT5lCu4f Kv0GzLR8Ty8ZOqt9PZqSg/5R1awPw8NGLFiyOh/sQV42K1uDLpbPy6Tc wD5Zkc4e/6Ytra5BWwRu+l74Y9rMOjw7bKf3i5XEKRychOe1SoFvyPu8 8fZFwQ==
	*/

	rrset := []dns.RR{
		newRR("example.com. 3600 IN MX 10 mx1.example.com."),
		newRR("example.com. 3600 IN MX 10 mx2.example.com."),
	}

	// We sign the same set with 3 different keys.

	key1 := testEcKey()
	key2 := testEcKey()
	key3 := testEcKey()

	rrset1 := append(rrset, key1.sign(rrset, 0, 0))
	rrset2 := append(rrset, key2.sign(rrset, 0, 0))
	rrset3 := append(rrset, key3.sign(rrset, 0, 0))
	combined := dns.Dedup(slices.Concat(rrset1, rrset2, rrset3), nil)

	set, err := authenticate(zoneName, combined, []*dns.DNSKEY{key1.key, key2.key, key3.key}, answerSection)
	assert.NoError(t, err)

	assert.Len(t, set, 3)
	assert.True(t, set.Valid())
	assert.NoError(t, set.Verify())

	assert.False(t, set[0].wildcard)
	assert.False(t, set[1].wildcard)
	assert.False(t, set[2].wildcard)
}

func TestAuthenticate_ValidWithMultipleRRSetsOfSameTypeDifferentName(t *testing.T) {

	rrset1 := []dns.RR{
		newRR("a.example.com. 3600 IN CNAME b.example.com."),
	}
	rrset2 := []dns.RR{
		newRR("b.example.com. 3600 IN CNAME c.example.com."),
	}
	rrset3 := []dns.RR{
		newRR("c.example.com. 3600 IN A 192.0.2.53"),
	}

	key := testEcKey()

	rrset1 = append(rrset1, key.sign(rrset1, 0, 0))
	rrset2 = append(rrset2, key.sign(rrset2, 0, 0))
	rrset3 = append(rrset3, key.sign(rrset3, 0, 0))

	set, err := authenticate(zoneName, slices.Concat(rrset1, rrset2, rrset3), []*dns.DNSKEY{key.key}, answerSection)
	assert.NoError(t, err)

	assert.Len(t, set, 3)
	assert.True(t, set.Valid())
	assert.NoError(t, set.Verify())

	assert.False(t, set[0].wildcard)
	assert.False(t, set[1].wildcard)
	assert.False(t, set[2].wildcard)
}
