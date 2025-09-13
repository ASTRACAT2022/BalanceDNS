package dnssec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthenticationResult_String(t *testing.T) {
	tests := []struct {
		result   AuthenticationResult
		expected string
	}{
		{Unknown, "Unknown"},
		{Insecure, "Insecure"},
		{Secure, "Secure"},
		{Bogus, "Bogus"},
	}

	for _, test := range tests {
		assert.Equal(t, test.expected, test.result.String())
	}
}

func TestAuthenticationResult_Combine(t *testing.T) {
	tests := []struct {
		r1, r2   AuthenticationResult
		expected AuthenticationResult
	}{
		{Secure, Secure, Secure},
		{Secure, Insecure, Insecure},
		{Secure, Unknown, Unknown},
		{Secure, Bogus, Bogus},
		{Insecure, Insecure, Insecure},
		{Insecure, Unknown, Unknown},
		{Insecure, Bogus, Bogus},
		{Unknown, Unknown, Unknown},
		{Unknown, Bogus, Bogus},
		{Bogus, Bogus, Bogus},
	}

	for _, test := range tests {
		assert.Equal(t, test.expected, test.r1.Combine(test.r2))
	}
}

func TestDenialOfExistenceState_String(t *testing.T) {
	tests := []struct {
		state    DenialOfExistenceState
		expected string
	}{
		{NotFound, "NotFound"},
		{NsecMissingDS, "NsecMissingDS"},
		{NsecNoData, "NsecNoData"},
		{NsecNxDomain, "NsecNxDomain"},
		{NsecWildcard, "NsecWildcard"},
		{Nsec3MissingDS, "Nsec3MissingDS"},
		{Nsec3NoData, "Nsec3NoData"},
		{Nsec3NxDomain, "Nsec3NxDomain"},
		{Nsec3OptOut, "Nsec3OptOut"},
		{Nsec3Wildcard, "Nsec3Wildcard"},
	}

	for _, test := range tests {
		assert.Equal(t, test.expected, test.state.String())
	}
}
