package dnssec

const year68 = 1 << 31 // For RFC1982 (Serial Arithmetic) calculations in 32 bits.

type AuthenticationResult uint8

const (
	Unknown AuthenticationResult = iota
	Insecure
	Secure
	Bogus
)

func (r AuthenticationResult) String() string {
	switch r {
	default:
		fallthrough
	case Unknown:
		return "Unknown"
	case Insecure:
		return "Insecure"
	case Secure:
		return "Secure"
	case Bogus:
		return "Bogus"
	}
}

// Combine determines the overall AuthenticationResult when merging two authenticated results,
// such as when a result is based on multiple DNS requests (e.g., following a CNAME chain).
func (r AuthenticationResult) Combine(r2 AuthenticationResult) AuthenticationResult {
	// If either result is Bogus, the overall result should be Bogus.
	if r == Bogus || r2 == Bogus {
		return Bogus
	}
	// If either result is Unknown, the overall result should be Unknown.
	if r == Unknown || r2 == Unknown {
		return Unknown
	}
	// If either result is Insecure, the overall result should be Insecure.
	if r == Insecure || r2 == Insecure {
		return Insecure
	}
	// Only return Secure if both results are independently Secure.
	if r == Secure && r2 == Secure {
		return Secure
	}
	// Default to Bogus if none of the conditions are met.
	return Bogus
}

//---

type DenialOfExistenceState uint8

const (
	NotFound DenialOfExistenceState = iota

	NsecMissingDS
	NsecNoData
	NsecNxDomain
	NsecWildcard

	Nsec3MissingDS
	Nsec3NoData
	Nsec3NxDomain
	Nsec3OptOut
	Nsec3Wildcard
)

func (d DenialOfExistenceState) String() string {
	switch d {
	default:
		fallthrough
	case NotFound:
		return "NotFound"
	case NsecMissingDS:
		return "NsecMissingDS"
	case NsecNoData:
		return "NsecNoData"
	case NsecNxDomain:
		return "NsecNxDomain"
	case NsecWildcard:
		return "NsecWildcard"
	case Nsec3MissingDS:
		return "Nsec3MissingDS"
	case Nsec3NoData:
		return "Nsec3NoData"
	case Nsec3NxDomain:
		return "Nsec3NxDomain"
	case Nsec3OptOut:
		return "Nsec3OptOut"
	case Nsec3Wildcard:
		return "Nsec3Wildcard"
	}
}

//---

type section bool

const (
	answerSection    section = true
	authoritySection section = false
)
