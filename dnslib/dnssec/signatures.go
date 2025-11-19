package dnssec

import (
	"fmt"
	"github.com/miekg/dns"
)

func (ss signatures) filterOnType(rtype uint16) signatures {
	set := make(signatures, 0, len(ss))
	for _, sig := range ss {
		if sig.rtype == rtype {
			set = append(set, sig)
		}
	}
	return set
}

func (ss signatures) countNameTypeCombinations() int {
	type combination struct {
		name   string
		rrtype uint16
	}
	combinations := make(map[combination]bool, len(ss))
	for _, sig := range ss {
		combinations[combination{
			name:   sig.name,
			rrtype: sig.rtype,
		}] = true
	}
	return len(combinations)
}

// Verify calls one of two local policy strategies for determining if the response is verified.
func (ss signatures) Verify() error {
	if RequireAllSignaturesValid {
		return ss.verifyAllRRSigsPerRRSet()
	}
	return ss.verifyOneOrMoreRRSigPerRRSet()
}

// verifyOneOrMoreRRSigPerRRSet a signature set. For a set to be valid, at least one signature per RRSet must be valid.
// All errors will be returns, wrapped into a single error.
func (ss signatures) verifyOneOrMoreRRSigPerRRSet() error {
	if len(ss) == 0 {
		return ErrSignatureSetEmpty
	}

	// It's most common to only have one rrsig, so we'll keep that instance simple.
	if len(ss) == 1 {
		if ss[0].verified {
			return nil
		}

		err := ss[0].err
		if err != nil {
			return fmt.Errorf("%w / %w", ErrVerifyFailed, err)
		}
		return fmt.Errorf("%w / %w", ErrVerifyFailed, ErrUnableToVerify)
	}

	//---

	type rrsetState struct {
		verifiedSigSeen bool
		err             error
	}

	states := make(map[uint16]rrsetState, len(ss))
	for _, s := range ss {
		state, found := states[s.rtype]

		if !found {
			state = rrsetState{}
		}

		// Once True, it's always true.
		state.verifiedSigSeen = state.verifiedSigSeen || s.verified

		if !s.verified {
			if state.err == nil {
				if s.err == nil {
					state.err = ErrUnableToVerify
				} else {
					state.err = s.err
				}
			} else {
				if s.err == nil {
					state.err = fmt.Errorf("%w / %w", state.err, ErrUnableToVerify)
				} else {
					state.err = fmt.Errorf("%w / %w", state.err, s.err)
				}
			}
		}

		states[s.rtype] = state
	}

	//---

	var err error
	for rtype, state := range states {
		if !state.verifiedSigSeen {
			if err == nil {
				// This should always be the first error in the stack
				err = ErrVerifyFailed
			}

			if state.err == nil {
				// Use this default.
				state.err = ErrUnableToVerify
			}

			err = fmt.Errorf("%w  type %d = (%w)", err, rtype, state.err)
		}
	}

	return err
}

// verifyAllRRSigsPerRRSet a signature set. For a set to be valid, all signatures within it must be valid. A nil error will be returned in this case.
// If one or more errors are found, we make the local policy decision to conclude the whole response is invalid.
// All errors will be returns, wrapped into a single error.
func (ss signatures) verifyAllRRSigsPerRRSet() error {
	if len(ss) == 0 {
		return ErrSignatureSetEmpty
	}

	var err error
	for _, s := range ss {
		if !s.verified {
			if err == nil {
				// This should always be the first error in the stack
				err = ErrVerifyFailed
			}

			// We then nest the more specific errors
			if s.err != nil {
				err = fmt.Errorf("%w / %w", err, s.err)
			} else {
				err = fmt.Errorf("%w / %w", err, ErrUnableToVerify)
			}
		}
	}

	return err
}

// Valid returns if all signatures in the have been successfully verified.
func (ss signatures) Valid() bool {
	return ss.Verify() == nil
}

// extractDSRecords returns all DS records from signatures with a rrtype of DS.
func (ss signatures) extractDSRecords() []*dns.DS {
	parentDSRecords := make([]*dns.DS, 0)
	for _, s := range ss.filterOnType(dns.TypeDS) {
		parentDSRecords = append(parentDSRecords, extractRecords[*dns.DS](s.rrset)...)
	}
	return parentDSRecords
}

func (ss signatures) extractNSECRecords() []*dns.NSEC {
	parentDSRecords := make([]*dns.NSEC, 0)
	for _, s := range ss.filterOnType(dns.TypeNSEC) {
		parentDSRecords = append(parentDSRecords, extractRecords[*dns.NSEC](s.rrset)...)
	}
	return parentDSRecords
}

func (ss signatures) extractNSEC3Records() []*dns.NSEC3 {
	parentDSRecords := make([]*dns.NSEC3, 0)
	for _, s := range ss.filterOnType(dns.TypeNSEC3) {
		parentDSRecords = append(parentDSRecords, extractRecords[*dns.NSEC3](s.rrset)...)
	}
	return parentDSRecords
}
