package dnssec

import (
	"errors"
	"fmt"
)

var (
	ErrNoParentDSRecords              = errors.New("no DS records passed")
	ErrUnableToFetchDSRecord          = errors.New("unable to fetch missing DS record")
	ErrKeysNotFound                   = errors.New("no dnskey records found for zone")
	ErrKeySigningKeysNotFound         = errors.New("no dnskey records found that match the parent ds records")
	ErrAuthSignerNameMismatch         = errors.New("auth signer name does match the zone's origin")
	ErrSignatureSetEmpty              = errors.New("cannot verify an empty signature set")
	ErrUnableToVerify                 = errors.New("unable to verify signature")
	ErrVerifyFailed                   = errors.New("signature verification failed")
	ErrNoKeyFoundForSignature         = errors.New("no key found for signature")
	ErrInvalidTime                    = errors.New("current time is outside of the msg validity period")
	ErrInvalidSignature               = errors.New("msg signature is invalid")
	ErrInvalidLabelCount              = errors.New("number of labels in the rrset owner name is less the value in the rrsig rr's labels field")
	ErrMultipleVaryingSignerNames     = errors.New("rrsigs in the response contain multiple varying signer names")
	ErrNSRecordsHaveMismatchingOwners = errors.New("the ns records in the authority section do not have matching owners")
	ErrFailsafeResponse               = errors.New("unable to determine if response is delegating, positive or negative. we fail-safe to bogus")
	ErrUnexpectedSignatureCount       = errors.New("an unexpected number of rrsig records were found given the rrsets seen")
	ErrMultipleWildcardSignatures     = errors.New("multiple wildcard signatures seen")
	ErrDSLookupLoop                   = errors.New("the maximum number of ds record lookups has been reached")
	ErrNotSubdomain                   = errors.New("domain is not a subdomain of another")
	ErrSameName                       = errors.New("domain names are the same")
	ErrUnknown                        = errors.New("unknown error: unable to process response")
	ErrSignerNameNotParentOfQName     = errors.New("the signer name is not a parent of the qname")
	ErrNoResults                      = errors.New("no results have been processed")
	ErrBogusResultFound               = errors.New("we've deemed the result bogus")
	ErrBogusDoeRecordsNotFound        = errors.New("denial of existence records missing")
	ErrBogusWildcardDoeNotFound       = errors.New("missing doe for qname when answer synthesised from a wildcard")
	ErrNotAllInputsProcessed          = errors.New("not all inputs have been processed")
	ErrDuplicateInputForZone          = errors.New("duplicate input for zone")
)

type MissingDSRecordError struct {
	name string
}

func (e *MissingDSRecordError) RName() string {
	return e.name
}

func (e *MissingDSRecordError) Error() string {
	return fmt.Sprintf("missing DS record: %s", e.name)
}
