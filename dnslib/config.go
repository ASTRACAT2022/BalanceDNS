package resolver

import (
	"github.com/nsmithuk/resolver/dnssec"
	"time"
)

const (
	DefaultMaxAllowedTTL = uint32(60 * 60 * 48) // 48 Hours

	DefaultMaxQueriesPerRequest = uint32(100)

	DefaultDesireNumberOfNameserversPerZone = 3

	DefaultLazyEnrichment = false

	DefaultSuppressBogusResponseSections = true

	DefaultRemoveAuthoritySectionForPositiveAnswers  = true
	DefaultRemoveAdditionalSectionForPositiveAnswers = true

	DefaultTimeoutUDP = 150 * time.Millisecond
	DefaultTimeoutTCP = 600 * time.Millisecond
)

var (
	// MaxAllowedTTL define the maximum TTL that we'll cache any record for. This overrides any TTLs set by records
	// we receive. Shorter TTLs on received records will still be respected.
	MaxAllowedTTL = DefaultMaxAllowedTTL

	// MaxQueriesPerRequest gives the maximum number of DNS lookups that can occur some a single request to resolver.Exchange().
	// This will include all requests for all the requests from the root, to the leaf; plus any enrichment needed.
	// It's main task is to prevent infinite loops.
	// Note that lookups for DNSKEY and DS records are excluded from this count.
	MaxQueriesPerRequest = DefaultMaxQueriesPerRequest

	// DesireNumberOfNameserversPerZone The number of nameservers, with IP addresses, that we ideally know for a zone.
	// If we know less than this, and LazyEnrichment is _not_ enabled, then we'll set-out to gather more addresses.
	DesireNumberOfNameserversPerZone = DefaultDesireNumberOfNameserversPerZone

	// LazyEnrichment - if true, we put less effort into gathering the IP address details of a zone's nameservers.
	// We will still always gather the minimum to complete the query, but no more.
	// Enabling LazyEnrichment can reduce reliability over multiple queries.
	LazyEnrichment = DefaultLazyEnrichment

	// SuppressBogusResponseSections indicates if a response Answer, Authority and Extra sections should
	// be suppressed if a response is Bogus. The default and recommended value is true which
	// aligns the resolver with https://datatracker.ietf.org/doc/html/rfc4035#section-5.5
	SuppressBogusResponseSections = DefaultSuppressBogusResponseSections

	// RemoveAuthoritySectionForPositiveAnswers indicates if the Authority section should be returned when it's deemed
	// that it's record have no material impact on the result. e.g. it only contains nameserver records.
	RemoveAuthoritySectionForPositiveAnswers  = DefaultRemoveAuthoritySectionForPositiveAnswers
	RemoveAdditionalSectionForPositiveAnswers = DefaultRemoveAdditionalSectionForPositiveAnswers
)

//---

// Cache Default (disabled) cache function.
var Cache CacheInterface = nil

//---

type Logger func(string)

// Default logging functions just black-hole the input.

var Query Logger = func(s string) {}
var Debug Logger = func(s string) {}
var Info Logger = func(s string) {}
var Warn Logger = func(s string) {}

//---

func init() {
	go IPv6Available()
	dnssec.Info = func(s string) {
		Info(s)
	}
	dnssec.Warn = func(s string) {
		Warn(s)
	}
	dnssec.Debug = func(s string) {
		Debug(s)
	}
}
