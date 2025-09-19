package goresolver

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/domainr/dnsr"
)

var (
	ErrNoData = errors.New("no data for this record")
)

const (
	// DefaultTimeout is the default timeout for DNS queries.
	DefaultTimeout = 2 * time.Second
	DefaultCacheTTL = 5 * time.Minute
	DefaultNegativeCacheTTL = 1 * time.Minute
)

// Resolver contains the client configuration for github.com/miekg/dns,
// and the upstream DNS server addresses.
type Resolver struct {
	dnsClient       *dns.Client
	dnsClientConfig *dns.ClientConfig
	queryFn         queryFunc
	Cache           *DNSCache
	dnsrResolver    *dnsr.Resolver // Add dnsr.Resolver
}

type queryFunc func(name string, qtype uint16) (*dns.Msg, error)

// Errors returned by the verification/validation methods at all levels.
var (
	ErrResourceNotSigned    = errors.New("resource is not signed with RRSIG")
	ErrNoResult             = errors.New("requested RR not found")
	ErrNsNotAvailable       = errors.New("no name server to answer the question")
	ErrDnskeyNotAvailable   = errors.New("DNSKEY RR does not exist")
	ErrDsNotAvailable       = errors.New("DS RR does not exist")
	ErrInvalidRRsig         = errors.New("invalid RRSIG")
	ErrForgedRRsig          = errors.New("forged RRSIG header")
	ErrRrsigValidationError = errors.New("RR doesn't validate against RRSIG")
	ErrRrsigValidityPeriod  = errors.New("invalid RRSIG validity period")
	ErrUnknownDsDigestType  = errors.New("unknown DS digest type")
	ErrDsInvalid            = errors.New("DS RR does not match DNSKEY")
	ErrInvalidQuery         = errors.New("invalid query input")
)

// NewDNSMessage creates and initializes a dns.Msg object, with EDNS enabled
// and the DO (DNSSEC OK) flag set.  It returns a pointer to the created
// object.
func NewDNSMessage(qname string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)
	return m
}

func (r *Resolver) Query(name string, qtype uint16) (*dns.Msg, error) {
	cacheKey := fmt.Sprintf("%s:%d", name, qtype)

	// Try to get from cache first
	if r.Cache != nil {
		if cachedMsg, timeLeft, found, isNegative := r.Cache.Get(cacheKey); found {
			if isNegative {
				return nil, ErrNoData
			}
			// If the record is about to expire, prefetch it
			if timeLeft < DefaultCacheTTL/2 && timeLeft > 0 {
				go r.Prefetch(name, qtype)
			}
			return cachedMsg, nil
		}
	}

	// If the name is an IP address, perform a reverse lookup
	if net.ParseIP(name) != nil {
		return r.queryFn(name, qtype)
	}

	// Check if it's a local domain
	if r.isLocalDomain(name) {
		return r.queryFn(name, qtype)
	}

	// Otherwise, query upstream DNS servers
	msg, err := r.queryUpstream(name, qtype)

	// Add to cache if successful
	if r.Cache != nil && err == nil && msg != nil && msg.Rcode == dns.RcodeSuccess {
		r.Cache.Add(cacheKey, msg, DefaultCacheTTL, false)
	} else if r.Cache != nil && err != nil {
		// Negative cache for errors
		r.Cache.Add(cacheKey, nil, DefaultNegativeCacheTTL, true)
	}

	// Cache successful responses
	if err == nil && msg != nil && msg.Rcode == dns.RcodeSuccess {
		r.Cache.Add(cacheKey, msg, DefaultCacheTTL, false)
	} else if err == nil && msg != nil && (msg.Rcode == dns.RcodeNameError || msg.Rcode == dns.RcodeServerFailure) {
		// Cache negative responses
		r.Cache.Add(cacheKey, msg, DefaultNegativeCacheTTL, true)
	}

	return msg, err
}

// Prefetch asynchronously queries and updates the cache for a given DNS record.
func (r *Resolver) Prefetch(name string, qtype uint16) {
	log.Printf("Prefetching %s (type %s)", name, dns.TypeToString[qtype])
	msg, err := r.queryUpstream(name, qtype)
	if err == nil && msg != nil && msg.Rcode == dns.RcodeSuccess {
		cacheKey := fmt.Sprintf("%s:%d", name, qtype)
		r.Cache.Add(cacheKey, msg, DefaultCacheTTL, false)
		log.Printf("Prefetched %s (type %s) successfully", name, dns.TypeToString[qtype])
	} else {
		log.Printf("Failed to prefetch %s (type %s): %v", name, dns.TypeToString[qtype], err)
	}
}

func (r *Resolver) isLocalDomain(name string) bool {
	for _, domain := range r.dnsClientConfig.Search {
		if dns.IsSubDomain(domain, name) {
			return true
		}
	}
	return false
}

func (r *Resolver) queryUpstream(name string, qtype uint16) (*dns.Msg, error) {
	m := NewDNSMessage(name, qtype)

	// Try all configured upstream servers
	for _, server := range r.dnsClientConfig.Servers {
		resp, _, err := r.dnsClient.Exchange(m, net.JoinHostPort(server, r.dnsClientConfig.Port))
		if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
			return resp, nil
		}
	}
	return nil, fmt.Errorf("failed to query upstream DNS servers for %s", name)
}

// localQuery takes a query name (qname) and query type (qtype) and
// performs a DNS lookup by calling dnsClient.Exchange.
// It returns the answer in a *dns.Msg (or nil in case of an error, in which
// case err will be set accordingly.)
func (r *Resolver) localQuery(qname string, qtype uint16) (*dns.Msg, error) {
	dnsMessage := NewDNSMessage(qname, qtype)

	if r.dnsClientConfig == nil {
		return nil, errors.New("dns client not initialized")
	}

	for _, server := range r.dnsClientConfig.Servers {
		resp, _, err := r.dnsClient.Exchange(dnsMessage, server+":"+r.dnsClientConfig.Port)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Rcode == dns.RcodeNameError || resp.Rcode == dns.RcodeSuccess {
			return resp, err
		}
	}
	return nil, ErrNsNotAvailable
}

// queryDelegation takes a domain name and fetches the DS and DNSKEY records
// in that zone.  Returns a SignedZone or nil in case of error.
func (r *Resolver) queryDelegation(domainName string) (signedZone *SignedZone, err error) {

	signedZone = NewSignedZone(domainName)

	signedZone.dnskey, err = r.queryRRset(domainName, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	for _, rr := range signedZone.dnskey.rrSet {
		signedZone.addPubKey(rr.(*dns.DNSKEY))
	}

	signedZone.ds, _ = r.queryRRset(domainName, dns.TypeDS)

	return signedZone, nil
}

// RecursiveQuery performs a recursive DNS query using the dnsr library.
func (r *Resolver) RecursiveQuery(name string, qtype string) ([]*dnsr.RR, error) {
	rrs := r.dnsrResolver.Resolve(name, qtype)
	var result []*dnsr.RR
	for _, rr := range rrs {
		rrCopy := rr // Create a copy to take address of
		result = append(result, &rrCopy)
	}
	return result, nil
}

// NewResolver initializes the package Resolver instance using the default
// dnsClientConfig.
func NewResolver(resolvConf string) (*Resolver, error) {
	resolver := &Resolver{}
	resolver.dnsClient = &dns.Client{
		ReadTimeout: DefaultTimeout,
	}
	var err error
	resolver.dnsClientConfig, err = dns.ClientConfigFromFile(resolvConf)
	if err != nil {
		return nil, err
	}
	resolver.queryFn = resolver.localQuery
	resolver.Cache = NewDNSCache(16, 1024) // Initialize cache with 16 shards and 1024 max size per shard
	resolver.dnsrResolver = dnsr.NewResolver() // Initialize dnsr.Resolver without cache
	return resolver, nil
}
