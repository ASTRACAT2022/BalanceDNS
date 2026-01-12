package resolver

import "errors"

var (
	ErrNotRecursionDesired         = errors.New("only recursive queries are supported via this server")
	ErrNilMessageSentToExchange    = errors.New("nil message sent to exchange")
	ErrNoPoolConfiguredForZone     = errors.New("no nameserver pool configured for zone")
	ErrFailedToGetDNSKEYs          = errors.New("failed looking up DNSKEY records")
	ErrFailedCreatingZoneAndPool   = errors.New("failed creating nameserver pool for zone")
	ErrFailedEnrichingPool         = errors.New("failed enriching nameserver pool for zone")
	ErrUnableToResolveAnswer       = errors.New("failed resolving answer")
	ErrNextNameserversNotFound     = errors.New("the onward nameservers cannot be found")
	ErrEmptyResponse               = errors.New("the received response is empty")
	ErrInternalError               = errors.New("internal error")
	ErrMaxQueriesPerRequestReached = errors.New("max queries per request reached")
)
