package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"sync"
	"sync/atomic"
	"time"
)

//---------------------------------------------------------------------------------

type zone interface {
	exchanger
	name() string
	parent() string
	expired() bool
	clone(name, parent string) zone
	soa(ctx context.Context, name string) (*dns.SOA, error)
	dnskeys(ctx context.Context) ([]dns.RR, error)
}

type zoneImpl struct {
	zoneName   string
	parentName string

	pool  expiringExchanger
	calls atomic.Uint64

	dnskeyRecords []dns.RR
	dnskeyExpiry  time.Time
	dnskeyLock    sync.Mutex
}

func (z *zoneImpl) name() string {
	return z.zoneName
}

func (z *zoneImpl) parent() string {
	return z.parentName
}

func (z *zoneImpl) expired() bool {
	return z.pool.expired()
}

func (z *zoneImpl) clone(name, parent string) zone {
	// TODO: debugging
	if canonicalName(name) == canonicalName(parent) || !dns.IsSubDomain(parent, name) {
		Debug(fmt.Sprintf("child %s is not actually a child of parent: %s", name, parent))
		panic("invalid clone")
	}
	return &zoneImpl{
		zoneName:   canonicalName(name),
		parentName: canonicalName(parent),
		pool:       z.pool,
	}
}

func (z *zoneImpl) exchange(ctx context.Context, m *dns.Msg) *Response {

	z.calls.Add(1)

	if Cache != nil {
		if msg, err := Cache.Get(z.zoneName, m.Question[0]); err != nil {
			Warn(fmt.Errorf("error trying to perform a cache lookup for zone [%s]: %w", z.zoneName, err).Error())
		} else if msg != nil {
			trace, _ := ctx.Value(CtxTrace).(*Trace)
			Query(fmt.Sprintf(
				"%s-%d: response for [%s] %s in zone [%s] found in cache",
				trace.ShortID(),
				trace.Iteration(),
				m.Question[0].Name,
				TypeToString(m.Question[0].Qtype),
				z.zoneName,
			))
			return &Response{Msg: msg.Copy()}
		}
	}

	//---

	if z.pool == nil {
		return newResponseError(fmt.Errorf("%w [%s]", ErrNoPoolConfiguredForZone, z.zoneName))
	}

	ctx = context.WithValue(ctx, ctxZoneName, z.zoneName)
	response := z.pool.exchange(ctx, m)

	//---

	if Cache != nil && !response.IsEmpty() && !response.HasError() {
		go func(zone string, question dns.Question, msg *dns.Msg) {
			// We never cache OPT records.
			msg.Extra = removeRecordsOfType(msg.Extra, dns.TypeOPT)

			if err := Cache.Update(zone, question, msg); err != nil {
				Warn(fmt.Errorf("error trying to perform a cache update for zone [%s]: %w", z.zoneName, err).Error())
			}
		}(z.zoneName, m.Question[0], response.Msg.Copy())
	}

	//---

	return response
}

func (z *zoneImpl) soa(ctx context.Context, name string) (*dns.SOA, error) {
	soaMsg := new(dns.Msg)
	soaMsg.SetQuestion(dns.Fqdn(name), dns.TypeSOA)
	soaMsg.RecursionDesired = false
	response := z.exchange(ctx, soaMsg)

	if response.IsEmpty() {
		return nil, ErrEmptyResponse
	}
	if response.HasError() {
		return nil, response.Err
	}
	if !recordsOfTypeExist(response.Msg.Answer, dns.TypeSOA) {
		return nil, nil
	}

	soas := extractRecords[*dns.SOA](response.Msg.Answer)
	if len(soas) != 1 {
		return nil, fmt.Errorf("we expect only a single SOA for a given name / zone. we got %d", len(soas))
	}

	return soas[0], nil
}

func (z *zoneImpl) dnskeys(ctx context.Context) ([]dns.RR, error) {
	z.dnskeyLock.Lock()

	// We base this check on the expiry only, as `z.dnskeyRecords` can be both nil and valid.
	if !z.dnskeyExpiry.IsZero() && !z.dnskeyExpiry.Before(time.Now()) {
		keys := z.dnskeyRecords
		z.dnskeyLock.Unlock()
		return keys, nil
	}
	defer z.dnskeyLock.Unlock()

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(z.zoneName), dns.TypeDNSKEY)
	msg.SetEdns0(4096, true)
	msg.RecursionDesired = false
	response := z.exchange(ctx, msg)
	if response.HasError() {
		return nil, fmt.Errorf("%w for %s: %w", ErrFailedToGetDNSKEYs, z.zoneName, response.Err)
	}
	if response.IsEmpty() {
		return nil, fmt.Errorf("%w for %s: reponse is empty", ErrFailedToGetDNSKEYs, z.zoneName)
	}

	if len(response.Msg.Answer) == 0 {
		// If we got no answer, we'll put a short cache on that, rather than the MaxAllowedTTL.
		z.dnskeyExpiry = time.Now().Add(time.Second * 60)
		return nil, nil
	}

	z.dnskeyRecords = response.Msg.Answer

	var ttl = MaxAllowedTTL
	for _, rr := range z.dnskeyRecords {
		ttl = min(ttl, rr.Header().Ttl)
	}
	z.dnskeyExpiry = time.Now().Add(time.Duration(ttl) * time.Second)

	return z.dnskeyRecords, nil
}
