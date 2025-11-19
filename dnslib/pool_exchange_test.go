package resolver

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"testing"
)

type TestPoolExchangeMockNameserver struct {
	f func(context.Context, *dns.Msg) *Response
}

func (t TestPoolExchangeMockNameserver) exchange(context.Context, *dns.Msg) *Response {
	return t.f(context.Background(), new(dns.Msg))
}

//---

func TestPoolExchange_Empty(t *testing.T) {

	pool := nameserverPool{}

	r := pool.exchange(context.Background(), &dns.Msg{})

	assert.True(t, r.HasError())
	if r.HasError() {
		assert.ErrorIs(t, r.Err, ErrNoPoolConfiguredForZone)
	}

	//---

	// And when the zone is known...
	ctx := context.WithValue(context.Background(), ctxZoneName, "test.zone")
	r = pool.exchange(ctx, &dns.Msg{})

	assert.True(t, r.HasError())
	if r.HasError() {
		assert.ErrorIs(t, r.Err, ErrNoPoolConfiguredForZone)
		assert.Contains(t, r.Err.Error(), "test.zone")
	}

}

func TestPoolExchange_IPv4OnlyFirstTry(t *testing.T) {
	ns1Called := false
	ns1 := TestPoolExchangeMockNameserver{
		func(context.Context, *dns.Msg) *Response {
			ns1Called = true
			return &Response{
				Msg: new(dns.Msg),
			}
		},
	}

	ns2Called := false
	ns2 := TestPoolExchangeMockNameserver{
		func(context.Context, *dns.Msg) *Response {
			ns2Called = true
			return &Response{
				Msg: new(dns.Msg),
			}
		},
	}

	pool := nameserverPool{
		ipv4: []exchanger{ns1, ns2},
	}
	pool.updateIPCount()

	// As ns1 returns a good response, we expect ns2 not to be called.

	r := pool.exchange(context.Background(), &dns.Msg{})
	assert.False(t, r.IsEmpty())
	assert.False(t, r.HasError())

	assert.True(t, ns1Called)
	assert.False(t, ns2Called)
}

func TestPoolExchange_IPv4OnlySecondTry(t *testing.T) {
	ErrTest := errors.New("test error")

	ns1Called := false
	ns1 := TestPoolExchangeMockNameserver{
		func(context.Context, *dns.Msg) *Response {
			ns1Called = true
			return &Response{
				Msg: new(dns.Msg),
				Err: ErrTest,
			}
		},
	}

	ns2Called := false
	ns2 := TestPoolExchangeMockNameserver{
		func(context.Context, *dns.Msg) *Response {
			ns2Called = true
			return &Response{
				Msg: new(dns.Msg),
			}
		},
	}

	pool := nameserverPool{
		ipv4: []exchanger{ns1, ns2},
	}
	pool.updateIPCount()

	// As ns1 returns an error response, we expect ns2 to be called.

	r := pool.exchange(context.Background(), &dns.Msg{})
	assert.False(t, r.IsEmpty())
	assert.False(t, r.HasError())

	assert.True(t, ns1Called)
	assert.True(t, ns2Called)
}

func TestPoolExchange_IPv6Unavailable(t *testing.T) {
	ns1Called := false
	ns1 := TestPoolExchangeMockNameserver{
		func(context.Context, *dns.Msg) *Response {
			ns1Called = true
			return &Response{
				Msg: new(dns.Msg),
			}
		},
	}

	ns2Called := false
	ns2 := TestPoolExchangeMockNameserver{
		func(context.Context, *dns.Msg) *Response {
			ns2Called = true
			return &Response{
				Msg: new(dns.Msg),
			}
		},
	}

	pool := nameserverPool{
		ipv4: []exchanger{ns1},
		ipv6: []exchanger{ns2},
	}
	pool.updateIPCount()

	// Set IPv6 as Unavailable
	ipv6Answered.Store(true)
	ipv6Available.Store(false)

	// Whilst we typically prefer IPv6, if it's unavailable, we only try IPv4.

	r := pool.exchange(context.Background(), &dns.Msg{})
	assert.False(t, r.IsEmpty())
	assert.False(t, r.HasError())

	assert.True(t, ns1Called)
	assert.False(t, ns2Called)

	//---

	// Reset, and now show IPv6 as available. We now expect only IPv6 to be tried.

	ns1Called = false
	ns2Called = false
	ipv6Available.Store(true)

	r = pool.exchange(context.Background(), &dns.Msg{})
	assert.False(t, r.IsEmpty())
	assert.False(t, r.HasError())

	assert.False(t, ns1Called)
	assert.True(t, ns2Called)
}

func TestPoolExchange_IPv6OnlyFirstTry(t *testing.T) {
	ns1Called := false
	ns1 := TestPoolExchangeMockNameserver{
		func(context.Context, *dns.Msg) *Response {
			ns1Called = true
			return &Response{
				Msg: new(dns.Msg),
			}
		},
	}

	ns2Called := false
	ns2 := TestPoolExchangeMockNameserver{
		func(context.Context, *dns.Msg) *Response {
			ns2Called = true
			return &Response{
				Msg: new(dns.Msg),
			}
		},
	}

	pool := nameserverPool{
		ipv6: []exchanger{ns1, ns2},
	}
	pool.updateIPCount()

	// As ns1 returns a good response, we expect ns2 not to be called.

	ipv6Answered.Store(true)
	ipv6Available.Store(true)

	r := pool.exchange(context.Background(), &dns.Msg{})
	assert.False(t, r.IsEmpty())
	assert.False(t, r.HasError())

	assert.True(t, ns1Called)
	assert.False(t, ns2Called)
}

func TestPoolExchange_IPv6OnlySecondTry(t *testing.T) {
	ErrTest := errors.New("test error")

	ns1Called := false
	ns1 := TestPoolExchangeMockNameserver{
		func(context.Context, *dns.Msg) *Response {
			ns1Called = true
			return &Response{
				Msg: new(dns.Msg),
				Err: ErrTest,
			}
		},
	}

	ns2Called := false
	ns2 := TestPoolExchangeMockNameserver{
		func(context.Context, *dns.Msg) *Response {
			ns2Called = true
			return &Response{
				Msg: new(dns.Msg),
			}
		},
	}

	pool := nameserverPool{
		ipv6: []exchanger{ns1, ns2},
	}
	pool.updateIPCount()

	// As ns1 returns an error response, we expect ns2 to be called.

	ipv6Answered.Store(true)
	ipv6Available.Store(true)

	r := pool.exchange(context.Background(), &dns.Msg{})
	assert.False(t, r.IsEmpty())
	assert.False(t, r.HasError())

	assert.True(t, ns1Called)
	assert.True(t, ns2Called)
}

func TestPoolExchange_Error(t *testing.T) {
	ErrTest := errors.New("test error")

	ns1Called := false
	ns1 := TestPoolExchangeMockNameserver{
		func(context.Context, *dns.Msg) *Response {
			ns1Called = true
			return &Response{
				Msg: new(dns.Msg),
				Err: ErrTest,
			}
		},
	}

	ns2Called := false
	ns2 := TestPoolExchangeMockNameserver{
		func(context.Context, *dns.Msg) *Response {
			ns2Called = true
			return &Response{
				Msg: new(dns.Msg),
				Err: ErrTest,
			}
		},
	}

	pool := nameserverPool{
		ipv4: []exchanger{ns1},
		ipv6: []exchanger{ns2},
	}
	pool.updateIPCount()

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)

	// As ns1 returns an error response, we expect ns2 to be called.

	ipv6Answered.Store(true)
	ipv6Available.Store(true)

	r := pool.exchange(context.Background(), msg)
	assert.False(t, r.IsEmpty())
	assert.True(t, r.HasError())
	if r.HasError() {
		assert.ErrorIs(t, r.Err, ErrTest)
		assert.ErrorIs(t, r.Err, ErrUnableToResolveAnswer)
		assert.Contains(t, r.Err.Error(), "example.com.")
	}

	assert.True(t, ns1Called)
	assert.True(t, ns2Called)

	//---

	// And when the zone is known...
	ctx := context.WithValue(context.Background(), ctxZoneName, "test.zone")

	r = pool.exchange(ctx, msg)
	assert.False(t, r.IsEmpty())
	assert.True(t, r.HasError())
	if r.HasError() {
		assert.ErrorIs(t, r.Err, ErrTest)
		assert.ErrorIs(t, r.Err, ErrUnableToResolveAnswer)
		assert.Contains(t, r.Err.Error(), "example.com.")
		assert.Contains(t, r.Err.Error(), "test.zone")
	}
}
