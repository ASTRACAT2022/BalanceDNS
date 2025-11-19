package resolver

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestCName_FoundAuthoritativeSuccess(t *testing.T) {
	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.Background()

	rmsg := qmsg.SetReply(&dns.Msg{})

	rmsg.Authoritative = true

	rmsg.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME}, Target: "other.example.net."},
	}
	inputResponse := &Response{
		Msg: rmsg,
	}

	resolver := getTestResolverWithRoot()

	a1 := &dns.A{Hdr: dns.RR_Header{Name: "other.example.net.", Rrtype: dns.TypeA}, A: net.IPv4(192, 0, 2, 1)}
	a2 := &dns.A{Hdr: dns.RR_Header{Name: "other.example.net.", Rrtype: dns.TypeA}, A: net.IPv4(192, 0, 2, 2)}
	a3 := &dns.A{Hdr: dns.RR_Header{Name: "other.example.net.", Rrtype: dns.TypeA}, A: net.IPv4(192, 0, 2, 3)}

	exchangeCalled := 0
	resolver.funcs.getExchanger = func() exchanger {
		return &mockExchanger{
			mockExchange: func(ctx context.Context, msg *dns.Msg) *Response {
				exchangeCalled++
				assert.Equal(t, "other.example.net.", msg.Question[0].Name)
				return &Response{
					Msg: &dns.Msg{
						MsgHdr: dns.MsgHdr{Authoritative: true},
						Answer: []dns.RR{a1},
						Ns:     []dns.RR{a2},
						Extra:  []dns.RR{a3},
					},
				}
			},
		}
	}

	err := cname(ctx, qmsg, inputResponse, resolver.funcs.getExchanger())

	assert.NoError(t, err)
	assert.Equal(t, 1, exchangeCalled)
	assert.Contains(t, rmsg.Answer, a1)
	assert.Contains(t, rmsg.Ns, a2)
	assert.Contains(t, rmsg.Extra, a3)
	assert.Equal(t, dns.RcodeSuccess, rmsg.Rcode)
	assert.True(t, rmsg.Authoritative)
}

func TestCName_FoundUnauthoritativeSrvFail(t *testing.T) {
	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.Background()

	rmsg := qmsg.SetReply(&dns.Msg{})

	rmsg.Authoritative = true

	rmsg.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME}, Target: "other.example.net."},
	}
	inputResponse := &Response{
		Msg: rmsg,
	}

	resolver := getTestResolverWithRoot()

	a := &dns.A{Hdr: dns.RR_Header{Name: "other.example.net.", Rrtype: dns.TypeA}, A: net.IPv4(192, 0, 2, 1)}

	exchangeCalled := 0
	resolver.funcs.getExchanger = func() exchanger {
		return &mockExchanger{
			mockExchange: func(ctx context.Context, msg *dns.Msg) *Response {
				exchangeCalled++
				assert.Equal(t, "other.example.net.", msg.Question[0].Name)
				return &Response{
					Msg: &dns.Msg{
						MsgHdr: dns.MsgHdr{Authoritative: false, Rcode: dns.RcodeServerFailure},
						Answer: []dns.RR{a},
					},
				}
			},
		}
	}

	err := cname(ctx, qmsg, inputResponse, resolver.funcs.getExchanger())

	assert.NoError(t, err)
	assert.Equal(t, 1, exchangeCalled)
	assert.Contains(t, rmsg.Answer, a)
	assert.Equal(t, dns.RcodeServerFailure, rmsg.Rcode)
	assert.False(t, rmsg.Authoritative)
}

func TestCName_FoundAnswerAlreadyKnown(t *testing.T) {

	// If we've already got an answer for the target (either QType or CNAME), then we don't follow it.

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.Background()

	rmsg := qmsg.SetReply(&dns.Msg{})

	rmsg.Authoritative = true

	rmsg.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME}, Target: "other.example.net."},
		&dns.CNAME{Hdr: dns.RR_Header{Name: "other.example.net.", Rrtype: dns.TypeA}, Target: "different.example.net."},
		&dns.A{Hdr: dns.RR_Header{Name: "different.example.net.", Rrtype: dns.TypeA}, A: net.IPv4(192, 0, 2, 1)},
	}
	inputResponse := &Response{
		Msg: rmsg,
	}

	resolver := getTestResolverWithRoot()

	exchangeCalled := 0
	resolver.funcs.getExchanger = func() exchanger {
		return &mockExchanger{
			mockExchange: func(ctx context.Context, msg *dns.Msg) *Response {
				exchangeCalled++
				assert.Equal(t, "other.example.net.", msg.Question[0].Name)
				return &Response{}
			},
		}
	}

	err := cname(ctx, qmsg, inputResponse, resolver.funcs.getExchanger())
	assert.NoError(t, err)
	assert.Equal(t, 0, exchangeCalled)
}

func TestCName_ErrorReturned(t *testing.T) {
	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.Background()

	rmsg := qmsg.SetReply(&dns.Msg{})

	rmsg.Authoritative = true

	rmsg.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME}, Target: "other.example.net."},
	}
	inputResponse := &Response{
		Msg: rmsg,
	}

	resolver := getTestResolverWithRoot()

	ErrTest := errors.New("test error")

	exchangeCalled := 0
	resolver.funcs.getExchanger = func() exchanger {
		return &mockExchanger{
			mockExchange: func(ctx context.Context, msg *dns.Msg) *Response {
				exchangeCalled++
				assert.Equal(t, "other.example.net.", msg.Question[0].Name)
				return &Response{
					Msg: &dns.Msg{},
					Err: ErrTest,
				}
			},
		}
	}

	err := cname(ctx, qmsg, inputResponse, resolver.funcs.getExchanger())

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrTest)
	assert.Equal(t, 1, exchangeCalled)
}
