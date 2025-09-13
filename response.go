package resolver

import (
	"context"
	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver/dnssec"
	"time"
)

type Response struct {
	Msg      *dns.Msg
	Err      error
	Duration time.Duration
	Doe      dnssec.DenialOfExistenceState
	Auth     dnssec.AuthenticationResult
}

func (r *Response) HasError() bool {
	return r != nil && r.Err != nil
}

func (r *Response) IsEmpty() bool {
	return r == nil || r.Msg == nil
}

func (r *Response) truncated() bool {
	if r.IsEmpty() {
		return false
	}
	return r.Msg.Truncated
}

func newResponseError(err error) *Response {
	return &Response{
		Err: err,
	}
}

//---

type exchanger interface {
	exchange(context.Context, *dns.Msg) *Response
}

type expiringExchanger interface {
	exchanger
	expired() bool
}
