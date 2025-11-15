package pool

import (
	"github.com/miekg/dns"
	"sync"
)

// MsgPool is a pool for DNS messages to reduce allocations.
var MsgPool = sync.Pool{
	New: func() interface{} {
		return new(dns.Msg)
	},
}

// GetMsg retrieves a DNS message from the pool.
func GetMsg() *dns.Msg {
	return MsgPool.Get().(*dns.Msg)
}

// PutMsg returns a DNS message to the pool.
func PutMsg(m *dns.Msg) {
	// Reset the message to a zero-like state before putting it back in the pool.
	*m = dns.Msg{}
	MsgPool.Put(m)
}
