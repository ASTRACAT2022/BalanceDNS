package pool

import (
	"sync"

	"github.com/miekg/dns"
)

var (
	// DnsMsgPool is a pool of *dns.Msg objects.
	DnsMsgPool = &sync.Pool{
		New: func() interface{} {
			return new(dns.Msg)
		},
	}
)

// GetDnsMsg retrieves a *dns.Msg from the pool.
func GetDnsMsg() *dns.Msg {
	return DnsMsgPool.Get().(*dns.Msg)
}

// PutDnsMsg returns a *dns.Msg to the pool.
func PutDnsMsg(msg *dns.Msg) {
	// Reset the message before putting it back into the pool.
	msg.Id = 0
	msg.Response = false
	msg.Opcode = 0
	msg.Authoritative = false
	msg.Truncated = false
	msg.RecursionDesired = false
	msg.RecursionAvailable = false
	msg.Zero = false
	msg.AuthenticatedData = false
	msg.CheckingDisabled = false
	msg.Rcode = 0
	msg.Question = nil
	msg.Answer = nil
	msg.Ns = nil
	msg.Extra = nil
	DnsMsgPool.Put(msg)
}
