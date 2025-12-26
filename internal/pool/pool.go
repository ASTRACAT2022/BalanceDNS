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

	// BytePool is a pool of byte slices for buffer reuse.
	// We use a fixed size buffer pool (e.g. 4KB which covers most DNS packets + overhead).
	// EDNS0 can go up to 65535 but typically 4096 or less.
	BytePool = &sync.Pool{
		New: func() interface{} {
			b := make([]byte, 4096)
			return &b
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
	// Reset slices to nil to release memory, but we might want to keep capacity?
	// dns.Msg fields are slices of RRs.
	// If we want to reduce GC, we should reuse the underlying arrays.
	// But dns library might reallocate anyway.
	// Safest is nil for now to avoid leaking data.
	msg.Question = nil
	msg.Answer = nil
	msg.Ns = nil
	msg.Extra = nil
	DnsMsgPool.Put(msg)
}

// GetBytes retrieves a byte slice from the pool.
func GetBytes() *[]byte {
	return BytePool.Get().(*[]byte)
}

// PutBytes returns a byte slice to the pool.
func PutBytes(b *[]byte) {
	// Optional: zero out buffer if needed, but for performance we usually don't.
	// We just assume caller handles length correctly.
	BytePool.Put(b)
}
