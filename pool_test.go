package resolver

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestNewNameserverPool_Create(t *testing.T) {
	// Setup: Define valid nameservers (NS) and A/AAAA records
	nsRecords := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns3.example.com."},
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns4.example.com."},
	}

	// A (IPv4) and AAAA (IPv6) records for the nameservers
	extraRecords := []dns.RR{
		// ns1.example.com IPv4 and IPv6
		&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA}, A: net.IPv4(192, 0, 2, 1)},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeAAAA}, AAAA: net.IP{0x20, 0x01, 0xdb, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}},

		// ns2.example.com IPv4 and IPv6
		&dns.A{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeA}, A: net.IPv4(192, 0, 2, 2)},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeAAAA}, AAAA: net.IP{0x20, 0x01, 0xdb, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2}},

		// ns3.example.com IPv4 and IPv6
		&dns.A{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeA}, A: net.IPv4(192, 0, 2, 3)},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeAAAA}, AAAA: net.IP{0x20, 0x01, 0xdb, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3}},

		// ns4.example.com IPv4 only, just so we have a different number of each.
		&dns.A{Hdr: dns.RR_Header{Name: "ns4.example.com.", Rrtype: dns.TypeA}, A: net.IPv4(192, 0, 2, 4)},
	}

	// Execute: Create the nameserver pool
	pool := newNameserverPool(nsRecords, extraRecords)

	// Assertions: Ensure the pool contains the expected nameservers with correct addresses
	assert.NotNil(t, pool)

	assert.Len(t, pool.hostsWithoutAddresses, 0)
	assert.Len(t, pool.ipv4, 4)
	assert.Equal(t, uint32(4), pool.countIPv4())

	assert.Len(t, pool.ipv6, 3)
	assert.Equal(t, uint32(3), pool.countIPv6())

	ips := make([]string, 7)
	for i, ip := range append(pool.ipv4, pool.ipv6...) {
		ips[i] = ip.(*nameserver).addr
	}

	assert.Contains(t, ips, "192.0.2.1")
	assert.Contains(t, ips, "192.0.2.2")
	assert.Contains(t, ips, "192.0.2.3")
	assert.Contains(t, ips, "192.0.2.4")
	assert.Contains(t, ips, "2001:db08::1")
	assert.Contains(t, ips, "2001:db08::2")
	assert.Contains(t, ips, "2001:db08::3")

	//---

	assert.True(t, pool.hasIPv4())
	assert.True(t, pool.hasIPv6())

	//---

	seen := make([]string, 0, 4)

	// There are 4 IPv4 addresses, thus we should get a unique address 4 times, then the 5th should be a repeat.
	for i := 0; i < 4; i++ {
		ns := pool.getIPv4().(*nameserver)
		assert.NotContains(t, ns.addr, seen)
		seen = append(seen, ns.addr)
	}
	ns := pool.getIPv4().(*nameserver)
	assert.Contains(t, seen, ns.addr)

	//---

	seen = make([]string, 0, 3)

	// There are 3 IPv6 addresses, thus we should get a unique address 3 times, then the 4th should be a repeat.
	for i := 0; i < 3; i++ {
		ns := pool.getIPv6().(*nameserver)
		assert.NotContains(t, ns.addr, seen)
		seen = append(seen, ns.addr)
	}
	ns = pool.getIPv6().(*nameserver)
	assert.Contains(t, seen, ns.addr)

}

func TestFindAddressesForHostname_BasicFunctionality(t *testing.T) {
	hostname := "example.com."
	records := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: hostname, Ttl: 300}, A: net.IP{192, 0, 2, 1}},
		&dns.AAAA{Hdr: dns.RR_Header{Name: hostname, Ttl: 200}, AAAA: net.IP{32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
	}
	a, aaaa, ttl := findAddressesForHostname(hostname, records)

	assert.Equal(t, []*dns.A{records[0].(*dns.A)}, a)
	assert.Equal(t, []*dns.AAAA{records[1].(*dns.AAAA)}, aaaa)
	assert.Equal(t, uint32(200), ttl)
}

func TestFindAddressesForHostname_EmptyInput(t *testing.T) {
	hostname := "example.com."
	a, aaaa, ttl := findAddressesForHostname(hostname, []dns.RR{})

	assert.Len(t, a, 0)
	assert.Len(t, aaaa, 0)
	assert.Equal(t, MaxAllowedTTL, ttl)
}

func TestFindAddressesForHostname_MixedRecords(t *testing.T) {
	hostname := "example.com."
	records := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: hostname, Ttl: 300}, A: net.IP{192, 0, 2, 1}},
		&dns.TXT{Hdr: dns.RR_Header{Name: "unrelated.com.", Ttl: 100}},
	}
	a, aaaa, ttl := findAddressesForHostname(hostname, records)

	assert.Len(t, a, 1)
	assert.Len(t, aaaa, 0)
	assert.Equal(t, uint32(300), ttl)
}

func TestFindAddressesForHostname_MinimumTTLCalculation(t *testing.T) {
	hostname := "example.com."
	records := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: hostname, Ttl: 300}, A: net.IP{192, 0, 2, 1}},
		&dns.A{Hdr: dns.RR_Header{Name: hostname, Ttl: 100}, A: net.IP{192, 0, 2, 2}},
	}
	_, _, ttl := findAddressesForHostname(hostname, records)

	assert.Equal(t, uint32(100), ttl)
}

func TestFindAddressesForHostname_CaseInsensitivity(t *testing.T) {
	hostname := "example.com."
	records := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "Example.Com.", Ttl: 200}, A: net.IP{192, 0, 2, 1}},
	}
	a, _, _ := findAddressesForHostname(hostname, records)

	assert.Len(t, a, 1)
}

func TestExpired_NotSet(t *testing.T) {
	pool := nameserverPool{}

	// For example, the root zone never expires.
	assert.False(t, pool.expired(), "we expect false as no TTL was set. this essentially means expiry is disabled")
}

func TestExpired_False(t *testing.T) {
	pool := nameserverPool{}

	// Expires 60 seconds in the future.
	expires := time.Now().Add(time.Second * 60)
	pool.expires.Store(expires.Unix())

	assert.False(t, pool.expired())
}

func TestExpired_True(t *testing.T) {
	pool := nameserverPool{}

	// Expires 60 seconds in the past.
	expires := time.Now().Add(time.Second * -60)
	pool.expires.Store(expires.Unix())

	assert.True(t, pool.expired())
}
