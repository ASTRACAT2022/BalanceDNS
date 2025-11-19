package resolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestCreateZone_SuccessWithoutEnrichment(t *testing.T) {
	// Setup
	mockExchanger := new(MockExpiringExchanger)

	// Prepare nameservers and extra records. A primed pool is, by default, >= 3 nameservers with glue records.
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
		{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeNS}, Ns: "ns3.example.com."},
	}
	extra := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.53")},
		&dns.A{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.54")},
		&dns.A{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.55")},
	}
	ctx := context.TODO()

	// Execute
	z, err := createZone(ctx, "example.com.", "com.", nameservers, extra, mockExchanger)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, z)
	assert.Equal(t, "example.com.", z.name())

	// We'll peek under the covers to ensure the pool was created as expected.
	pool, ok := z.(*zoneImpl).pool.(*nameserverPool)
	assert.True(t, ok)
	assert.Equal(t, pool.status(), PoolPrimed)
}

func TestCreateZone_PoolCreationFailsWithoutEnrichment(t *testing.T) {
	// Setup
	mockExchanger := new(MockExpiringExchanger)

	// Prepare nameservers with no valid addresses
	nameservers := []*dns.NS{}
	extra := []dns.RR{}
	ctx := context.TODO()

	// Execute
	z, err := createZone(ctx, "example.com.", "com.", nameservers, extra, mockExchanger)

	// Assertions
	assert.Nil(t, z)
	assert.ErrorIs(t, err, ErrFailedCreatingZoneAndPool)
}

func TestCreateZone_SuccessWithEnrichment(t *testing.T) {
	// Setup
	mockExchanger := new(MockExpiringExchanger)

	// Prepare nameservers and extra records
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
		{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeNS}, Ns: "ns3.example.com."},
	}
	extra := []dns.RR{}
	ctx := context.TODO()

	// Mock the exchanger behavior if needed (e.g., to enrich the pool)
	mockExchanger.On("exchange", mock.Anything, mock.Anything).Return(&Response{
		Msg: &dns.Msg{
			Answer: []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.53")},
				&dns.A{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.54")},
				&dns.A{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.55")},
			},
		},
		Duration: 10 * time.Millisecond,
	})

	// Execute
	z, err := createZone(ctx, "example.com.", "com.", nameservers, extra, mockExchanger)

	// AssertionsOk
	assert.NoError(t, err)
	assert.NotNil(t, z)
	assert.Equal(t, "example.com.", z.name())

	// We'll peek under the covers to ensure the pool was created as expected.
	pool, ok := z.(*zoneImpl).pool.(*nameserverPool)
	assert.True(t, ok)
	assert.Equal(t, pool.status(), PoolPrimed)
}

func TestCreateZone_PoolCreationFailsWithEnrichment(t *testing.T) {
	// Setup
	mockExchanger := new(MockExpiringExchanger)

	// Prepare nameservers and extra records
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
		{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeNS}, Ns: "ns3.example.com."},
	}
	extra := []dns.RR{}
	ctx := context.TODO()

	// Mock the exchanger behavior if needed (e.g., to enrich the pool)
	mockExchanger.On("exchange", mock.Anything, mock.Anything).Return(&Response{
		Msg: &dns.Msg{
			Answer: []dns.RR{},
		},
		Duration: 10 * time.Millisecond,
	})

	// Execute
	z, err := createZone(ctx, "example.com.", "com.", nameservers, extra, mockExchanger)

	// Assertions
	assert.Nil(t, z)
	assert.ErrorIs(t, err, ErrFailedEnrichingPool)
}

// TestCreateZone_SuccessWithOptionalEnrichment Has one glue record returned, so tried to enrich to find the addresses of the other two.
func TestCreateZone_SuccessWithOptionalEnrichment(t *testing.T) {
	// Setup
	mockExchanger := new(MockExpiringExchanger)

	// Prepare nameservers and extra records
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
		{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeNS}, Ns: "ns3.example.com."},
	}
	extra := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.53")},
	}
	ctx := context.TODO()

	// Mock the exchanger behavior if needed (e.g., to enrich the pool)
	mockExchanger.On("exchange", mock.Anything, mock.Anything).Return(&Response{
		Msg: &dns.Msg{
			Answer: []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.54")},
				&dns.A{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.55")},
			},
		},
		Duration: 10 * time.Millisecond,
	})

	// Execute
	z, err := createZone(ctx, "example.com.", "com.", nameservers, extra, mockExchanger)

	// AssertionsOk
	assert.NoError(t, err)
	assert.NotNil(t, z)
	assert.Equal(t, "example.com.", z.name())

	// We'll peek under the covers to ensure the pool was created as expected.
	pool, ok := z.(*zoneImpl).pool.(*nameserverPool)
	assert.True(t, ok)

	for i := 1; i <= 10; i++ {
		// Not really nice testing across multi-threads, but this seems deterministic enough.
		time.Sleep(time.Duration(i) * 10 * time.Millisecond)
		if pool.status() == PoolPrimed {
			break
		}
	}
	assert.Equal(t, pool.status(), PoolPrimed)
}
