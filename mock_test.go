package resolver

import (
	"context"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/mock"
)

// Mock expiringExchanger to simulate pool expiration behavior and DNS message exchange
type MockExpiringExchanger struct {
	mock.Mock
}

// Mock the expired function
func (m *MockExpiringExchanger) expired() bool {
	args := m.Called()
	return args.Bool(0)
}

// Mock the exchange function to simulate DNS message exchange
func (m *MockExpiringExchanger) exchange(ctx context.Context, msg *dns.Msg) *Response {
	args := m.Called(ctx, msg)
	return args.Get(0).(*Response)
}

//--------------------------------------------------------------------------

type mockZoneStore struct {
	mockAdd      func(z zone)
	mockGet      func(name string) zone
	mockCount    func() int
	mockZoneList func(name string) []zone
}

func (m mockZoneStore) getZoneList(name string) []zone {
	return m.mockZoneList(name)
}
func (m mockZoneStore) get(name string) zone {
	return m.mockGet(name)
}
func (m mockZoneStore) add(z zone) {
	m.mockAdd(z)
}
func (m mockZoneStore) count() int {
	return m.mockCount()
}

//--------------------------------------------------------------------------

type mockExchanger struct {
	mockExchange func(context.Context, *dns.Msg) *Response
}

func (m *mockExchanger) exchange(ctx context.Context, qmsg *dns.Msg) *Response {
	return m.mockExchange(ctx, qmsg)
}

//--------------------------------------------------------------------------

type mockZone struct {
	mockName     func() string
	mockParent   func() string
	mockExpired  func() bool
	mockClone    func(name, parent string) zone
	mockSoa      func(ctx context.Context, name string) (*dns.SOA, error)
	mockDnskeys  func(ctx context.Context) ([]dns.RR, error)
	mockExchange func(ctx context.Context, m *dns.Msg) *Response
}

func (z *mockZone) name() string {
	return z.mockName()
}

func (z *mockZone) parent() string {
	return z.mockParent()
}

func (z *mockZone) expired() bool {
	return z.mockExpired()
}

func (z *mockZone) clone(name, parent string) zone {
	return z.mockClone(name, parent)
}

func (z *mockZone) soa(ctx context.Context, name string) (*dns.SOA, error) {
	return z.mockSoa(ctx, name)
}

func (z *mockZone) dnskeys(ctx context.Context) ([]dns.RR, error) {
	return z.mockDnskeys(ctx)
}

func (z *mockZone) exchange(ctx context.Context, m *dns.Msg) *Response {
	return z.mockExchange(ctx, m)
}
