package resolver

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"regexp"
	"sync/atomic"
	"testing"
	"time"
)

var uuidv7Regex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var uuidv7ShortRegex = regexp.MustCompile(`^[0-9a-f]{7}$`)

//---

func getMockZone(name, parent string) *mockZone {
	return &mockZone{
		mockName: func() string {
			return name
		},
		mockParent: func() string {
			return parent
		},
		mockDnskeys: func(ctx context.Context) ([]dns.RR, error) {
			return nil, nil
		},
		mockExchange: func(ctx context.Context, m *dns.Msg) *Response {
			return nil
		},
		mockExpired: func() bool {
			return false
		},
	}
}

func getTestResolverWithRoot() *Resolver {

	root := getMockZone(".", "")

	mzs := mockZoneStore{
		mockGet: func(name string) zone {
			return nil
		},
		mockZoneList: func(name string) []zone {
			return []zone{root}
		},
	}

	r := &Resolver{
		zones: mzs,
		funcs: resolverFunctions{},
	}

	return r
}

func getTestResolverWithExample() (*Resolver, *mockZone, *mockZone, *mockZone, *mockZoneStore) {
	root := getMockZone(".", "")
	com := getMockZone("com.", ".")
	example := getMockZone("example.com.", "com.")

	zones := []zone{example, com, root}

	mzs := &mockZoneStore{
		mockGet: func(name string) zone {
			for _, z := range zones {
				if z.name() == name {
					return z
				}
			}
			return root
		},
		mockAdd: func(z zone) {

		},
		mockZoneList: func(name string) []zone {
			return zones
		},
	}

	resolver := &Resolver{
		zones: mzs,
	}

	resolver.funcs = resolverFunctions{
		getExchanger: func() exchanger {
			return resolver
		},
	}

	return resolver, root, com, example, mzs
}

func TestResolver_Exchange_RecursionNotDesired(t *testing.T) {

	// We only accept QMsgs that have RecursionDesired set to true.
	// Otherwise, an error is returned.

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)

	// We need to do this here as SetQuestion() sets it to true.
	qmsg.RecursionDesired = false

	resolver := getTestResolverWithRoot()

	response := resolver.Exchange(context.Background(), qmsg)
	assert.True(t, response.IsEmpty())
	assert.True(t, response.HasError())
	assert.ErrorIs(t, response.Err, ErrNotRecursionDesired)
}

func TestResolver_Exchange_Context(t *testing.T) {

	// Test that the expect values are added to the context.

	resolver := getTestResolverWithRoot()

	ctx := context.Background()
	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)

	expectedResponse := &Response{}

	var seenAuth *authenticator
	var seenCtx context.Context
	resolver.funcs.resolveLabel = func(ctx context.Context, d *domain, z zone, qmsg *dns.Msg, auth *authenticator) (zone, *Response) {
		seenCtx = ctx
		seenAuth = auth
		return nil, expectedResponse
	}

	response := resolver.Exchange(ctx, qmsg)

	// Sense check that the response returned from resolveLabel(), is returned from Exchange().
	assert.Equal(t, expectedResponse, response)

	// We did not set DO, thus we expect no authenticator.
	assert.Nil(t, seenAuth)

	start, ok := seenCtx.Value(ctxStartTime).(time.Time)
	assert.True(t, ok, "we expect a start time to have been set")
	assert.IsType(t, time.Time{}, start)

	counter, ok := seenCtx.Value(ctxSessionQueries).(*atomic.Uint32)
	require.True(t, ok)
	assert.Equal(t, uint32(1), counter.Load())

	trace, ok := seenCtx.Value(CtxTrace).(*Trace)
	require.True(t, ok)
	assert.Equal(t, uint32(1), trace.Iterations.Load())
	assert.Regexp(t, uuidv7Regex, trace.ID())
	assert.Regexp(t, uuidv7ShortRegex, trace.ShortID())
	require.IsType(t, time.Time{}, trace.Start)
	assert.False(t, trace.Start.IsZero())

}

func TestResolver_Exchange_DOSet(t *testing.T) {

	// Tests that an authenticator is created when the DO-bit is set.

	resolver := getTestResolverWithRoot()

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	qmsg.SetEdns0(4096, true)

	var authSeen *authenticator
	resolver.funcs.resolveLabel = func(ctx context.Context, d *domain, z zone, qmsg *dns.Msg, auth *authenticator) (zone, *Response) {
		authSeen = auth
		return nil, &Response{}
	}

	resolver.Exchange(context.Background(), qmsg)
	assert.NotNil(t, authSeen)
}

func TestResolver_Exchange_NonApexResultWithKnownHosts(t *testing.T) {

	resolver, root, com, example, _ := getTestResolverWithExample()

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	qmsg.SetEdns0(4096, true)

	//---

	rootExchangeCalled := false
	root.mockExchange = func(ctx context.Context, m *dns.Msg) *Response {
		rootExchangeCalled = true
		// We expect the qname to be the direct descendant of this zone.
		assert.Equal(t, "com.", m.Question[0].Name)
		return nil
	}

	comExchangeCalled := false
	com.mockExchange = func(ctx context.Context, m *dns.Msg) *Response {
		comExchangeCalled = true
		// We expect the qname to be the direct descendant of this zone.
		assert.Equal(t, "example.com.", m.Question[0].Name)
		return nil
	}

	var timesCalled int
	var lastZoneSeen zone
	var lastDomainSeen string
	var lastAuthSeen *authenticator
	resolver.funcs.resolveLabel = func(ctx context.Context, d *domain, z zone, qmsg *dns.Msg, auth *authenticator) (zone, *Response) {
		timesCalled++

		lastZoneSeen = z
		lastAuthSeen = auth
		lastDomainSeen = d.current()

		// We expect this on the first call.
		if d.current() == "example.com." {
			// We return the next zone, and no response.
			return example, nil
		}

		return nil, &Response{}
	}

	resolver.Exchange(context.Background(), qmsg)

	assert.Equal(t, 1, timesCalled)

	assert.True(t, rootExchangeCalled)
	assert.True(t, comExchangeCalled)

	assert.NotNil(t, lastZoneSeen)
	assert.IsType(t, &mockZone{}, lastZoneSeen)

	assert.NotNil(t, lastAuthSeen)
	assert.IsType(t, &authenticator{}, lastAuthSeen)

	assert.Equal(t, "www.example.com.", lastDomainSeen)
}

func TestResolver_Exchange_NoResultFound(t *testing.T) {

	// Tests that is no response if found after we've looped through each label, we get an error.

	resolver, _, _, _, _ := getTestResolverWithExample()

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	qmsg.SetEdns0(4096, true)

	//---

	resolver.funcs.resolveLabel = func(ctx context.Context, d *domain, z zone, qmsg *dns.Msg, auth *authenticator) (zone, *Response) {
		// We never return a response
		return getMockZone("test", ""), nil
	}

	response := resolver.Exchange(context.Background(), qmsg)

	assert.True(t, response.HasError())
	assert.ErrorIs(t, response.Err, ErrUnableToResolveAnswer)
}

func TestResolver_Exchange_MaxQueriesPerRequestReached(t *testing.T) {

	// If the total number of request to resolve a query exceeds MaxQueriesPerRequest, we expect an error.

	resolver := getTestResolverWithRoot()

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	qmsg.SetEdns0(4096, true)

	//---

	resolver.funcs.resolveLabel = func(ctx context.Context, d *domain, z zone, qmsg *dns.Msg, auth *authenticator) (zone, *Response) {
		// We never return a response
		return getMockZone("test", ""), nil
	}

	// We set MaxQueriesPerRequest to 2, so this basic query will exceed it.
	MaxQueriesPerRequest = 2

	response := resolver.Exchange(context.Background(), qmsg)

	// This is global, so we need to set it back!
	MaxQueriesPerRequest = DefaultMaxQueriesPerRequest

	assert.True(t, response.HasError())
	assert.ErrorIs(t, response.Err, ErrMaxQueriesPerRequestReached)
}

func TestResolver_Exchange_ApexResultWithNoKnownHosts(t *testing.T) {

	// When a QName resolves a record that's at the apex of a zone, it requires one additional set
	// at the end of exchange().

	resolver := getTestResolverWithRoot()

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("example.com.", dns.TypeMX)
	qmsg.SetEdns0(4096, true)

	var timesCalled int
	domainsSeen := make([]string, 0, 4)
	resolver.funcs.resolveLabel = func(ctx context.Context, d *domain, z zone, qmsg *dns.Msg, auth *authenticator) (zone, *Response) {
		timesCalled++
		domainsSeen = append(domainsSeen, d.current())

		if timesCalled == 4 {
			// On the (expected) last call, we return a non-empty response.
			return nil, &Response{Msg: &dns.Msg{}}
		}

		return nil, nil
	}

	response := resolver.Exchange(context.Background(), qmsg)

	assert.False(t, response.IsEmpty())
	assert.False(t, response.HasError())

	assert.Equal(t, 4, timesCalled)

	// Note that we expect to see `example.com.` twice.
	assert.ElementsMatch(t, domainsSeen, []string{".", "com.", "example.com.", "example.com."})
}

func TestResolver_ResolveLabel_ZoneIsNil(t *testing.T) {

	resolver, _, _, _, _ := getTestResolverWithExample()

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)

	ctx := context.Background()
	d := newDomain(qmsg.Question[0].Name)

	// So zone z is nil
	var z zone

	zone, response := resolver.resolveLabel(ctx, &d, z, qmsg, nil)

	assert.Nil(t, zone)
	assert.True(t, response.HasError())
	assert.ErrorIs(t, response.Err, ErrInternalError)
}

func TestResolver_ResolveLabel_ErrorFromExchange(t *testing.T) {

	ErrTest := errors.New("test error")

	resolver, _, _, example, _ := getTestResolverWithExample()

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.Background()
	d := newDomain(qmsg.Question[0].Name)

	//---

	callsSeen := 0
	example.mockExchange = func(ctx context.Context, m *dns.Msg) *Response {
		callsSeen++
		return &Response{
			Msg: new(dns.Msg),
			Err: ErrTest,
		}
	}

	//---

	z, r := resolver.resolveLabel(ctx, &d, example, qmsg, nil)

	assert.Nil(t, z)
	assert.True(t, r.HasError())
	assert.ErrorIs(t, r.Err, ErrTest)
	assert.Equal(t, 1, callsSeen)
}

func TestResolver_ResolveLabel_EmptyFromExchange(t *testing.T) {

	resolver, _, _, example, _ := getTestResolverWithExample()

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.Background()
	d := newDomain(qmsg.Question[0].Name)

	//---

	callsSeen := 0
	example.mockExchange = func(ctx context.Context, m *dns.Msg) *Response {
		callsSeen++
		return &Response{}
	}

	//---

	z, r := resolver.resolveLabel(ctx, &d, example, qmsg, nil)

	assert.Nil(t, z)
	assert.True(t, r.HasError())
	assert.ErrorIs(t, r.Err, ErrEmptyResponse)
	assert.Equal(t, 1, callsSeen)

}

func TestResolver_ResolveLabel_Process(t *testing.T) {

	// We consider a query as needing further delegation if:
	//	- Zero Answers are returned; and
	//	- NS records are present in the Authority; and
	// 	- There's no SOA in the Authority.
	//
	// Otherwise, we see the query as complete, and return the response to th called.
	//
	// In the context of this test, if we see finaliseResponse() called, we're seeing the input result in a complete query.
	// Otherwise ,we should see processDelegation() called.

	resolver, _, _, example, _ := getTestResolverWithExample()

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.Background()
	d := newDomain(qmsg.Question[0].Name)

	//---

	testResponse1 := &Response{
		Msg: &dns.Msg{
			MsgHdr: dns.MsgHdr{},
		},
	}

	testResponse2 := &Response{
		Msg: &dns.Msg{
			MsgHdr: dns.MsgHdr{},
		},
	}

	testZone := new(mockZone)

	// We return our test response
	mockExchangeCallsSeen := 0
	example.mockExchange = func(ctx context.Context, m *dns.Msg) *Response {
		mockExchangeCallsSeen++
		return testResponse1
	}

	checkForMissingZonesCallsSeen := 0
	resolver.funcs.checkForMissingZones = func(ctx context.Context, d *domain, z zone, rmsg *dns.Msg, auth *authenticator) zone {
		checkForMissingZonesCallsSeen++
		assert.Equal(t, testResponse1.Msg, rmsg)
		return z
	}

	processDelegationCallsSeen := 0
	resolver.funcs.processDelegation = func(ctx context.Context, z zone, rmsg *dns.Msg) (zone, *Response) {
		processDelegationCallsSeen++
		return testZone, testResponse2
	}

	finaliseResponseCallsSeen := 0
	resolver.funcs.finaliseResponse = func(ctx context.Context, auth *authenticator, qmsg *dns.Msg, response *Response) *Response {
		finaliseResponseCallsSeen++
		assert.Equal(t, testResponse1, response)
		return response
	}

	//---

	// We expect a complete query initially, so finaliseResponse().

	z, r := resolver.resolveLabel(ctx, &d, example, qmsg, nil)

	assert.Nil(t, z)
	assert.Equal(t, testResponse1, r)
	assert.Equal(t, 1, mockExchangeCallsSeen)
	assert.Equal(t, 1, checkForMissingZonesCallsSeen)
	assert.Equal(t, 0, processDelegationCallsSeen)
	assert.Equal(t, 1, finaliseResponseCallsSeen)

	//---

	// If we add a NS record, this should now be caught by processDelegation().

	testResponse1.Msg.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
	}

	z, r = resolver.resolveLabel(ctx, &d, example, qmsg, nil)

	assert.Equal(t, testZone, z)
	assert.Equal(t, testResponse2, r)
	assert.Equal(t, 2, mockExchangeCallsSeen)
	assert.Equal(t, 2, checkForMissingZonesCallsSeen)
	assert.Equal(t, 1, processDelegationCallsSeen) // This has now been called
	assert.Equal(t, 1, finaliseResponseCallsSeen)  // This has not changed

	//---

	// If there was also a record in the Answer section, we should end up back at finaliseResponse().

	testResponse1.Msg.Answer = []dns.RR{
		&dns.MX{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX}, Mx: "mx.example.com."},
	}

	z, r = resolver.resolveLabel(ctx, &d, example, qmsg, nil)

	assert.Nil(t, z)
	assert.Equal(t, testResponse1, r)
	assert.Equal(t, 3, mockExchangeCallsSeen)
	assert.Equal(t, 3, checkForMissingZonesCallsSeen)
	assert.Equal(t, 1, processDelegationCallsSeen) // This has not changed
	assert.Equal(t, 2, finaliseResponseCallsSeen)  // This has incremented

	//---

	// Or if we empty the Answer section, but there was a SOA, we also end up at finaliseResponse()

	testResponse1.Msg.Answer = []dns.RR{}

	testResponse1.Msg.Ns = append(testResponse1.Msg.Ns,
		&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA}, Ns: "ns1.example.com."},
	)

	z, r = resolver.resolveLabel(ctx, &d, example, qmsg, nil)

	assert.Nil(t, z)
	assert.Equal(t, testResponse1, r)
	assert.Equal(t, 4, mockExchangeCallsSeen)
	assert.Equal(t, 4, checkForMissingZonesCallsSeen)
	assert.Equal(t, 1, processDelegationCallsSeen) // This has not changed
	assert.Equal(t, 3, finaliseResponseCallsSeen)  // This has incremented

}

func TestResolver_CheckForMissingZones_NoRecords(t *testing.T) {

	resolver, _, _, example, _ := getTestResolverWithExample()

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.Background()
	d := newDomain(qmsg.Question[0].Name)

	// When no records are in the Answer or Authority, we expect the zone we passed in, back.

	z := resolver.checkForMissingZones(ctx, &d, example, qmsg, nil)

	assert.Equal(t, example, z)
}

func TestResolver_CheckForMissingZones_NoChildrenOfCurrentZone(t *testing.T) {

	resolver, _, _, example, _ := getTestResolverWithExample()

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.Background()
	d := newDomain(qmsg.Question[0].Name)

	// If the Owner Name of a record is not a child of the zone passed in, we expect the zone we passed in, back.

	qmsg.Ns = []dns.RR{
		// Note the .net
		&dns.NS{Hdr: dns.RR_Header{Name: "a.b.c.example.net.", Rrtype: dns.TypeNS}, Ns: "ns1.example.net."},
	}

	z := resolver.checkForMissingZones(ctx, &d, example, qmsg, nil)

	assert.Equal(t, example, z)
}

func TestResolver_CheckForMissingZones_NoMissingZones(t *testing.T) {

	resolver, _, _, example, _ := getTestResolverWithExample()

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.Background()

	d := newDomain(qmsg.Question[0].Name)
	d.windTo("www.example.com.")

	// If the Owner Name of a record is the direct descendant of the zone, there are no missing zones.
	// We expect the zone we passed in, back.

	// Here d.current() is `www.example.com.`, which is a direct descendant of the zone `example.com`,
	// so we expect no missing zones.

	qmsg.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
	}

	// If a zone is missing, z.soa() is called. Thus in this instance we expect to not see it called.
	mockSoaCalled := 0
	example.mockSoa = func(ctx context.Context, name string) (*dns.SOA, error) {
		mockSoaCalled++
		return nil, nil
	}

	z := resolver.checkForMissingZones(ctx, &d, example, qmsg, nil)

	assert.Equal(t, example, z)
	assert.Equal(t, 0, mockSoaCalled)
}

func TestResolver_CheckForMissingZones_WithMissingZones(t *testing.T) {

	resolver, _, _, example, mzs := getTestResolverWithExample()

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("a.b.c.d.example.com.", dns.TypeA)
	ctx := context.Background()

	d := newDomain(qmsg.Question[0].Name)
	d.windTo("d.example.com.")

	// If the Owner Name of a record is a descendant, but _not_ a direct descendant, then the labels in the delta are
	// potentially zones that have been skipped over. We expect the code to validate each by checking if each
	// has a SOA record.

	// If there are more than one descendant returned, we use the one with the most labels.

	// The below tells the resolver that there's a zone at `a.b.c.d.example.com.`
	// Thus far the resolver only knows about `example.com.` It will therefore take the following as missing:
	//	- d.example.com.
	//	- c.d.example.com.
	//	- b.c.d.example.com.

	qmsg.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "c.d.example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		&dns.NS{Hdr: dns.RR_Header{Name: "a.b.c.d.example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
	}

	// With potentially 3 missing, we expect this to be called 3 times.
	mockSoaCalled := 0
	example.mockSoa = func(ctx context.Context, name string) (*dns.SOA, error) {
		mockSoaCalled++

		// We'll return a SOA for this (middle) name.
		// We should therefor see this a zone, and the other two should be seen as records within other zones.
		if name == "c.d.example.com." {
			return &dns.SOA{}, nil
		}

		return nil, nil
	}

	var newZone *mockZone
	mockCloneCalled := 0
	newZoneSoaCalled := 0
	example.mockClone = func(name, parent string) zone {
		mockCloneCalled++
		newZone = getMockZone(name, parent)

		// As "c.d.example.com." will now be considered a zone, the looked for the SOA on
		// `b.c.d.example.com.` will be against this new zone.
		newZone.mockSoa = func(ctx context.Context, name string) (*dns.SOA, error) {
			newZoneSoaCalled++
			return nil, nil
		}

		return newZone
	}

	mockAddCalled := 0
	var mockAddZoneSeen zone
	mzs.mockAdd = func(z zone) {
		mockAddCalled++
		mockAddZoneSeen = z
	}

	z := resolver.checkForMissingZones(ctx, &d, example, qmsg, nil)

	// We should have a new zone with these details.
	assert.Equal(t, "c.d.example.com.", z.name())
	assert.Equal(t, example.name(), z.parent())

	// We expect to see the new zone added to the Zone Store.
	assert.Equal(t, "c.d.example.com.", mockAddZoneSeen.name())
	assert.Equal(t, example.name(), mockAddZoneSeen.parent())

	assert.Equal(t, 2, mockSoaCalled)
	assert.Equal(t, 1, mockCloneCalled)
	assert.Equal(t, 1, newZoneSoaCalled)
	assert.Equal(t, 1, mockAddCalled)

	// We expect d.current() to have progressed to the new (longest) zone in the NS records.
	assert.Equal(t, "a.b.c.d.example.com.", d.current())
}

func TestResolver_ProcessDelegation_NoNameservers(t *testing.T) {

	resolver, _, _, example, _ := getTestResolverWithExample()

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.Background()

	rmsg := qmsg.SetReply(&dns.Msg{})

	z, r := resolver.processDelegation(ctx, example, rmsg)

	assert.Nil(t, z)
	assert.True(t, r.HasError())
	assert.ErrorIs(t, r.Err, ErrNextNameserversNotFound)
}

func TestResolver_ProcessDelegation_NotSubdomain(t *testing.T) {

	resolver, _, _, example, _ := getTestResolverWithExample()

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.Background()

	rmsg := qmsg.SetReply(&dns.Msg{})

	// This owner name is not valid as it's not a parent to the QName.

	rmsg.Ns = []dns.RR{
		// Note the .net
		&dns.NS{Hdr: dns.RR_Header{Name: "example.net.", Rrtype: dns.TypeNS}, Ns: "ns1.example.net."},
	}

	z, r := resolver.processDelegation(ctx, example, rmsg)

	assert.Nil(t, z)
	assert.True(t, r.HasError())
	assert.ErrorIs(t, r.Err, ErrNextNameserversNotFound)
}

func TestResolver_ProcessDelegation_ErrorFromCreateZone(t *testing.T) {

	resolver, _, _, example, mzs := getTestResolverWithExample()

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.Background()

	rmsg := qmsg.SetReply(&dns.Msg{})

	// This will throw an error because for Owner name of the NS record equals the name of the current zone.
	// We only accept responses if the owner name is a descendant of the current zone.

	rmsg.Ns = []dns.RR{
		// Note the .net
		&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.net."},
	}

	createZoneCalled := 0
	resolver.funcs.createZone = func(ctx context.Context, name, parent string, nameservers []*dns.NS, extra []dns.RR, exchanger exchanger) (zone, error) {
		createZoneCalled++
		return nil, errors.New("test error")
	}

	mockAddCalled := 0
	mzs.mockAdd = func(z zone) {
		mockAddCalled++
	}

	z, r := resolver.processDelegation(ctx, example, rmsg)
	assert.Nil(t, z)
	assert.True(t, r.HasError())
	assert.ErrorIs(t, r.Err, ErrNextNameserversNotFound)

	// As we had an error, these should not get called.
	assert.Equal(t, 0, createZoneCalled)
	assert.Equal(t, 0, mockAddCalled)
}

func TestResolver_ProcessDelegation_CreateZone(t *testing.T) {

	resolver, _, com, _, mzs := getTestResolverWithExample()

	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.Background()

	rmsg := qmsg.SetReply(&dns.Msg{})

	// This owner name is not valid as it's not a parent to the QName.

	rmsg.Ns = []dns.RR{
		// Note the .net
		&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.net."},
	}

	var newZone *mockZone
	createZoneCalled := 0
	resolver.funcs.createZone = func(ctx context.Context, name, parent string, nameservers []*dns.NS, extra []dns.RR, exchanger exchanger) (zone, error) {
		createZoneCalled++
		newZone = getMockZone(name, parent)
		return newZone, nil
	}

	mockAddCalled := 0
	mzs.mockAdd = func(z zone) {
		mockAddCalled++
	}

	z, r := resolver.processDelegation(ctx, com, rmsg)
	assert.False(t, r.HasError())
	assert.Equal(t, newZone, z)

	// We expect the zone to be added to the store.
	assert.Equal(t, 1, mockAddCalled)
	assert.Equal(t, 1, createZoneCalled)
}

func TestResolver_FinaliseResponse_ARecord(t *testing.T) {
	resolver, _, _, _, _ := getTestResolverWithExample()
	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.WithValue(context.Background(), ctxStartTime, time.Now().Add(-5*time.Millisecond))

	rmsg := qmsg.SetReply(&dns.Msg{})

	rmsg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA}, A: net.IPv4(192, 0, 2, 1)},
	}

	inputResponse := &Response{Msg: rmsg}

	r := resolver.finaliseResponse(ctx, nil, qmsg, inputResponse)

	assert.Equal(t, inputResponse, r)
}

func TestResolver_FinaliseResponse_CNameQuestion(t *testing.T) {

	// When the QType is CNAME, the CNAME in the answer should not be resolved.

	resolver, _, _, _, _ := getTestResolverWithExample()
	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeCNAME)
	ctx := context.WithValue(context.Background(), ctxStartTime, time.Now().Add(-5*time.Millisecond))

	rmsg := qmsg.SetReply(&dns.Msg{})

	rmsg.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME}, Target: "other.example.net."},
	}
	inputResponse := &Response{Msg: rmsg}

	cnameCalled := 0
	resolver.funcs.cname = func(ctx context.Context, qmsg *dns.Msg, r *Response, exchanger exchanger) error {
		cnameCalled++
		return nil
	}

	r := resolver.finaliseResponse(ctx, nil, qmsg, inputResponse)

	assert.Equal(t, inputResponse, r)
	assert.Equal(t, 0, cnameCalled)
}

func TestResolver_FinaliseResponse_CNameAnswer(t *testing.T) {

	// When the QType is A, but the answer has a CNAME, we should resolve that CNAME.

	resolver, _, _, _, _ := getTestResolverWithExample()
	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.WithValue(context.Background(), ctxStartTime, time.Now().Add(-5*time.Millisecond))

	rmsg := qmsg.SetReply(&dns.Msg{})

	rmsg.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME}, Target: "other.example.net."},
	}
	inputResponse := &Response{Msg: rmsg}

	cnameCalled := 0
	resolver.funcs.cname = func(ctx context.Context, qmsg *dns.Msg, r *Response, exchanger exchanger) error {
		cnameCalled++
		return nil
	}

	r := resolver.finaliseResponse(ctx, nil, qmsg, inputResponse)

	assert.Equal(t, inputResponse, r)
	assert.Equal(t, 1, cnameCalled)
}

func TestResolver_FinaliseResponse_CNameError(t *testing.T) {

	// When the CNAME function returns an error, that's returned to the user,

	resolver, _, _, _, _ := getTestResolverWithExample()
	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.WithValue(context.Background(), ctxStartTime, time.Now().Add(-5*time.Millisecond))

	rmsg := qmsg.SetReply(&dns.Msg{})

	rmsg.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME}, Target: "other.example.net."},
	}
	inputResponse := &Response{Msg: rmsg}

	ErrorTest := errors.New("test error")

	cnameCalled := 0
	resolver.funcs.cname = func(ctx context.Context, qmsg *dns.Msg, r *Response, exchanger exchanger) error {
		cnameCalled++
		return ErrorTest
	}

	r := resolver.finaliseResponse(ctx, nil, qmsg, inputResponse)

	assert.True(t, r.HasError())
	assert.ErrorIs(t, r.Err, ErrorTest)
	assert.Equal(t, 1, cnameCalled)
}

func TestResolver_FinaliseResponse_RCode(t *testing.T) {

	// When the CNAME function returns an error, that's returned to the user,

	resolver, _, _, _, _ := getTestResolverWithExample()
	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.WithValue(context.Background(), ctxStartTime, time.Now().Add(-5*time.Millisecond))

	rmsg := qmsg.SetReply(&dns.Msg{})

	// This should result in an error also being returned.
	rmsg.Rcode = dns.RcodeServerFailure

	rmsg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA}, A: net.IPv4(192, 0, 2, 1)},
	}
	inputResponse := &Response{Msg: rmsg}

	r := resolver.finaliseResponse(ctx, nil, qmsg, inputResponse)

	assert.Equal(t, inputResponse, r)
	assert.True(t, r.HasError())
	assert.Contains(t, r.Err.Error(), "ServFail")
}

func TestResolver_FinaliseResponse_Opt(t *testing.T) {

	// Any OPT record in the Extra section should not be removed

	resolver, _, _, _, _ := getTestResolverWithExample()
	qmsg := &dns.Msg{}
	qmsg.SetQuestion("www.example.com.", dns.TypeA)
	ctx := context.WithValue(context.Background(), ctxStartTime, time.Now().Add(-5*time.Millisecond))

	rmsg := qmsg.SetReply(&dns.Msg{})

	// Sets the record
	rmsg.SetEdns0(4096, true)

	rmsg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA}, A: net.IPv4(192, 0, 2, 1)},
	}
	rmsg.Extra = append(rmsg.Extra, &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA}, A: net.IPv4(192, 0, 2, 2)})

	inputResponse := &Response{Msg: rmsg}

	r := resolver.finaliseResponse(ctx, nil, qmsg, inputResponse)

	assert.Equal(t, inputResponse, r)

	// We expect the A record to have been removed.
	assert.Len(t, r.Msg.Extra, 1)

	optSeen := false
	for _, extra := range r.Msg.Extra {
		_, ok := extra.(*dns.OPT)
		optSeen = optSeen || ok
	}

	assert.True(t, optSeen)
}
