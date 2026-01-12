package dnssec

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"testing"
)

func TestResult_NoRecords(t *testing.T) {

	// If we call Result() when no response have been passed to the authenticator.
	// Then we cannot off a conclusion.

	a := NewAuth(context.Background(), dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	state, doe, err := a.Result()

	if doe != NotFound {
		t.Error("unexpected doe")
	}
	if state != Unknown {
		t.Error("unexpected state")
	}
	if err == nil {
		t.Error("we expected an error")
	}
	if !errors.Is(err, ErrNoResults) {
		t.Error("expected ErrNoResults")
	}

}

func TestResult_BogusRecords(t *testing.T) {

	// If any one of the results was Bogus, then the overall conclusion is also Bogus.

	a := NewAuth(context.Background(), dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Bogus})
	a.results = append(a.results, &result{state: Secure})

	state, doe, err := a.Result()
	if err != nil {
		t.Error("unexpected error")
	}
	if doe != NotFound {
		t.Error("unexpected doe")
	}
	if state != Bogus {
		t.Error("unexpected state")
	}

}

func TestResult_BreakInChainExpected(t *testing.T) {

	// These tests focus on what happens when a result state moves from Secure to Insecure part way through a chain.
	// We need to ensure that DOE exists for the DS records, for that to be valid.

	// These three states show that valid DOE was found at the delegation point.

	for _, expectedDOE := range []DenialOfExistenceState{Nsec3OptOut, NsecMissingDS, Nsec3MissingDS} {
		a := NewAuth(context.Background(), dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

		// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure, denialOfExistence: expectedDOE})
		a.results = append(a.results, &result{state: Insecure})

		state, doe, err := a.Result()
		if err != nil {
			t.Error("unexpected error")
		}
		if doe != expectedDOE {
			t.Error("unexpected doe")
		}
		if state != Insecure {
			t.Error("unexpected state")
		}
	}

}

func TestResult_BreakInChainValidated(t *testing.T) {

	// These tests focus on what happens when a result state moves from Secure to Insecure part way through a chain.
	// We need to ensure that DOE exists for the DS records, for that to be valid.

	// These two DOE states are only accepted if we'd explicitly queried for the DS records at the parent zone.

	for _, expectedDOE := range []DenialOfExistenceState{NsecNoData, Nsec3NoData} {
		a := NewAuth(context.Background(), dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

		// Used to return the zone apex of the Insecure Result.
		zone := &mockZone{name: "EXAMPLE.COM."}

		// Used to lookup the question details of the last Secure result.
		msg := &dns.Msg{Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeDS}}}

		// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure, denialOfExistence: expectedDOE, msg: msg})
		a.results = append(a.results, &result{state: Insecure, zone: zone})
		a.results = append(a.results, &result{state: Insecure})

		state, doe, err := a.Result()
		if err != nil {
			t.Error("unexpected error")
		}
		if doe != expectedDOE {
			t.Error("unexpected doe")
		}
		if state != Insecure {
			t.Error("unexpected state")
		}

		//---

		// If the query was not for a DS record, it should be Bogus.
		// We've changed it to an A record.

		a = NewAuth(context.Background(), dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

		// Used to return the zone apex of the Insecure Result.
		zone = &mockZone{name: "example.com."}

		// Used to lookup the question details of the last Secure result.
		msg = &dns.Msg{Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA}}}

		// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure, denialOfExistence: expectedDOE, msg: msg})
		a.results = append(a.results, &result{state: Insecure, zone: zone})
		a.results = append(a.results, &result{state: Insecure})

		state, doe, err = a.Result()
		if err != nil {
			t.Error("unexpected error")
		}
		if doe != expectedDOE {
			t.Error("unexpected doe")
		}
		if state != Bogus {
			t.Error("unexpected state")
		}

		//---

		// If the Insure zone's apex does not match the QName of the previous question, it should be Bogus.
		// We've changed the question domain to `.net`.

		a = NewAuth(context.Background(), dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

		// Used to return the zone apex of the Insecure Result.
		zone = &mockZone{name: "example.com."}

		// Used to lookup the question details of the last Secure result.
		msg = &dns.Msg{Question: []dns.Question{{Name: "example.net.", Qtype: dns.TypeDS}}}

		// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure, denialOfExistence: expectedDOE, msg: msg})
		a.results = append(a.results, &result{state: Insecure, zone: zone})
		a.results = append(a.results, &result{state: Insecure})

		state, doe, err = a.Result()
		if err != nil {
			t.Error("unexpected error")
		}
		if doe != expectedDOE {
			t.Error("unexpected doe")
		}
		if state != Bogus {
			t.Error("unexpected state")
		}
	}

}

func TestResult_BreakInChaiInvalid(t *testing.T) {

	// These three DOE states are never valid in this situation.
	// NotFound as that means we have no evidence that the Secure chain should have stopped.
	// NsecNxDomain & Nsec3NxDomain don't make sense as they must exist if we've been delegated to its ancestor.

	for _, expectedDOE := range []DenialOfExistenceState{NotFound, NsecNxDomain, Nsec3NxDomain} {
		a := NewAuth(context.Background(), dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

		// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure, denialOfExistence: expectedDOE})
		a.results = append(a.results, &result{state: Insecure})
		a.results = append(a.results, &result{state: Insecure})

		state, doe, err := a.Result()
		if err != nil {
			t.Error("unexpected error")
		}
		if doe != expectedDOE {
			t.Error("unexpected doe")
		}
		if state != Bogus {
			t.Error("unexpected state")
		}
	}

	//---

	// The default denialOfExistence is NotFound, but we'll sense check that here.

	a := NewAuth(context.Background(), dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Insecure})
	a.results = append(a.results, &result{state: Insecure})

	state, doe, err := a.Result()
	if err != nil {
		t.Error("unexpected error")
	}
	if doe != NotFound {
		t.Error("unexpected doe")
	}
	if state != Bogus {
		t.Error("unexpected state")
	}

}

func TestResult_IsIsInsecure(t *testing.T) {

	// If the first record is insecure, all records must be insecure (as long as none are Bogus).

	a := NewAuth(context.Background(), dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	a.results = append(a.results, &result{state: Insecure})
	a.results = append(a.results, &result{state: Secure})

	state, doe, err := a.Result()
	if err != nil {
		t.Error("unexpected error")
	}
	if doe != NotFound {
		t.Error("unexpected doe")
	}
	if state != Insecure {
		t.Error("unexpected state")
	}

}

func TestResult_LastIsNec3OptOut(t *testing.T) {

	// If the last record includes a Nsec3OptOut, then the final result must be Insecure.

	a := NewAuth(context.Background(), dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure, denialOfExistence: Nsec3OptOut})

	state, doe, err := a.Result()
	if err != nil {
		t.Error("unexpected error")
	}
	if doe != Nsec3OptOut {
		t.Error("unexpected doe")
	}
	if state != Insecure {
		t.Error("unexpected state")
	}

}

func TestResult_LastHasDOE(t *testing.T) {

	// If the last record has one of these DOEs, then we can conclude Secure.

	for _, expectedDOE := range []DenialOfExistenceState{NsecNxDomain, Nsec3NxDomain, NsecNoData, Nsec3NoData} {
		a := NewAuth(context.Background(), dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

		// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure, denialOfExistence: expectedDOE})

		state, doe, err := a.Result()
		if err != nil {
			t.Error("unexpected error")
		}
		if doe != expectedDOE {
			t.Error("unexpected doe")
		}
		if state != Secure {
			t.Error("unexpected state")
		}
	}

	// These DOEs are not valid on final results. The result is Bogus if we see them.

	for _, expectedDOE := range []DenialOfExistenceState{NsecMissingDS, Nsec3MissingDS} {
		a := NewAuth(context.Background(), dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

		// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure, denialOfExistence: expectedDOE})

		state, doe, err := a.Result()
		if err != nil {
			t.Error("unexpected error")
		}
		if doe != expectedDOE {
			t.Error("unexpected doe")
		}
		if state != Bogus {
			t.Error("unexpected state")
		}
	}
}

func TestResult_LastHasSOA(t *testing.T) {
	// If the Authority section of the final result includes a SOA, and no DOE was found, we conclude Bogus.
	a := NewAuth(context.Background(), dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	msg := &dns.Msg{Ns: []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Rrtype: dns.TypeSOA}}}}

	// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure, msg: msg})

	state, doe, err := a.Result()
	if err != nil {
		t.Error("unexpected error")
	}
	if doe != NotFound {
		t.Error("unexpected doe")
	}
	if state != Bogus {
		t.Error("unexpected state")
	}
}

func TestResult_LastHasMatchingNameAndType(t *testing.T) {

	// If the Answer section of the final result includes a record that matches the Qname and QType, then it's Secure.

	a := NewAuth(context.Background(), dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	msg := &dns.Msg{Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "test.example.com.", Rrtype: dns.TypeA}}}}

	// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure, msg: msg})

	state, doe, err := a.Result()
	if err != nil {
		t.Error("unexpected error")
	}
	if doe != NotFound {
		t.Error("unexpected doe")
	}
	if state != Secure {
		t.Error("unexpected state")
	}
}

func TestResult_LastHasMatchingNameAndCNAME(t *testing.T) {

	// If the Answer section of the final result includes a record that matches the Qname and a CNAME, then it's Secure.

	a := NewAuth(context.Background(), dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	msg := &dns.Msg{Answer: []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "test.example.com.", Rrtype: dns.TypeCNAME}}}}

	// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure, msg: msg})

	state, doe, err := a.Result()
	if err != nil {
		t.Error("unexpected error")
	}
	if doe != NotFound {
		t.Error("unexpected doe")
	}
	if state != Secure {
		t.Error("unexpected state")
	}
}

func TestResult_InvalidIfNameDoesNotMatch(t *testing.T) {

	// If the Answer section of the final result includes a record that matches the type, but not the name, then Bogus.

	a := NewAuth(context.Background(), dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	msg := &dns.Msg{Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "other.example.com.", Rrtype: dns.TypeA}}}}

	// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure, msg: msg})

	state, doe, err := a.Result()
	if err != nil {
		t.Error("unexpected error")
	}
	if doe != NotFound {
		t.Error("unexpected doe")
	}
	if state != Bogus {
		t.Error("unexpected state")
	}
}

func TestResult_InvalidIfTypeDoesNotMatch(t *testing.T) {

	// If the Answer section of the final result includes a record that matches the type, but not the name, then Bogus.

	a := NewAuth(context.Background(), dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	msg := &dns.Msg{Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "test.example.com.", Rrtype: dns.TypeAAAA}}}}

	// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure, msg: msg})

	state, doe, err := a.Result()
	if err != nil {
		t.Error("unexpected error")
	}
	if doe != NotFound {
		t.Error("unexpected doe")
	}
	if state != Bogus {
		t.Error("unexpected state")
	}
}
