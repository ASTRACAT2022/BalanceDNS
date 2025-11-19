package dnssec

import (
	"github.com/miekg/dns"
	"slices"
	"testing"
)

func TestFunctions_SetFiltering(t *testing.T) {

	// extractRecords

	rr1 := newRR("example.com. 3600 IN NS ns1.example.com.").(*dns.NS)
	rr2 := newRR("a.example.com. 3600 IN NS ns1.example.com.").(*dns.NS)
	rr3 := newRR("b.example.com. 3600 IN NS ns1.example.com.").(*dns.NS)
	rr4 := newRR("example.com. 3600 IN MX 10 mx1.example.com.").(*dns.MX)
	rr5 := newRR("example.com. 3600 IN MX 10 mx2.example.com.").(*dns.MX)
	rr6 := newRR("example.com. 54775 IN DS 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A8 6764247C").(*dns.DS)

	set := []dns.RR{rr1, rr2, rr3, rr4, rr5, rr6}

	if !slices.Equal([]*dns.NS{rr1, rr2, rr3}, extractRecords[*dns.NS](set)) {
		t.Error("Failed to extract NS records")
	}
	if !slices.Equal([]*dns.MX{rr4, rr5}, extractRecords[*dns.MX](set)) {
		t.Error("Failed to extract MX records")
	}
	if !slices.Equal([]*dns.DS{rr6}, extractRecords[*dns.DS](set)) {
		t.Error("Failed to extract DS records")
	}

	//---

	// extractRecordsOfType

	if !slices.Equal([]dns.RR{rr1, rr2, rr3}, extractRecordsOfType(set, dns.TypeNS)) {
		t.Error("Failed to extract NS records")
	}
	if !slices.Equal([]dns.RR{rr4, rr5}, extractRecordsOfType(set, dns.TypeMX)) {
		t.Error("Failed to extract MX records")
	}
	if !slices.Equal([]dns.RR{rr6}, extractRecordsOfType(set, dns.TypeDS)) {
		t.Error("Failed to extract DS records")
	}

	//---

	// extractRecordsOfNameAndType

	if !slices.Equal([]dns.RR{rr2}, extractRecordsOfNameAndType(set, "a.example.com.", dns.TypeNS)) {
		t.Error("Failed to extract NS record with expected name")
	}

	if len(extractRecordsOfNameAndType(set, "a.example.com.", dns.TypeMX)) != 0 {
		t.Error("We expect an empty set back")
	}

	//---

	// recordsOfTypeExist

	if !recordsOfTypeExist(set, dns.TypeNS) {
		t.Error("Failed to find NS records")
	}
	if !recordsOfTypeExist(set, dns.TypeMX) {
		t.Error("Failed to find MX records")
	}
	if !recordsOfTypeExist(set, dns.TypeDS) {
		t.Error("Failed to find DS records")
	}

	if recordsOfTypeExist(set, dns.TypeA) {
		t.Error("We do not expect to find an A record")
	}
	if recordsOfTypeExist(set, dns.TypeAAAA) {
		t.Error("We do not expect to find an AAAA record")
	}
	if recordsOfTypeExist(set, dns.TypeSOA) {
		t.Error("We do not expect to find an SOA record")
	}

	//---

	// recordsHaveTheSameOwner

	if !recordsHaveTheSameOwner([]dns.RR{rr1, rr4, rr5, rr6}) {
		t.Error("We expected to find the same owner record")
	}

	if recordsHaveTheSameOwner([]dns.RR{rr1, rr2, rr3, rr4, rr5, rr6}) {
		t.Error("We did not expect to find the same owner record")
	}

	if !recordsHaveTheSameOwner([]dns.RR{rr1}) {
		t.Error("We expected to find the same owner record")
	}

	if !recordsHaveTheSameOwner([]dns.RR{}) {
		t.Error("We expected to find the same owner record")
	}

}

func TestFunctions_WildcardName(t *testing.T) {

	if s := wildcardName("text.example.com"); s != "*.example.com" {
		t.Errorf("we expected '*.example.com' but got '%s'", s)
	}

	if s := wildcardName("a.b.c.d.e.example.com."); s != "*.b.c.d.e.example.com." {
		t.Errorf("we expected '*.b.c.d.e.example.com' but got '%s'", s)
	}

	if s := wildcardName("com."); s != "*." {
		t.Errorf("we expected '*.' but got '%s'", s)
	}

}
