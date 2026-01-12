package dnssec

import (
	"github.com/miekg/dns"
)

func extractRecords[T dns.RR](rr []dns.RR) []T {
	r := make([]T, 0, len(rr))
	for _, record := range rr {
		if typedRecord, ok := record.(T); ok {
			r = append(r, typedRecord)
		}
	}
	return r
}

func extractRecordsOfType(rr []dns.RR, t uint16) []dns.RR {
	r := make([]dns.RR, 0, len(rr))
	for _, record := range rr {
		if record.Header().Rrtype == t {
			r = append(r, record)
		}
	}
	return r
}

func extractRecordsOfNameAndType(rr []dns.RR, name string, t uint16) []dns.RR {
	r := make([]dns.RR, 0, len(rr))
	for _, record := range rr {
		if record.Header().Rrtype == t && record.Header().Name == name {
			r = append(r, record)
		}
	}
	return r
}

func recordsOfTypeExist(rr []dns.RR, t uint16) bool {
	for _, record := range rr {
		if record.Header().Rrtype == t {
			return true
		}
	}
	return false
}

func recordsHaveTheSameOwner(rr []dns.RR) bool {
	if len(rr) < 2 {
		return true
	}
	owner := rr[0].Header().Name
	for i := 1; i < len(rr); i++ {
		if rr[i].Header().Name != owner {
			return false
		}
	}
	return true
}

// wildcardName replaces the first label with `*`
func wildcardName(name string) string {
	labelIndexes := dns.Split(name)
	if len(labelIndexes) < 2 {
		return "*."
	}
	return "*." + name[labelIndexes[1]:]
}

func namesEqual(s1, s2 string) bool {
	return dns.CanonicalName(s1) == dns.CanonicalName(s2)
}

func getOwnerNameFromSet(rr []dns.RR) (string, bool) {
	if len(rr) > 0 {
		return rr[0].Header().Name, true
	}
	return "", false
}
