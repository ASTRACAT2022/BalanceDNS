package resolver

import (
	"github.com/miekg/dns"
)

var dnsRecordTypes = map[uint16]string{
	1:     "A",
	2:     "NS",
	5:     "CNAME",
	6:     "SOA",
	12:    "PTR",
	15:    "MX",
	16:    "TXT",
	17:    "RP",
	18:    "AFSDB",
	24:    "SIG", // Predecessor to RRSIG, included for completeness
	25:    "KEY", // Predecessor to DNSKEY
	28:    "AAAA",
	29:    "LOC",
	33:    "SRV",
	35:    "NAPTR",
	36:    "KX",
	37:    "CERT",
	39:    "DNAME",
	41:    "OPT", // Pseudo-record for EDNS (Extended DNS)
	43:    "DS",
	44:    "SSHFP",    // SSH Public Key Fingerprint
	45:    "IPSECKEY", // IPsec Key
	46:    "RRSIG",
	47:    "NSEC",
	48:    "DNSKEY",
	49:    "DHCID", // DHCP Identifier
	50:    "NSEC3",
	51:    "NSEC3PARAM",
	52:    "TLSA",
	53:    "SMIMEA",     // S/MIME certificate association
	55:    "HIP",        // Host Identity Protocol
	57:    "NINFO",      // (Experimental, rarely used)
	59:    "CDS",        // Child DS, related to DNSSEC delegation
	60:    "CDNSKEY",    // Child DNSKEY, related to DNSSEC delegation
	61:    "OPENPGPKEY", // OpenPGP public key
	62:    "CSYNC",      // Child-To-Parent Synchronization
	63:    "ZONEMD",     // Zone Message Digest
	64:    "SVCB",       // Service Binding
	65:    "HTTPS",      // HTTPS-specific Service Binding
	99:    "SPF",        // Sender Policy Framework, typically TXT now
	100:   "UINFO",      // User Information
	101:   "UID",        // User ID
	102:   "GID",        // Group ID
	103:   "UNSPEC",     // Unspecified Information
	108:   "EUI48",      // Extended Unique Identifier (48-bit)
	109:   "EUI64",      // Extended Unique Identifier (64-bit)
	249:   "TKEY",       // Transaction Key, for DNS security
	250:   "TSIG",       // Transaction Signature, for DNS security
	251:   "IXFR",       // Incremental Zone Transfer
	252:   "AXFR",       // Full Zone Transfer
	255:   "ANY",        // Query for all record types
	256:   "URI",        // URI record
	257:   "CAA",
	32768: "TA",  // Trust Anchor, experimental
	32769: "DLV", // DNSSEC Lookaside Validation, obsolete
}

func TypeToString(rrtype uint16) string {
	if name, ok := dnsRecordTypes[rrtype]; ok {
		return name
	} else {
		return "unknown"
	}
}

//---

var dnsRCodes = map[int]string{
	0:  "NoError",   // RcodeSuccess
	1:  "FormErr",   // RcodeFormatError
	2:  "ServFail",  // RcodeServerFailure
	3:  "NXDomain",  // RcodeNameError
	4:  "NotImp",    // RcodeNotImplemented
	5:  "Refused",   // RcodeRefused
	6:  "YXDomain",  // RcodeYXDomain
	7:  "YXRRSet",   // RcodeYXRrset
	8:  "NXRRSet",   // RcodeNXRrset
	9:  "NotAuth",   // RcodeNotAuth
	10: "NotZone",   // RcodeNotZone
	16: "BADSIG",    // RcodeBadSig and RcodeBadVers
	17: "BADKEY",    // RcodeBadKey
	18: "BADTIME",   // RcodeBadTime
	19: "BADMODE",   // RcodeBadMode
	20: "BADNAME",   // RcodeBadName
	21: "BADALG",    // RcodeBadAlg
	22: "BADTRUNC",  // RcodeBadTrunc
	23: "BADCOOKIE", // RcodeBadCookie
}

func RcodeToString(rcode int) string {
	if name, ok := dnsRCodes[rcode]; ok {
		return name
	} else {
		return "unknown"
	}
}

//---

func isSetDO(msg *dns.Msg) bool {
	for _, extra := range msg.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			return opt.Do()
		}
	}
	return false
}

func canonicalName(name string) string {
	return dns.CanonicalName(name)
}

func extractRecords[T dns.RR](rr []dns.RR) []T {
	result := make([]T, 0, len(rr))
	for _, record := range rr {
		if typedRecord, ok := record.(T); ok {
			result = append(result, typedRecord)
		}
	}
	return result
}

func recordsOfTypeExist(rr []dns.RR, t uint16) bool {
	for _, record := range rr {
		if record.Header().Rrtype == t {
			return true
		}
	}
	return false
}

func removeRecordsOfType(rr []dns.RR, t uint16) []dns.RR {
	if len(rr) == 0 || !recordsOfTypeExist(rr, t) {
		return rr
	}
	r := make([]dns.RR, 0, len(rr)-1) // -1 as we know at least one is the records we're removing.
	for _, record := range rr {
		if record.Header().Rrtype != t {
			r = append(r, record)
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

func recordsOfNameAndTypeExist(rr []dns.RR, name string, t uint16) bool {
	for _, record := range rr {
		if record.Header().Rrtype == t && record.Header().Name == name {
			return true
		}
	}
	return false
}

func namesEqual(s1, s2 string) bool {
	return dns.CanonicalName(s1) == dns.CanonicalName(s2)
}
