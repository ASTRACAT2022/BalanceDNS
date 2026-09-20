package threat

import (
	"strings"
	"unicode"
)

// normalizeQuery returns a canonical form of a query name suitable for
// threat matching. It lowercases, trims whitespace, and removes the trailing
// dot when present. The result is a bare domain WITHOUT the trailing dot (e.g.
// "packetsdk.io"), unless the input is empty, in which case "" is returned.
//
// IDN inputs are expected to arrive already in punycode from the DNS layer
// (miekg/dns hands back ASCII/ASCII-with-escapes names); non-ASCII labels are
// lowercased byte-wise, which is sufficient for the suffix match.
func normalizeQuery(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	// Strip a single trailing FQDN dot: "example.org." -> "example.org".
	// Do not strip the bare-root "." label.
	if name != "." && strings.HasSuffix(name, ".") {
		name = name[:len(name)-1]
	}
	return strings.ToLower(name)
}

// splitLabels returns the labels of a normalized bare domain split on the
// final dot boundary, in order. "abc.api-seed.packetsdk.io" ->
// ["abc","api-seed","packetsdk","io"]. An empty or root input returns nil.
func splitLabels(d string) []string {
	if d == "" || d == "." {
		return nil
	}
	return strings.Split(d, ".")
}

// isValidDomain reports whether a normalized string looks like a plausible
// hostname before it is admitted into a snapshot. It rejects entries that would
// be unsafe or useless in a suffix match: empty, wildcard prefixes that were
// not handled, entries with characters that cannot appear in a DNS label
// (aside from letters, digits, hyphen, underscore, and the label dot).
func isValidDomain(d string) bool {
	if d == "" || d == "." {
		return false
	}
	if strings.HasPrefix(d, "*.") || strings.HasPrefix(d, "-") || strings.HasPrefix(d, ".") {
		return false
	}
	for _, r := range d {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	// Reject a domain whose only label is a TLD (single-label TLDs as exact
	// blocked roots are almost always a mistake and create huge catch-alls).
	if !strings.Contains(d, ".") {
		return false
	}
	return true
}

// stripWildcard normalizes a raw feed line that may carry a "*." or leading
// "." into a plain suffix base. It returns "" if the line is not usable.
func stripWildcard(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	if strings.HasPrefix(line, "*.") {
		line = strings.TrimPrefix(line, "*.")
	}
	line = strings.TrimPrefix(line, ".")
	return normalizeQuery(line)
}
