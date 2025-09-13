package resolver

import (
	"fmt"
	"github.com/miekg/dns"
	"slices"
)

// domain represents a domain name with utilities for traversing its labels.
type domain struct {
	name         string // full canonical domain name
	labelIndexes []int  // indices marking each label start in the domain
	currentIdx   int    // current traversal position in labelIndexes
}

// newDomain creates a new domain with a canonical name and prepares label indexes for traversal.
func newDomain(d string) domain {
	d = dns.CanonicalName(d)
	labelIndexes := append(dns.Split(d), len(d)-1)

	// We iterate over the labels backwards, shortest FQDN to longest.
	slices.Reverse(labelIndexes)

	return domain{name: d, labelIndexes: labelIndexes}
}

// windTo moves to the specified label within the domain, returning an error if not found.
func (d *domain) windTo(target string) error {
	target = dns.CanonicalName(target)

	if !dns.IsSubDomain(target, d.name) {
		return fmt.Errorf("%s is not a subdomain of %s", target, d.name)
	}

	for d.more() {
		if d.current() == target {
			return nil
		}
		d.next()
	}

	return fmt.Errorf("%s not found", target)
}

// current returns the domain segment from the current label position onward.
func (d *domain) current() string {

	// If the index pointer has moved past the end of the slice, we always return the full name.
	if d.currentIdx >= len(d.labelIndexes) {
		return d.name
	}

	return d.name[d.labelIndexes[d.currentIdx]:]
}

// next advances to the next label position in the domain hierarchy.
func (d *domain) next() {
	d.currentIdx++
}

// more checks if there are remaining labels to traverse.
func (d *domain) more() bool {
	// By setting this to <=, the last domain is returned twice.
	// This is needed when the QName is the apex of a zone.
	// The first call resolves the zone's name servers; the second the actual response.
	return d.currentIdx <= len(d.labelIndexes)
}

func (d *domain) last() bool {
	return d.currentIdx >= len(d.labelIndexes)-1
}

// gap returns intermediate domain segments between the current position and a target with more labels.
func (d *domain) gap(target string) []string {
	if !dns.IsSubDomain(target, d.name) {
		return nil
	}

	missing := dns.CountLabel(target) - dns.CountLabel(d.current())
	if missing <= 0 {
		return nil
	}

	results := make([]string, 0, missing)
	for i := d.currentIdx; i < missing+d.currentIdx; i++ {
		results = append(results, d.name[d.labelIndexes[i]:])
	}
	return results
}
