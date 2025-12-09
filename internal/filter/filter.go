package filter

import (
	"net"
	"strings"
	"sync"

	"github.com/armon/go-radix"
)

// DomainFilter is a filter for domains.
type DomainFilter struct {
	tree *radix.Tree
	mu   sync.RWMutex
}

// NewDomainFilter creates a new DomainFilter.
func NewDomainFilter() *DomainFilter {
	return &DomainFilter{
		tree: radix.New(),
	}
}

// Add adds a domain to the filter.
func (f *DomainFilter) Add(domain string, ip net.IP) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Ensure domain is clean and consistent
	domain = strings.ToLower(strings.TrimSpace(domain))
	f.tree.Insert(domain, ip)
}

// Len returns the number of items in the filter.
func (f *DomainFilter) Len() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.tree.Len()
}

// Match checks if a domain or its parent domain is in the filter.
func (f *DomainFilter) Match(domain string) (net.IP, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Sanitize domain
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// Check for exact match first
	if val, ok := f.tree.Get(domain); ok {
		return val.(net.IP), true
	}

	// Check for parent domain matches (for subdomain blocking)
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return nil, false
	}

	for i := 1; i < len(parts); i++ {
		parentDomain := strings.Join(parts[i:], ".")
		if val, ok := f.tree.Get(parentDomain); ok {
			// If a parent domain is in the tree, we consider it a match.
			return val.(net.IP), true
		}
	}

	return nil, false
}
