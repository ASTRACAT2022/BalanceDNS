package adblock

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAdBlockPlugin_UpdateBlocklists_WithHostsFormat(t *testing.T) {
	// Mock hosts content
	hostsContent := `
# This is a comment
0.0.0.0 example.com
0.0.0.0 another-domain.org # inline comment
127.0.0.1 localhost
::1 localhost
`

	// Create a mock HTTP server to serve the hosts file
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, hostsContent)
	}))
	defer server.Close()

	// Initialize the AdBlock plugin with the mock server's URL
	plugin := New([]string{server.URL}, 1*time.Hour)
	plugin.UpdateBlocklists() // Manually trigger an update

	// Check if the domains are correctly blocked
	testCases := []struct {
		domain   string
		expected bool
	}{
		{"example.com", true},
		{"www.example.com", true}, // Subdomain should be blocked
		{"another-domain.org", true},
		{"sub.another-domain.org", true}, // Subdomain should be blocked
		{"localhost", false}, // Should not be blocked as it's not 0.0.0.0
		{"google.com", false},
	}

	for _, tc := range testCases {
		t.Run(tc.domain, func(t *testing.T) {
			_, isBlocked := plugin.filter.Match(tc.domain)
			if isBlocked != tc.expected {
				t.Errorf("Expected domain %s to be blocked=%v, but got %v", tc.domain, tc.expected, isBlocked)
			}
		})
	}
}
