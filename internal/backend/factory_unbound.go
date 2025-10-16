//go:build !kres && (!unbound || !cgo)

package backend

import (
    "dns-resolver/internal/backend/stub"
    "dns-resolver/internal/config"
    "dns-resolver/internal/interfaces"
    "dns-resolver/internal/metrics"
)

// New returns the default cgo-free stub backend when neither Kres nor
// Unbound+cgo backends are enabled via build tags.
func New(cfg *config.Config, m *metrics.Metrics) interfaces.Backend {
    return stub.NewDefault()
}
