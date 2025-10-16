//go:build unbound && cgo && !kres

package backend

import (
    backendunbound "dns-resolver/internal/backend/unbound"
    "dns-resolver/internal/config"
    "dns-resolver/internal/interfaces"
    "dns-resolver/internal/metrics"
)

// New returns the Unbound backend when built with -tags=unbound and CGO enabled.
func New(cfg *config.Config, m *metrics.Metrics) interfaces.Backend {
    return backendunbound.New(cfg, m)
}
