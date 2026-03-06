//go:build !cgo || !unbound

package main

import (
	"fmt"

	"dns-resolver/internal/config"
)

func newUnboundResolver(_ *config.Config) (runtimeResolver, error) {
	return nil, fmt.Errorf("resolver_type=unbound requested, but binary was built without unbound support (rebuild with CGO_ENABLED=1 and -tags unbound, and install libunbound-dev)")
}
