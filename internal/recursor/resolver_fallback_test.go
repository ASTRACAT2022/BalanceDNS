package recursor

import (
	"testing"
	"time"
)

func TestFallbackResolveTimeoutBounds(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		min  time.Duration
		max  time.Duration
		want time.Duration
	}{
		{
			name: "defaults to minimum",
			opts: Options{QueryTimeout: 500 * time.Millisecond},
			want: 2 * time.Second,
		},
		{
			name: "scales with query timeout",
			opts: Options{QueryTimeout: 3 * time.Second},
			want: 6 * time.Second,
		},
		{
			name: "caps at maximum",
			opts: Options{QueryTimeout: 8 * time.Second},
			want: 10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fallbackResolveTimeout(tt.opts)
			if got != tt.want {
				t.Fatalf("fallbackResolveTimeout()=%s want=%s", got, tt.want)
			}
		})
	}
}

func TestCanUseFallback(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want bool
	}{
		{
			name: "strict dnssec disables fallback",
			opts: Options{ValidateDNSSEC: true, DNSSECFailClosed: true},
			want: false,
		},
		{
			name: "dnssec validate but fail-open allows fallback",
			opts: Options{ValidateDNSSEC: true, DNSSECFailClosed: false},
			want: true,
		},
		{
			name: "dnssec disabled allows fallback",
			opts: Options{ValidateDNSSEC: false, DNSSECFailClosed: true},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Resolver{opts: tt.opts}
			if got := r.canUseFallback(); got != tt.want {
				t.Fatalf("canUseFallback()=%v want=%v", got, tt.want)
			}
		})
	}
}
