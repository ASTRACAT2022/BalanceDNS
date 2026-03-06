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
