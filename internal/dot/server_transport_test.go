package dot

import (
	"errors"
	"net"
	"testing"
)

func TestShouldFallbackTCPOnUpstreamError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "overflow", err: errors.New("dns: overflow unpacking uint16"), want: true},
		{name: "timeout string", err: errors.New("i/o timeout"), want: true},
		{name: "temporary net error", err: &net.DNSError{IsTemporary: true}, want: true},
		{name: "other", err: errors.New("connection refused"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldFallbackTCPOnUpstreamError(tt.err)
			if got != tt.want {
				t.Fatalf("got=%v want=%v", got, tt.want)
			}
		})
	}
}

func TestIsRetriableUpstreamError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "timeout net", err: &net.DNSError{IsTimeout: true}, want: true},
		{name: "temporary net", err: &net.DNSError{IsTemporary: true}, want: true},
		{name: "timeout string", err: errors.New("request timeout"), want: true},
		{name: "hard error", err: errors.New("permission denied"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRetriableUpstreamError(tt.err)
			if got != tt.want {
				t.Fatalf("got=%v want=%v", got, tt.want)
			}
		})
	}
}
