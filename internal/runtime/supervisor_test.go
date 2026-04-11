package runtime

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"balancedns/internal/logx"
	"balancedns/internal/metrics"
)

func TestSupervisorRestartsComponent(t *testing.T) {
	var calls atomic.Int32

	comp := ComponentConfig{
		Name:     "test",
		Required: true,
		Start: func(ctx context.Context) error {
			n := calls.Add(1)
			if n <= 2 {
				return errors.New("boom")
			}
			<-ctx.Done()
			return nil
		},
	}

	s := New(logx.New("error", false), metrics.New(), []ComponentConfig{comp}, Options{
		RestartBackoff:    10 * time.Millisecond,
		RestartMaxBackoff: 20 * time.Millisecond,
		MinStableRun:      30 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	if err := s.Run(ctx); err != nil {
		t.Fatalf("run supervisor: %v", err)
	}

	if calls.Load() < 3 {
		t.Fatalf("expected restart attempts, calls=%d", calls.Load())
	}
}

func TestSupervisorTriggersFatalOnMaxFailures(t *testing.T) {
	comp := ComponentConfig{
		Name:     "fatal",
		Required: true,
		Start: func(ctx context.Context) error {
			return errors.New("always fail")
		},
	}

	s := New(logx.New("error", false), metrics.New(), []ComponentConfig{comp}, Options{
		RestartBackoff:      5 * time.Millisecond,
		RestartMaxBackoff:   10 * time.Millisecond,
		MaxConsecutiveFails: 3,
		MinStableRun:        100 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := s.Run(ctx)
	if err == nil {
		t.Fatalf("expected fatal error")
	}
}
