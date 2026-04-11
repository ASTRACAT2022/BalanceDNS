package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"balancedns/internal/logx"
	"balancedns/internal/metrics"
)

type ComponentConfig struct {
	Name     string
	Required bool
	Start    func(ctx context.Context) error
}

type Options struct {
	RestartBackoff      time.Duration
	RestartMaxBackoff   time.Duration
	MaxConsecutiveFails int
	MinStableRun        time.Duration
}

type State struct {
	Name                string    `json:"name"`
	Required            bool      `json:"required"`
	Running             bool      `json:"running"`
	Restarts            uint64    `json:"restarts"`
	ConsecutiveFailures uint64    `json:"consecutive_failures"`
	LastError           string    `json:"last_error,omitempty"`
	LastStartAt         time.Time `json:"last_start_at,omitempty"`
	LastStopAt          time.Time `json:"last_stop_at,omitempty"`
}

type Supervisor struct {
	logger  *logx.Logger
	metrics *metrics.Provider

	components []ComponentConfig
	opts       Options

	mu     sync.RWMutex
	states map[string]State

	wg       sync.WaitGroup
	fatalErr chan error
	onceErr  sync.Once
}

func New(logger *logx.Logger, m *metrics.Provider, components []ComponentConfig, opts Options) *Supervisor {
	if opts.RestartBackoff <= 0 {
		opts.RestartBackoff = 200 * time.Millisecond
	}
	if opts.RestartMaxBackoff <= 0 {
		opts.RestartMaxBackoff = 5 * time.Second
	}
	if opts.MinStableRun <= 0 {
		opts.MinStableRun = 10 * time.Second
	}
	if opts.RestartBackoff > opts.RestartMaxBackoff {
		opts.RestartBackoff = opts.RestartMaxBackoff
	}

	states := make(map[string]State, len(components))
	for _, c := range components {
		states[c.Name] = State{Name: c.Name, Required: c.Required}
	}

	return &Supervisor{
		logger:     logger,
		metrics:    m,
		components: components,
		opts:       opts,
		states:     states,
		fatalErr:   make(chan error, 1),
	}
}

func (s *Supervisor) Run(ctx context.Context) error {
	if len(s.components) == 0 {
		return errors.New("supervisor has no components")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, c := range s.components {
		component := c
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.runComponentLoop(ctx, component)
		}()
	}

	select {
	case <-ctx.Done():
		s.wg.Wait()
		return nil
	case err := <-s.fatalErr:
		cancel()
		s.wg.Wait()
		return err
	}
}

func (s *Supervisor) runComponentLoop(ctx context.Context, c ComponentConfig) {
	backoff := s.opts.RestartBackoff

	for {
		if ctx.Err() != nil {
			return
		}

		startedAt := time.Now()
		s.markRunning(c.Name, true, "")

		err := c.Start(ctx)
		if ctx.Err() != nil {
			s.markRunning(c.Name, false, "")
			return
		}
		if err == nil {
			err = errors.New("component exited without error")
		}

		uptime := time.Since(startedAt)
		state := s.markFailure(c.Name, err)
		s.logger.Errorf("component %s stopped: %v (uptime=%s, restart=%d)", c.Name, err, uptime, state.Restarts)

		if c.Required && s.opts.MaxConsecutiveFails > 0 && int(state.ConsecutiveFailures) >= s.opts.MaxConsecutiveFails {
			s.pushFatal(fmt.Errorf("component %s exceeded max consecutive failures (%d)", c.Name, s.opts.MaxConsecutiveFails))
			return
		}

		if uptime >= s.opts.MinStableRun {
			backoff = s.opts.RestartBackoff
			s.resetConsecutive(c.Name)
		} else {
			backoff *= 2
			if backoff > s.opts.RestartMaxBackoff {
				backoff = s.opts.RestartMaxBackoff
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

func (s *Supervisor) markRunning(name string, running bool, lastErr string) {
	s.mu.Lock()
	st := s.states[name]
	st.Running = running
	if running {
		st.LastStartAt = time.Now()
	} else {
		st.LastStopAt = time.Now()
	}
	if lastErr != "" {
		st.LastError = lastErr
	}
	s.states[name] = st
	s.mu.Unlock()

	if s.metrics != nil {
		s.metrics.SetComponentUp(name, running)
	}
}

func (s *Supervisor) markFailure(name string, err error) State {
	s.mu.Lock()
	st := s.states[name]
	st.Running = false
	st.LastStopAt = time.Now()
	st.LastError = err.Error()
	st.Restarts++
	st.ConsecutiveFailures++
	s.states[name] = st
	s.mu.Unlock()

	if s.metrics != nil {
		s.metrics.SetComponentUp(name, false)
		s.metrics.IncComponentRestart(name)
	}
	return st
}

func (s *Supervisor) resetConsecutive(name string) {
	s.mu.Lock()
	st := s.states[name]
	st.ConsecutiveFailures = 0
	s.states[name] = st
	s.mu.Unlock()
}

func (s *Supervisor) pushFatal(err error) {
	s.onceErr.Do(func() {
		s.fatalErr <- err
	})
}

func (s *Supervisor) Snapshot() []State {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]State, 0, len(s.states))
	for _, st := range s.states {
		out = append(out, st)
	}
	return out
}

func (s *Supervisor) Healthy(requiredOnly bool) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, st := range s.states {
		if requiredOnly && !st.Required {
			continue
		}
		if !st.Running {
			return false
		}
	}
	return true
}
