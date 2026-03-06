package dnsproxy

import (
	"sync"
	"time"
)

type clientState struct {
	tokens     float64
	lastRefill time.Time
	concurrent int
	lastSeen   time.Time
}

type securityManager struct {
	opts        ProxyOptions
	mu          sync.Mutex
	clients     map[string]*clientState
	nextCleanup time.Time
	globalSem   chan struct{}
}

func newSecurityManager(opts ProxyOptions) *securityManager {
	if !opts.EnableAttackProtection {
		return nil
	}

	sm := &securityManager{
		opts:      opts,
		clients:   make(map[string]*clientState),
		globalSem: nil,
	}
	if opts.MaxGlobalInflight > 0 {
		sm.globalSem = make(chan struct{}, opts.MaxGlobalInflight)
	}
	return sm
}

func (s *securityManager) admit(clientIP string) (release func(), denyReason string) {
	if s == nil {
		return func() {}, ""
	}
	if clientIP == "" {
		clientIP = "unknown"
	}

	globalAcquired := false
	if s.globalSem != nil {
		select {
		case s.globalSem <- struct{}{}:
			globalAcquired = true
		default:
			return nil, "global_inflight_limit"
		}
	}

	now := time.Now()
	s.mu.Lock()
	if now.After(s.nextCleanup) {
		s.cleanupLocked(now)
		s.nextCleanup = now.Add(1 * time.Minute)
	}

	st := s.clients[clientIP]
	if st == nil {
		st = &clientState{tokens: float64(s.effectiveBurst()), lastRefill: now}
		s.clients[clientIP] = st
	}

	if s.opts.MaxQPSPerIP > 0 {
		burst := float64(s.effectiveBurst())
		if st.lastRefill.IsZero() {
			st.lastRefill = now
		}
		elapsed := now.Sub(st.lastRefill).Seconds()
		if elapsed > 0 {
			st.tokens += elapsed * float64(s.opts.MaxQPSPerIP)
			if st.tokens > burst {
				st.tokens = burst
			}
			st.lastRefill = now
		}
		if st.tokens < 1 {
			s.mu.Unlock()
			if globalAcquired {
				<-s.globalSem
			}
			return nil, "per_ip_rate_limit"
		}
		st.tokens -= 1
	}

	if s.opts.MaxConcurrentPerIP > 0 && st.concurrent >= s.opts.MaxConcurrentPerIP {
		s.mu.Unlock()
		if globalAcquired {
			<-s.globalSem
		}
		return nil, "per_ip_concurrency_limit"
	}

	st.concurrent++
	st.lastSeen = now
	s.mu.Unlock()

	return func() {
		s.mu.Lock()
		if st.concurrent > 0 {
			st.concurrent--
		}
		st.lastSeen = time.Now()
		s.mu.Unlock()
		if globalAcquired {
			<-s.globalSem
		}
	}, ""
}

func (s *securityManager) effectiveBurst() int {
	if s.opts.RateLimitBurstPerIP > 0 {
		return s.opts.RateLimitBurstPerIP
	}
	if s.opts.MaxQPSPerIP > 0 {
		return s.opts.MaxQPSPerIP
	}
	return 1
}

func (s *securityManager) cleanupLocked(now time.Time) {
	const ttl = 5 * time.Minute
	for ip, st := range s.clients {
		if st.concurrent == 0 && now.Sub(st.lastSeen) > ttl {
			delete(s.clients, ip)
		}
	}
}
