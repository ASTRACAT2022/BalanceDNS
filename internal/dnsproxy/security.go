package dnsproxy

import (
	"sync"
	"time"
)

const securityShardCount = 256

type clientState struct {
	tokens     float64
	lastRefill time.Time
	concurrent int
	lastSeen   time.Time
}

type securityShard struct {
	mu          sync.Mutex
	clients     map[string]*clientState
	nextCleanup time.Time
}

type securityManager struct {
	opts      ProxyOptions
	globalSem chan struct{}
	shards    [securityShardCount]securityShard
}

func newSecurityManager(opts ProxyOptions) *securityManager {
	if !opts.EnableAttackProtection {
		return nil
	}

	sm := &securityManager{
		opts: opts,
	}
	for i := range sm.shards {
		sm.shards[i].clients = make(map[string]*clientState)
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
	shard := s.shard(clientIP)
	shard.mu.Lock()
	if now.After(shard.nextCleanup) {
		s.cleanupLocked(shard, now)
		shard.nextCleanup = now.Add(1 * time.Minute)
	}

	st := shard.clients[clientIP]
	if st == nil {
		st = &clientState{tokens: float64(s.effectiveBurst()), lastRefill: now}
		shard.clients[clientIP] = st
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
			shard.mu.Unlock()
			if globalAcquired {
				<-s.globalSem
			}
			return nil, "per_ip_rate_limit"
		}
		st.tokens -= 1
	}

	if s.opts.MaxConcurrentPerIP > 0 && st.concurrent >= s.opts.MaxConcurrentPerIP {
		shard.mu.Unlock()
		if globalAcquired {
			<-s.globalSem
		}
		return nil, "per_ip_concurrency_limit"
	}

	st.concurrent++
	st.lastSeen = now
	shard.mu.Unlock()

	return func() {
		shard.mu.Lock()
		if st.concurrent > 0 {
			st.concurrent--
		}
		st.lastSeen = time.Now()
		shard.mu.Unlock()
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

func (s *securityManager) cleanupLocked(shard *securityShard, now time.Time) {
	const ttl = 5 * time.Minute
	for ip, st := range shard.clients {
		if st.concurrent == 0 && now.Sub(st.lastSeen) > ttl {
			delete(shard.clients, ip)
		}
	}
}

func (s *securityManager) shard(clientIP string) *securityShard {
	return &s.shards[shardIndex(clientIP)]
}

func shardIndex(clientIP string) uint32 {
	var hash uint32 = 2166136261
	for i := 0; i < len(clientIP); i++ {
		hash ^= uint32(clientIP[i])
		hash *= 16777619
	}
	return hash % uint32(securityShardCount)
}
