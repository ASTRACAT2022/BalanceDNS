package server

import (
	"context"
	"sync"
	"time"
)

// TokenBucket represents a token bucket rate limiter
type TokenBucket struct {
	rate         float64 // tokens per second
	burst        uint64  // bucket size
	available    uint64  // currently available tokens
	lastUpdate   time.Time
	mutex        sync.Mutex
}

// NewTokenBucket creates a new token bucket
func NewTokenBucket(rate float64, burst uint64) *TokenBucket {
	return &TokenBucket{
		rate:       rate,
		burst:      burst,
		available:  burst,
		lastUpdate: time.Now(),
	}
}

// Allow checks if a request is allowed based on the rate limit
func (tb *TokenBucket) Allow() bool {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()

	// Add tokens based on time passed since last update
	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()
	newTokens := uint64(tb.rate * elapsed)

	tb.available += newTokens
	if tb.available > tb.burst {
		tb.available = tb.burst
	}

	tb.lastUpdate = now

	// Check if we can consume a token
	if tb.available > 0 {
		tb.available--
		return true
	}

	return false
}

// RateLimiter manages rate limiting for different IP addresses
type RateLimiter struct {
	limiters map[string]*TokenBucket
	mutex    sync.RWMutex
	rate     float64
	burst    uint64
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate float64, burst uint64) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*TokenBucket),
		rate:     rate,
		burst:    burst,
	}
}

// Allow checks if a request from the given IP is allowed
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mutex.RLock()
	limiter, exists := rl.limiters[ip]
	rl.mutex.RUnlock()

	if !exists {
		rl.mutex.Lock()
		// Double-check after acquiring write lock
		if limiter, exists = rl.limiters[ip]; !exists {
			limiter = NewTokenBucket(rl.rate, rl.burst)
			rl.limiters[ip] = limiter
		}
		rl.mutex.Unlock()
	}

	return limiter.Allow()
}

// Cleanup removes expired rate limiters (not needed for our simple case)
func (rl *RateLimiter) Cleanup() {
	// In a real implementation, you might want to clean up unused limiters
}