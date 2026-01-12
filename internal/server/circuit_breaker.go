package server

import (
	"sync"
	"time"
)

// CircuitState represents the state of the circuit breaker
type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

// CircuitBreaker implements the circuit breaker pattern for resilience
type CircuitBreaker struct {
	state          CircuitState
	mu             sync.RWMutex
	failureCount   int
	lastFailure    time.Time
	maxFailures    int
	resetTimeout   time.Duration
	halfOpenTimeout time.Duration
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(maxFailures int, resetTimeout, halfOpenTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		state:           CircuitClosed,
		maxFailures:     maxFailures,
		resetTimeout:    resetTimeout,
		halfOpenTimeout: halfOpenTimeout,
	}
}

// Call executes the function if the circuit is closed or half-open
func (cb *CircuitBreaker) Call(fn func() error) error {
	cb.mu.Lock()
	
	if cb.state == CircuitOpen {
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			cb.state = CircuitHalfOpen
		} else {
			cb.mu.Unlock()
			return nil // Circuit is open, return early without execution
		}
	}
	
	cb.mu.Unlock()
	
	err := fn()
	
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	if err != nil {
		cb.onFailure()
		return err
	} else {
		cb.onSuccess()
		return nil
	}
}

// onSuccess handles successful execution
func (cb *CircuitBreaker) onSuccess() {
	cb.failureCount = 0
	cb.state = CircuitClosed
}

// onFailure handles failed execution
func (cb *CircuitBreaker) onFailure() {
	cb.failureCount++
	
	if cb.failureCount >= cb.maxFailures {
		cb.state = CircuitOpen
		cb.lastFailure = time.Now()
	}
}

// IsOpen returns whether the circuit is open
func (cb *CircuitBreaker) IsOpen() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	
	if cb.state == CircuitOpen && time.Since(cb.lastFailure) > cb.resetTimeout {
		cb.state = CircuitHalfOpen
	}
	
	return cb.state == CircuitOpen
}