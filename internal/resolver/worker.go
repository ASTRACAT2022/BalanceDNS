package resolver

import "context"

// WorkerPool is a simple worker pool to limit concurrency.
type WorkerPool struct {
	sem chan struct{}
}

// NewWorkerPool creates a new worker pool with the given size.
func NewWorkerPool(size int) *WorkerPool {
	if size <= 0 {
		// If size is not positive, create a pool that doesn't limit concurrency.
		// This is not ideal, but it's better than panicking.
		// A better approach would be to return an error.
		return &WorkerPool{}
	}
	return &WorkerPool{
		sem: make(chan struct{}, size),
	}
}

// Acquire acquires a worker from the pool. It blocks until a worker is available or the context is canceled.
func (p *WorkerPool) Acquire(ctx context.Context) error {
	if p.sem == nil {
		return nil // No limiting
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case p.sem <- struct{}{}:
		return nil
	}
}

// Release releases a worker back to the pool.
func (p *WorkerPool) Release() {
	if p.sem == nil {
		return // No limiting
	}
	<-p.sem
}
