package main

import (
	"sync"
	"testing"
)

// TestJob is a simple job for benchmarking that does nothing.
type TestJob struct {
	wg *sync.WaitGroup
}

func (j *TestJob) Execute() {
	if j.wg != nil {
		j.wg.Done()
	}
}

// BenchmarkWorkerPoolThroughput measures how long it takes for N jobs to be fully processed.
// This is the most accurate measure of the pool's throughput.
func BenchmarkWorkerPoolThroughput(b *testing.B) {
	// Initialize the worker pool
	// Using a large number of workers to ensure the bottleneck is the pool's overhead,
	// not a lack of available workers.
	pool := NewWorkerPool(200, b.N)
	pool.Start()

	// Create a reusable job instance
	job := &TestJob{}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pool.Submit(job)
	}

	// Stop the pool. This will block until all jobs in the queue are processed.
	// This is the correct way to measure total throughput.
	pool.Stop()
}


// BenchmarkWorkerPoolSubmit measures only how fast jobs can be submitted to the queue.
// This is less about throughput and more about the overhead of the Submit call itself.
func BenchmarkWorkerPoolSubmit(b *testing.B) {
	pool := NewWorkerPool(100, b.N)
	pool.Start()
	defer pool.Stop()

	job := &TestJob{}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pool.Submit(job)
	}
}
