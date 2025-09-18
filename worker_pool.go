package main

import (
	"log"
	"sync"
)

// Job represents the interface for a task that can be executed by a worker.
type Job interface {
	Execute()
}

// WorkerPool manages a pool of workers to execute jobs concurrently.
type WorkerPool struct {
	jobQueue   chan Job
	wg         sync.WaitGroup
	maxWorkers int
}

// NewWorkerPool creates a new WorkerPool.
func NewWorkerPool(maxWorkers int, jobQueueSize int) *WorkerPool {
	if maxWorkers <= 0 {
		maxWorkers = 1 // Ensure at least one worker
	}
	if jobQueueSize < 0 {
		jobQueueSize = 0 // A job queue size of 0 is valid (unbuffered)
	}
	return &WorkerPool{
		maxWorkers: maxWorkers,
		jobQueue:   make(chan Job, jobQueueSize),
	}
}

// Start initializes the worker pool and starts the workers.
func (wp *WorkerPool) Start() {
	for i := 0; i < wp.maxWorkers; i++ {
		wp.wg.Add(1)
		go func(workerID int) {
			defer wp.wg.Done()
			log.Printf("Worker %d started", workerID)
			for job := range wp.jobQueue {
				job.Execute()
			}
			log.Printf("Worker %d stopping.", workerID)
		}(i + 1)
	}
}

// Submit adds a job to the job queue.
func (wp *WorkerPool) Submit(job Job) {
	wp.jobQueue <- job
}

// Stop gracefully shuts down the worker pool.
func (wp *WorkerPool) Stop() {
	log.Println("Stopping WorkerPool...")
	// Close the job queue. This signals workers to stop after processing remaining jobs.
	close(wp.jobQueue)
	// Wait for all worker goroutines to finish.
	wp.wg.Wait()
	log.Println("WorkerPool stopped.")
}
