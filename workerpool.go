package goresolver

import "sync"

// Task represents a job to be executed by a worker.
type Task func()

// WorkerPool manages a pool of workers to execute tasks concurrently.
type WorkerPool struct {
	tasks chan Task
	wg    sync.WaitGroup
}

// NewWorkerPool creates a new WorkerPool with a specified number of workers and task queue size.
func NewWorkerPool(numWorkers, queueSize int) *WorkerPool {
	pool := &WorkerPool{
		tasks: make(chan Task, queueSize),
	}

	pool.wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go pool.worker()
	}

	return pool
}

// Submit adds a task to the worker pool's queue.
func (p *WorkerPool) Submit(task Task) {
	p.tasks <- task
}

// Stop waits for all tasks to be completed and then stops the workers.
func (p *WorkerPool) Stop() {
	close(p.tasks)
	p.wg.Wait()
}

// worker is a goroutine that continuously executes tasks from the tasks channel.
func (p *WorkerPool) worker() {
	defer p.wg.Done()
	for task := range p.tasks {
		task()
	}
}
