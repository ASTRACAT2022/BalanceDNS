package resolver

import (
	"github.com/google/uuid"
	"sync/atomic"
	"time"
)

type Trace struct {
	Id    uuid.UUID
	Start time.Time

	Iterations atomic.Uint32
}

func NewTrace() *Trace {
	return newTraceWithStart(time.Now())
}

func newTraceWithStart(start time.Time) *Trace {
	id, _ := uuid.NewV7()
	trace := &Trace{
		Id:    id,
		Start: start,
	}
	return trace
}

func (t *Trace) ID() string {
	return t.Id.String()
}

func (t *Trace) ShortID() string {
	// Return only the last 7 characters. In the vast majority of cases this is unique enough.
	return t.ID()[29:]
}

func (t *Trace) Iteration() uint32 {
	return t.Iterations.Load()
}
