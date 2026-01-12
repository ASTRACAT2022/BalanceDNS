package resolver

type ctxKey uint8

const (
	CtxTrace ctxKey = iota

	ctxSessionQueries
	ctxIteration
	ctxZoneName
	ctxStartTime
)
