package cache

const (
	// DefaultCacheSize is the default number of items the cache can hold.
	DefaultCacheSize = 10000
	// DefaultShards is the default number of shards for the cache.
	DefaultShards = 32

	// SlruProbationFraction is the fraction of the cache size allocated to the probation segment.
	SlruProbationFraction = 0.8
)