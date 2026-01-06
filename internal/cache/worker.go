package cache

import (
	"log"

	bolt "go.etcd.io/bbolt"
)

func (c *Cache) persistWorker() {
	defer c.wg.Done()

	// Batch writes for better performance with BoltDB
	// Bolt is transactional, so we can group updates if we wanted,
	// but here we process one by one or small batches.
	// Given we have a channel, we can read chunks.

	// Simple implementation: process one by one.
	// Optimally we'd read up to N items or wait T time to do a batch Update.

	for item := range c.persistCh {
		packedData, err := item.Pack()
		if err != nil {
			log.Printf("Failed to pack cache item for key %s: %v", item.Key, err)
			continue
		}

		err = c.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(BoltBucketName))
			return b.Put([]byte(item.Key), packedData)
		})

		if err != nil {
			c.metrics.IncrementLMDBErrors()
			log.Printf("Failed to write to BoltDB for key %s: %v", item.Key, err)
		}
	}
}
