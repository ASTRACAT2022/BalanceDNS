package main

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func newTestMsg(name string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN A 1.2.3.4", name))
	msg.Answer = []dns.RR{rr}
	return msg
}

func BenchmarkCacheSet(b *testing.B) {
	cache := NewShardedCache(32, 10000, 10*time.Minute)
	defer cache.Stop()
	msg := newTestMsg("test.com.")

	// To avoid allocations in the loop, pre-generate keys if possible, though for benchmarks
	// this is often acceptable.
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		key := "test" + strconv.Itoa(i)
		cache.Set(key, msg, 1*time.Minute, true)
	}
}

func BenchmarkCacheGet(b *testing.B) {
	cache := NewShardedCache(32, 10000, 10*time.Minute)
	defer cache.Stop()
	msg := newTestMsg("test.com.")

	for i := 0; i < 1000; i++ {
		key := "test" + strconv.Itoa(i)
		cache.Set(key, msg, 1*time.Minute, true)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		key := "test" + strconv.Itoa(i%1000)
		cache.Get(key)
	}
}

func BenchmarkCacheGetConcurrent(b *testing.B) {
	cache := NewShardedCache(32, 100000, 10*time.Minute)
	defer cache.Stop()
	msg := newTestMsg("test.com.")

	// Pre-fill the cache
	for i := 0; i < 10000; i++ {
		key := fmt.Sprintf("test%d.com.", i)
		cache.Set(key, msg, 1*time.Minute, true)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// The key space should be large enough to avoid heavy contention on a single shard.
			key := fmt.Sprintf("test%d.com.", i%10000)
			cache.Get(key)
			i++
		}
	})
}

func BenchmarkCacheSetConcurrent(b *testing.B) {
	cache := NewShardedCache(32, b.N, 10*time.Minute) // Give enough capacity
	defer cache.Stop()
	msg := newTestMsg("test.com.")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("test%d.com.", i)
			cache.Set(key, msg, 1*time.Minute, true)
			i++
		}
	})
}
