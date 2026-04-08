//! Shared cache for DNS responses
//!
//! The cache is currently shared across all threads, and maps
//! `NormalizedQuestionKey` keys to DNS responses in wire format.
//!
//! DNS responses are stored as originally received from upstream servers,
//! and need to be modified to fit the original format of client queries
//! before being actually sent to clients.
//!
//! The cache current uses the CLOCK-Pro algorithm, but can be trivially
//! replaced with the `arc-cache` or `cart-cache` crates that expose a
//! similar API (but might be subject to patents).
//!
//! With a typical workload, it is expected that the vast majority of cached
//! responses end up in the `frequent` section of the cache.
//! The `test` and `recent` section act as a security valve when a spike of
//! previously unknown queries is observed.

use crate::config::Config;
use crate::dns;
use crate::dns::{NormalizedQuestion, NormalizedQuestionKey, DNS_CLASS_IN, DNS_RCODE_NXDOMAIN};
use caches::{AdaptiveCache, Cache as _};
use coarsetime::{Duration, Instant};
use log::error;
use parking_lot::Mutex;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io;
use std::sync::Arc;
use std::thread;

const CACHE_SHARD_MIN: usize = 4;
const CACHE_SHARD_MAX: usize = 64;

#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub expiration: Instant,
    pub packet: Vec<u8>,
}

impl CacheEntry {
    #[inline]
    pub fn is_expired(&self) -> bool {
        let now = Instant::recent();
        now > self.expiration
    }

    #[inline]
    pub fn is_servable_stale(&self, stale_ttl_seconds: u32) -> bool {
        let now = Instant::recent();
        now <= self.expiration + Duration::from_secs(stale_ttl_seconds as u64)
    }
}

#[derive(Clone)]
pub struct Cache {
    config: Config,
    shards: Arc<Vec<Mutex<AdaptiveCache<NormalizedQuestionKey, CacheEntry>>>>,
}

pub struct CacheStats {
    pub frequent_len: usize,
    pub recent_len: usize,
    pub test_len: usize,
    pub inserted: u64,
    pub evicted: u64,
}

impl Cache {
    #[inline]
    pub fn new(config: Config) -> io::Result<Cache> {
        let shard_count = shard_count_for_capacity(config.cache_size);
        let mut shards = Vec::with_capacity(shard_count);
        for shard_index in 0..shard_count {
            let shard_capacity = shard_capacity(config.cache_size, shard_count, shard_index);
            let shard = AdaptiveCache::new(shard_capacity)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
            shards.push(Mutex::new(shard));
        }
        Ok(Cache {
            config,
            shards: Arc::new(shards),
        })
    }

    #[inline]
    pub fn stats(&self) -> CacheStats {
        let mut stats = CacheStats {
            frequent_len: 0,
            recent_len: 0,
            test_len: 0,
            inserted: 0,
            evicted: 0,
        };
        for shard in self.shards.iter() {
            let cache = shard.lock();
            // AdaptiveCache doesn't expose frequent/recent/test len directly like ClockProCache did
            // We can approximate or just report total len if needed.
            stats.frequent_len += cache.len();
            // stats.inserted += cache.inserted();
            // stats.evicted += cache.evicted();
        }
        stats
    }

    #[inline]
    pub fn insert(
        &self,
        normalized_question_key: NormalizedQuestionKey,
        packet: Vec<u8>,
        ttl: u32,
    ) -> bool {
        debug_assert!(packet.len() >= dns::DNS_HEADER_SIZE);
        if packet.len() < dns::DNS_HEADER_SIZE {
            return false;
        }
        let now = Instant::recent();
        let duration = Duration::from_secs(ttl as u64);
        let expiration = now + duration;
        let cache_entry = CacheEntry { expiration, packet };
        let mut cache = self.shard_for_key(&normalized_question_key).lock();
        cache.put(normalized_question_key, cache_entry);
        true
    }

    #[inline]
    pub fn get(&self, normalized_question_key: &NormalizedQuestionKey) -> Option<CacheEntry> {
        let mut cache = self.shard_for_key(normalized_question_key).lock();
        cache.get(normalized_question_key).cloned()
    }

    /// get2() does a couple things before checking that a key is present in the cache.
    ///
    /// It handles special queries (responses to `ANY` queries and `CHAOS TXT`) as if they
    /// were cached, although they obviously don't need to actually use the cache.
    /// It also rejects queries that are not in the `IN` class, that we probably never
    /// want to cache.
    ///
    /// It then checks if a cached response is present and still valid.
    /// If `x.example.com` is not present, but `example.com` is cached with an `NXDOMAIN`
    /// response code, we assume that `x.example.com` doesn't exist either (RFC 8020).
    ///
    /// We are not checking additional cache entries for now. Both to be minimize
    /// possible incompatibilities with RFC 8020, and for speed.
    /// This might be revisited later.
    pub fn get2(&self, normalized_question: &NormalizedQuestion) -> Option<CacheEntry> {
        if let Some(special_packet) = self.handle_special_queries(normalized_question) {
            Some(CacheEntry {
                expiration: Instant::recent() + Duration::from_secs(self.config.max_ttl as u64),
                packet: special_packet,
            })
        } else if normalized_question.qclass != DNS_CLASS_IN {
            match dns::build_refused_packet(normalized_question) {
                Ok(packet) => Some(CacheEntry {
                    expiration: Instant::recent() + Duration::from_secs(self.config.max_ttl as u64),
                    packet,
                }),
                Err(err) => {
                    error!("Failed to build REFUSED packet: {}", err);
                    None
                }
            }
        } else {
            let normalized_question_key = normalized_question.key();
            let cache_entry = self.get(&normalized_question_key);
            if let Some(mut cache_entry) = cache_entry {
                if self.config.decrement_ttl {
                    let now = Instant::recent();
                    if now <= cache_entry.expiration {
                        let remaining_ttl = cache_entry.expiration.duration_since(now).as_secs();
                        let _ = dns::set_ttl(&mut cache_entry.packet, remaining_ttl as u32);
                    }
                }
                return Some(cache_entry);
            }
            if !normalized_question_key.dnssec {
                let qname = normalized_question_key.qname_lc;
                if let Some(qname_shifted) = dns::qname_shift(&qname) {
                    let mut normalized_question_key = normalized_question.key();
                    normalized_question_key.qname_lc = qname_shifted.to_owned();
                    let shifted_cache_entry = self.get(&normalized_question_key);
                    if let Some(shifted_cache_entry) = shifted_cache_entry {
                        debug!("Shifted query cached");
                        let shifted_packet = shifted_cache_entry.packet;
                        if shifted_packet.len() >= dns::DNS_HEADER_SIZE
                            && dns::rcode(&shifted_packet) == DNS_RCODE_NXDOMAIN
                        {
                            debug!("Shifted query returned NXDOMAIN");
                            match dns::build_nxdomain_packet(normalized_question) {
                                Ok(packet) => {
                                    return Some(CacheEntry {
                                        expiration: shifted_cache_entry.expiration,
                                        packet,
                                    });
                                }
                                Err(err) => {
                                    error!("Failed to build NXDOMAIN packet: {}", err);
                                    return None;
                                }
                            }
                        }
                    }
                }
            }
            None
        }
    }

    fn handle_special_queries(&self, normalized_question: &NormalizedQuestion) -> Option<Vec<u8>> {
        if normalized_question.qclass == dns::DNS_CLASS_IN
            && normalized_question.qtype == dns::DNS_TYPE_ANY
        {
            debug!("ANY query");
            match dns::build_any_packet(normalized_question, self.config.max_ttl) {
                Ok(packet) => Some(packet),
                Err(err) => {
                    error!("Failed to build ANY packet: {}", err);
                    None
                }
            }
        } else if normalized_question.qclass == dns::DNS_CLASS_CH
            && normalized_question.qtype == dns::DNS_TYPE_TXT
        {
            debug!("CHAOS TXT");
            match dns::build_version_packet(normalized_question, self.config.max_ttl) {
                Ok(packet) => Some(packet),
                Err(err) => {
                    error!("Failed to build VERSION packet: {}", err);
                    None
                }
            }
        } else {
            None
        }
    }

    #[inline]
    fn shard_for_key(
        &self,
        normalized_question_key: &NormalizedQuestionKey,
    ) -> &Mutex<AdaptiveCache<NormalizedQuestionKey, CacheEntry>> {
        let shard_index = shard_index(normalized_question_key, self.shards.len());
        &self.shards[shard_index]
    }
}

fn shard_count_for_capacity(cache_size: usize) -> usize {
    let available_parallelism = thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(4);
    let desired = (available_parallelism * 4).clamp(CACHE_SHARD_MIN, CACHE_SHARD_MAX);
    desired.min(cache_size.max(1))
}

fn shard_capacity(total_capacity: usize, shard_count: usize, shard_index: usize) -> usize {
    let base = total_capacity / shard_count;
    let remainder = total_capacity % shard_count;
    let capacity = if shard_index < remainder {
        base + 1
    } else {
        base
    };
    capacity.max(1)
}

fn shard_index(normalized_question_key: &NormalizedQuestionKey, shard_count: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    normalized_question_key.hash(&mut hasher);
    (hasher.finish() as usize) % shard_count
}
