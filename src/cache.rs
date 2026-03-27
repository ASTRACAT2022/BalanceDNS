use std::{
    sync::Arc,
};

use clockpro_cache::ClockProCache;
use coarsetime::{Duration, Instant};
use parking_lot::Mutex;

/// DNS cache based on CLOCK-Pro algorithm
pub struct DnsCache {
    /// Cache: key = (domain_lowercase, qtype), value = cached response
    cache: Mutex<ClockProCache<CacheKey, CacheEntry>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    /// Lowercase domain (binary representation for speed)
    domain: Arc<[u8]>,
    /// Query type
    qtype: u16,
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Cached DNS packet
    pub response: Vec<u8>,
    /// Expiration instant
    pub expires: Instant,
}

impl DnsCache {
    /// Creates a new DNS cache
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Mutex::new(ClockProCache::new(max_size).expect("failed to create cache")),
        }
    }

    /// Checks for a valid cached response
    pub fn get(&self, domain: &str, qtype: u16) -> Option<Vec<u8>> {
        let key = CacheKey {
            domain: normalize_domain_bytes(domain).into(),
            qtype,
        };

        let mut cache = self.cache.lock();
        if let Some(entry) = cache.get_mut(&key) {
            if Instant::recent() <= entry.expires {
                metrics::counter!("dns_cache_hits_total").increment(1);
                return Some(entry.response.clone());
            } else {
                // TTL expired. ClockProCache doesn't have a direct remove by key,
                // but we can just ignore it and it will eventually be evicted.
                metrics::counter!("dns_cache_expired_total").increment(1);
            }
        } else {
            metrics::counter!("dns_cache_misses_total").increment(1);
        }
        None
    }

    /// Saves a DNS response to the cache
    pub fn set(&self, domain: &str, qtype: u16, response: Vec<u8>, ttl: std::time::Duration) {
        let key = CacheKey {
            domain: normalize_domain_bytes(domain).into(),
            qtype,
        };

        let expires = Instant::recent() + Duration::from(ttl);

        let entry = CacheEntry {
            response,
            expires,
        };

        let mut cache = self.cache.lock();
        cache.insert(key, entry);
        
        // Update metrics
        metrics::gauge!("dns_cache_size").set((cache.frequent_len() + cache.recent_len() + cache.test_len()) as f64);
    }

    pub fn len(&self) -> usize {
        let cache = self.cache.lock();
        cache.frequent_len() + cache.recent_len() + cache.test_len()
    }
}

/// Normalizes domain to lowercase (binary)
fn normalize_domain_bytes(domain: &str) -> Vec<u8> {
    let mut out = domain.trim().to_ascii_lowercase().into_bytes();
    if !out.ends_with(b".") {
        out.push(b'.');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    #[test]
    fn test_cache_basic() {
        let cache = DnsCache::new(100);
        let _ = coarsetime::Updater::new(10).start();
        
        let response = vec![1u8, 2, 3, 4];
        cache.set("example.com", 1, response.clone(), StdDuration::from_secs(60));
        
        let cached = cache.get("example.com", 1);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), response);
    }
}
