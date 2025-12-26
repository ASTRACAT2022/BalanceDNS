use std::sync::Arc;
use dashmap::DashMap;
use governor::{Quota, RateLimiter};
use governor::state::keyed::{KeyedStateStore, DefaultKeyedStateStore}; // Correct import for keyed state
use governor::state::InMemoryState; // If needed, or remove if unused
use governor::clock::DefaultClock;
use std::num::NonZeroU32;
// use std::time::Duration; // Unused
use log::{info, warn};

pub struct Protection {
    // Rate limiter keyed by IP address string
    limiter: Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>,
    // Dynamic blocklist (IP -> manual block or automatic ban)
    blocklist: DashMap<String, bool>,
    enabled: bool,
}

impl Protection {
    pub fn new(enabled: bool, qps: u32, burst: u32) -> Self {
        let qps = if qps == 0 { 100 } else { qps };
        let burst = if burst == 0 { 100 } else { burst };

        let quota = Quota::per_second(NonZeroU32::new(qps).unwrap())
            .allow_burst(NonZeroU32::new(burst).unwrap());

        let limiter = Arc::new(RateLimiter::keyed(quota));

        Protection {
            limiter,
            blocklist: DashMap::new(),
            enabled,
        }
    }

    pub fn allow_request(&self, ip: &str) -> bool {
        if !self.enabled {
            return true;
        }

        // 1. Check Blocklist
        if let Some(_) = self.blocklist.get(ip) {
            return false;
        }

        // 2. Check Rate Limit
        if let Err(_) = self.limiter.check_key(&ip.to_string()) {
            warn!("Rate limit exceeded for IP: {}", ip);
            // Optional: Auto-ban if rate limit exceeded too often?
            // For now just drop.
            return false;
        }

        true
    }

    pub fn ban_ip(&self, ip: &str) {
        info!("Banning IP: {}", ip);
        self.blocklist.insert(ip.to_string(), true);
    }
    
    pub fn unban_ip(&self, ip: &str) {
        info!("Unbanning IP: {}", ip);
        self.blocklist.remove(ip);
    }
}
