use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::path::Path;
use std::fs;
use crate::metrics::Metrics;
use moka::sync::Cache as MokaCache;
use lmdb::{Cursor, Database, Environment, Transaction, WriteFlags};
use lmdb::DatabaseFlags;
use serde::{Deserialize, Serialize};
use bincode;

#[derive(Serialize, Deserialize, Clone)]
struct FixedSizeCacheItem {
    expiration_unix: i64,
    swr_nanos: i64,
    msg_bytes: Vec<u8>,
    original_ttl_secs: u32,
}

#[derive(Clone)]
struct FastCacheItem {
    msg_bytes: Arc<Vec<u8>>,
    expiration: SystemTime,
    swr: Duration,
    hits: Arc<AtomicU64>,
    original_ttl: Duration,
}

#[derive(Debug, PartialEq)]
pub enum CacheStatus {
    Hit,
    Miss,
    Stale, // Serve old, but revalidate
    Prefetch, // Serve fresh, but start bg refresh
}

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Cache {
    // Sharded in-memory cache
    shards: Vec<MokaCache<String, FastCacheItem>>,
    env: Option<Arc<Environment>>,
    db: Option<Database>,
    metrics: Arc<Metrics>,
    _write_tx: async_channel::Sender<(String, FixedSizeCacheItem)>,
}

const SHARD_COUNT: usize = 16; // Power of 2 for easy distribution

impl Cache {
    pub fn new(size: usize, lmdb_path: &str, metrics: Arc<Metrics>) -> anyhow::Result<Self> {
        // Moka cache with high concurrency
        let total_size = if size == 0 { 5000 } else { size as u64 };
        let shard_size = total_size / (SHARD_COUNT as u64); // Distribute capacity
        
        let mut shards = Vec::with_capacity(SHARD_COUNT);

        for _ in 0..SHARD_COUNT {
             let shard = MokaCache::builder()
                .max_capacity(shard_size.max(100)) // Ensure at least some capacity
                .build();
             shards.push(shard);
        }

        // LMDB setup
        let path = Path::new(lmdb_path);
        if !path.exists() {
            fs::create_dir_all(path)?;
        }

        let env = Environment::new()
            .set_max_dbs(1)
            .set_map_size(1024 * 1024 * 1024) // 1GB
            .open(path)?;

        let env_arc = Arc::new(env);

        let db = env_arc.create_db(Some("cache"), DatabaseFlags::empty())?;

        // Write channel for background persistence
        let (tx, rx) = async_channel::bounded(2048);

        let cache = Cache {
            shards,
            env: Some(env_arc.clone()),
            db: Some(db),
            metrics: metrics.clone(),
            _write_tx: tx,
        };

        // Load from DB
        if let Err(e) = cache.load_from_db() {
             if e.to_string().contains("Too many corrupted items") {
                 log::error!("Cache is corrupted ({}). Wiping and starting fresh...", e);
                 // Drop everything to close environments
                 drop(cache);
                 drop(env_arc);
                 // db is dropped when cache is dropped (it was moved into cache)
                 
                 // Remove directory
                 let _ = fs::remove_dir_all(lmdb_path);
                 
                 // Recursively try again (once)
                 return Cache::new(size, lmdb_path, metrics);
             } else {
                 return Err(e);
             }
        }

        // Start writer
        let env_clone = cache.env.as_ref().unwrap().clone();
        let db_clone = cache.db.unwrap();
        let metrics_clone = metrics.clone();

        // Spawn background writer task
        // BATched Persistence Implementation
        tokio::spawn(async move {
            let mut batch = Vec::with_capacity(100);
            let mut interval = tokio::time::interval(Duration::from_secs(1));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            flush_batch(&env_clone, db_clone, &batch, &metrics_clone);
                            batch.clear();
                        }
                    },
                    res = rx.recv() => {
                         match res {
                             Ok((key, item)) => {
                                 batch.push((key, item));
                                 if batch.len() >= 100 {
                                     flush_batch(&env_clone, db_clone, &batch, &metrics_clone);
                                     batch.clear();
                                 }
                             }
                             Err(_) => break, // Channel closed
                         }
                    }
                }
            }
        });

        Ok(cache)
    }

    fn get_shard(&self, key: &str) -> &MokaCache<String, FastCacheItem> {
        // Consistent Hashing (simplified for local shards)
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish();
        // Use wrapping logic or simple modulo
        let index = (hash as usize) % SHARD_COUNT;
        &self.shards[index]
    }

    fn load_from_db(&self) -> anyhow::Result<()> {
        let env = self.env.as_ref().unwrap();
        let db = self.db.unwrap();
        let txn = env.begin_ro_txn()?;
        let mut cursor = txn.open_ro_cursor(db)?;

        let mut corrupted_count = 0;
        let mut total_count = 0;

        for item in cursor.iter() {
             total_count += 1;
             let (key_bytes, val_bytes) = match item {
                 Ok(x) => x,
                 Err(e) => {
                     log::error!("LMDB cursor iteration error: {}", e);
                     corrupted_count += 1;
                     continue;
                 }
             };
             let key = String::from_utf8_lossy(key_bytes).to_string();
             match bincode::deserialize::<FixedSizeCacheItem>(val_bytes) {
                 Ok(item) => {
                    let expiration = UNIX_EPOCH + Duration::from_secs(item.expiration_unix as u64);
                    if SystemTime::now() > expiration {
                        continue;
                    }

                    let swr = Duration::from_nanos(item.swr_nanos as u64);

                    // Populate in-memory cache (routed to correct shard)
                    self.get_shard(&key).insert(key, FastCacheItem {
                        msg_bytes: Arc::new(item.msg_bytes),
                        expiration,
                        swr,
                        hits: Arc::new(AtomicU64::new(1)), // Reset hits on reload
                        original_ttl: Duration::from_secs(item.original_ttl_secs as u64),
                    });
                    self.metrics.increment_lmdb_cache_loads();
                 },
                 Err(e) => {
                     log::error!("Failed to unpack cache item for key {}: {}", key, e);
                     self.metrics.increment_lmdb_errors();
                     corrupted_count += 1;
                 }
             }
        }
        
        // If more than 10% or 100 items are corrupted, consider the DB broken
        if corrupted_count > 0 && (corrupted_count > 100 || (total_count > 0 && corrupted_count * 10 > total_count)) {
            return Err(anyhow::anyhow!("Too many corrupted items in cache"));
        }

        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<(Arc<Vec<u8>>, CacheStatus)> {
        let shard = self.get_shard(key);
        if let Some(item) = shard.get(key) {
             let now = SystemTime::now();
             
             // Increment hits
             let hits = item.hits.fetch_add(1, Ordering::Relaxed);
             
             if now > item.expiration {
                 // Check Serve-Stale (SWR)
                 let serve_stale = if item.swr > Duration::ZERO {
                      now < item.expiration + item.swr
                 } else {
                     false
                 };

                 if !serve_stale {
                     shard.remove(key);
                     self.metrics.increment_cache_misses();
                     return None;
                 }

                 // Return stale data but signal revalidation
                 self.metrics.increment_cache_hits();
                 return Some((item.msg_bytes.clone(), CacheStatus::Stale));
             }

             // Check Prefetch: Intelligent (10% remaining)
             if let Ok(remaining) = item.expiration.duration_since(now) {
                 // Precalculate 10% of original
                 let prefetch_threshold = item.original_ttl.as_secs_f64() * 0.1;
                 let remaining_secs = remaining.as_secs_f64();

                 // Heuristic: if remaining < 10% AND (hits > 2 OR original TTL was very short)
                 if remaining_secs < prefetch_threshold {
                      // Only trigger if we have seen some traffic, or it is about to expire anyway
                      if hits > 2 {
                          self.metrics.increment_cache_hits();
                          return Some((item.msg_bytes.clone(), CacheStatus::Prefetch));
                      }
                 }
             }

             self.metrics.increment_cache_hits();
             return Some((item.msg_bytes.clone(), CacheStatus::Hit));
        }

        self.metrics.increment_cache_misses();
        None
    }

    pub fn set(&self, key: &str, msg_bytes: Vec<u8>, ttl: Duration, swr: Duration) {
        let expiration = SystemTime::now() + ttl;
        
        let shard = self.get_shard(key);
        // Store as Arc to avoid cloning on get
        let msg_arc = Arc::new(msg_bytes.clone());

        shard.insert(key.to_string(), FastCacheItem {
            msg_bytes: msg_arc,
            expiration,
            swr,
            hits: Arc::new(AtomicU64::new(1)),
            original_ttl: ttl,
        });

        // Persist to LMDB
        let persistent_item = FixedSizeCacheItem {
            expiration_unix: expiration.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
            swr_nanos: swr.as_nanos() as i64,
            msg_bytes,
            original_ttl_secs: ttl.as_secs() as u32,
        };

        // Non-blocking send
        if let Err(_) = self._write_tx.try_send((key.to_string(), persistent_item)) {
            // Channel full, drop persistence to favor availability
            self.metrics.increment_lmdb_errors(); // or "dropped_writes"
        }
    }
}

fn flush_batch(env: &Environment, db: Database, batch: &[(String, FixedSizeCacheItem)], metrics: &Metrics) {
    let mut txn = match env.begin_rw_txn() {
        Ok(t) => t,
        Err(e) => {
            log::error!("Failed to create LMDB write txn: {}", e);
            metrics.increment_lmdb_errors();
            return;
        }
    };

    let mut count = 0;
    for (key, item) in batch {
         if let Ok(encoded) = bincode::serialize(item) {
             if let Err(e) = txn.put(db, key, &encoded, WriteFlags::empty()) {
                 log::error!("Failed to write to LMDB for key {}: {}", key, e);
                 metrics.increment_lmdb_errors();
             } else {
                 count += 1;
             }
         }
    }

    if count > 0 {
        if let Err(e) = txn.commit() {
             log::error!("Failed to commit LMDB batch: {}", e);
             metrics.increment_lmdb_errors();
        }
    }
}
