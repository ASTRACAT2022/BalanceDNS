use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::path::Path;
use std::fs;
use crate::metrics::Metrics;
use lru::LruCache;
use std::num::NonZeroUsize;
use lmdb::{Cursor, Database, Environment, EnvironmentBuilder, RwTransaction, Transaction, WriteFlags};
use lmdb::DatabaseFlags;
use serde::{Deserialize, Serialize};
use bincode;

const DEFAULT_CACHE_SIZE: usize = 5000;
const DEFAULT_SHARDS: usize = 8;

#[derive(Serialize, Deserialize, Clone)]
struct FixedSizeCacheItem {
    expiration_unix: i64,
    swr_nanos: i64,
    msg_bytes: Vec<u8>,
}

struct FastCacheShard {
    lru: LruCache<String, FastCacheItem>,
}

#[derive(Clone)]
struct FastCacheItem {
    msg_bytes: Vec<u8>,
    expiration: SystemTime,
    swr: Duration,
}

pub struct Cache {
    shards: Vec<Mutex<FastCacheShard>>,
    env: Option<Arc<Environment>>,
    db: Option<Database>,
    metrics: Arc<Metrics>,
    write_tx: async_channel::Sender<(String, FixedSizeCacheItem)>,
}

impl Cache {
    pub fn new(size: usize, lmdb_path: &str, metrics: Arc<Metrics>) -> anyhow::Result<Self> {
        let size = if size == 0 { DEFAULT_CACHE_SIZE } else { size };
        let num_shards = DEFAULT_SHARDS;
        let shard_capacity = size / num_shards;

        let mut shards = Vec::with_capacity(num_shards);
        for _ in 0..num_shards {
            shards.push(Mutex::new(FastCacheShard {
                lru: LruCache::new(NonZeroUsize::new(shard_capacity).unwrap()),
            }));
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
        let (tx, rx) = async_channel::bounded(1024);

        let cache = Cache {
            shards,
            env: Some(env_arc.clone()),
            db: Some(db),
            metrics: metrics.clone(),
            write_tx: tx,
        };

        // Load from DB
        cache.load_from_db()?;

        // Start writer
        let env_clone = env_arc.clone();
        let db_clone = db;
        let metrics_clone = metrics.clone();

        // Spawn background writer task
        tokio::spawn(async move {
            while let Ok((key, item)) = rx.recv().await {
                if let Ok(encoded) = bincode::serialize(&item) {
                    // Attempt to create write transaction.
                    // Note: LMDB only allows one write txn at a time.
                    // If we used a long-lived txn it would block.
                    // Here we do one small txn per item or batch.
                    // For simplicity, one per item.
                    let mut txn = match env_clone.begin_rw_txn() {
                        Ok(t) => t,
                        Err(e) => {
                            log::error!("Failed to create LMDB write txn: {}", e);
                            metrics_clone.increment_lmdb_errors();
                            continue;
                        }
                    };

                    if let Err(e) = txn.put(db_clone, &key, &encoded, WriteFlags::empty()) {
                        log::error!("Failed to write to LMDB for key {}: {}", key, e);
                        metrics_clone.increment_lmdb_errors();
                    }
                    if let Err(e) = txn.commit() {
                         log::error!("Failed to commit LMDB txn for key {}: {}", key, e);
                         metrics_clone.increment_lmdb_errors();
                    }
                }
            }
        });

        Ok(cache)
    }

    fn load_from_db(&self) -> anyhow::Result<()> {
        let env = self.env.as_ref().unwrap();
        let db = self.db.unwrap();
        let txn = env.begin_ro_txn()?;
        let mut cursor = txn.open_ro_cursor(db)?;

        for item in cursor.iter() {
             let (key_bytes, val_bytes) = match item {
                 Ok(x) => x,
                 Err(e) => {
                     log::error!("LMDB cursor iteration error: {}", e);
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

                    // Populate in-memory cache
                    let shard_idx = self.get_shard_idx(&key);
                    let mut shard = self.shards[shard_idx].lock().unwrap();
                    shard.lru.put(key, FastCacheItem {
                        msg_bytes: item.msg_bytes,
                        expiration,
                        swr,
                    });
                    self.metrics.increment_lmdb_cache_loads();
                 },
                 Err(e) => {
                     log::error!("Failed to unpack cache item for key {}: {}", key, e);
                     self.metrics.increment_lmdb_errors();
                 }
             }
        }
        Ok(())
    }

    fn get_shard_idx(&self, key: &str) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(key, &mut hasher);
        (std::hash::Hasher::finish(&hasher) as usize) % self.shards.len()
    }

    pub fn get(&self, key: &str) -> Option<(Vec<u8>, bool)> {
        let shard_idx = self.get_shard_idx(key);
        let mut shard = self.shards[shard_idx].lock().unwrap();

        if let Some(item) = shard.lru.get(key) {
             let now = SystemTime::now();
             if now > item.expiration {
                 let revalidate = if item.swr > Duration::ZERO {
                      now < item.expiration + item.swr
                 } else {
                     false
                 };

                 if !revalidate {
                     shard.lru.pop(key);
                     self.metrics.increment_cache_misses();
                     return None;
                 }

                 // Return stale data but signal revalidation
                 self.metrics.increment_cache_hits();
                 return Some((item.msg_bytes.clone(), true));
             }

             self.metrics.increment_cache_hits();
             return Some((item.msg_bytes.clone(), false));
        }

        self.metrics.increment_cache_misses();
        None
    }

    pub fn set(&self, key: &str, msg_bytes: Vec<u8>, ttl: Duration, swr: Duration) {
        let expiration = SystemTime::now() + ttl;
        let shard_idx = self.get_shard_idx(key);

        {
            let mut shard = self.shards[shard_idx].lock().unwrap();
            shard.lru.put(key.to_string(), FastCacheItem {
                msg_bytes: msg_bytes.clone(),
                expiration,
                swr,
            });
        }

        // Persist to LMDB
        let persistent_item = FixedSizeCacheItem {
            expiration_unix: expiration.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
            swr_nanos: swr.as_nanos() as i64,
            msg_bytes,
        };

        let _ = self.write_tx.send_blocking((key.to_string(), persistent_item));
    }
}
