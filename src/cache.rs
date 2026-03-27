use std::{
    sync::Arc,
};

use clockpro_cache::ClockProCache;
use coarsetime::{Duration, Instant};
use parking_lot::Mutex;

/// DNS-кэш на базе алгоритма CLOCK-Pro
pub struct DnsCache {
    /// Кэш: ключ = (домен_в_нжнем_регистре, тип_запроса), значение = кэшированный ответ
    cache: Mutex<ClockProCache<CacheKey, CacheEntry>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    /// Домен в нижнем регистре (бинарное представление для скорости)
    domain: Arc<[u8]>,
    /// Тип запроса
    qtype: u16,
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Кэшированный DNS-пакет
    pub response: Vec<u8>,
    /// Время истечения срока действия
    pub expires: Instant,
}

impl DnsCache {
    /// Создаёт новый DNS-кэш
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Mutex::new(ClockProCache::new(max_size).expect("failed to create cache")),
        }
    }

    /// Проверяет наличие валидного кэшированного ответа
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
                // Истёк TTL - удаляем запись (в ClockProCache get_mut перемещает запись, но мы не можем легко удалить её отсюда если она и стекла без remove)
                // На самом деле ClockProCache не имеет явного метода удаления по ключу кроме вытеснения,
                // но мы можем просто игнорировать и она со временем вытеснится, или перезаписать её.
                // В edgedns они просто возвращают None если истёк.
                metrics::counter!("dns_cache_expired_total").increment(1);
            }
        } else {
            metrics::counter!("dns_cache_misses_total").increment(1);
        }
        None
    }

    /// Сохраняет DNS-ответ в кэш
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
        
        // Обновляем метрики
        metrics::gauge!("dns_cache_size").set((cache.frequent_len() + cache.recent_len() + cache.test_len()) as f64);
    }

    pub fn len(&self) -> usize {
        let cache = self.cache.lock();
        cache.frequent_len() + cache.recent_len() + cache.test_len()
    }
}

/// Нормализует домен к нижнему регистру (бинарно)
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
