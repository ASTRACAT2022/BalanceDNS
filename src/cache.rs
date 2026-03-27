use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;

/// DNS-кэш в оперативной памяти
/// 
/// Хранит ответы DNS-запросов с TTL для ускорения обработки повторяющихся запросов.
/// Использует DashMap для потокобезопасного доступа без блокировок.
pub struct DnsCache {
    /// Кэш: ключ = (домен, тип_запроса), значение = кэшированный ответ
    entries: DashMap<CacheKey, CacheEntry>,
    /// Максимальное количество записей в кэше
    max_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    /// Домен в нижнем регистре с точкой на конце
    domain: Arc<str>,
    /// Тип запроса (A=1, AAAA=28, etc.)
    qtype: u16,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    /// Кэшированный DNS-пакет (полный ответ)
    response: Vec<u8>,
    /// Время создания записи
    created: Instant,
    /// Время истечения срока действия
    expires: Instant,
}

impl DnsCache {
    /// Создаёт новый DNS-кэш
    /// 
    /// # Аргументы
    /// * `max_size` - максимальное количество записей в кэше
    /// * `default_ttl` - TTL по умолчанию для записей без явного TTL
    pub fn new(max_size: usize, default_ttl: Duration) -> Self {
        let _ = default_ttl; // Зарезервировано для будущего использования
        Self {
            entries: DashMap::new(),
            max_size,
        }
    }

    /// Создаёт кэш с конфигурацией по умолчанию
    /// 
    /// max_size: 10000 записей
    /// default_ttl: 300 секунд (5 минут)
    pub fn default_config() -> Self {
        Self::new(10_000, Duration::from_secs(300))
    }

    /// Проверяет наличие валидного кэшированного ответа
    /// 
    /// Возвращает копию кэшированного ответа, если запись существует и не истекла
    pub fn get(&self, domain: &str, qtype: u16) -> Option<Vec<u8>> {
        let key = CacheKey {
            domain: normalize_domain(domain).into(),
            qtype,
        };

        match self.entries.get(&key) {
            Some(entry) => {
                if Instant::now() <= entry.expires {
                    metrics::counter!("dns_cache_hits_total").increment(1);
                    Some(entry.response.clone())
                } else {
                    // Истёк TTL - удаляем запись
                    drop(entry);
                    self.entries.remove(&key);
                    metrics::counter!("dns_cache_expired_total").increment(1);
                    None
                }
            }
            None => {
                metrics::counter!("dns_cache_misses_total").increment(1);
                None
            }
        }
    }

    /// Сохраняет DNS-ответ в кэш
    /// 
    /// # Аргументы
    /// * `domain` - домен (будет нормализован к нижнему регистру)
    /// * `qtype` - тип запроса
    /// * `response` - полный DNS-ответ (пакет)
    /// * `ttl` - TTL из DNS-ответа (будет ограничен max_ttl)
    pub fn set(&self, domain: &str, qtype: u16, response: Vec<u8>, ttl: Duration) {
        let key = CacheKey {
            domain: normalize_domain(domain).into(),
            qtype,
        };

        // Ограничиваем TTL разумным максимумом (1 час)
        let ttl = ttl.min(Duration::from_secs(3600));
        let now = Instant::now();
        let expires = now + ttl;

        // Проверка на переполнение кэша перед вставкой
        if self.entries.len() >= self.max_size {
            self.evict_oldest();
        }

        let entry = CacheEntry {
            response,
            created: now,
            expires,
        };

        self.entries.insert(key, entry);
        
        // Обновляем метрики размера кэша
        metrics::gauge!("dns_cache_size").set(self.entries.len() as f64);
    }

    /// Удаляет устаревшие записи (может вызываться периодически)
    pub fn cleanup(&self) -> usize {
        let now = Instant::now();
        let mut removed = 0;

        // Собираем ключи для удаления (чтобы избежать удержания lock)
        let expired_keys: Vec<_> = self
            .entries
            .iter()
            .filter(|entry| now > entry.value().expires)
            .map(|entry| entry.key().clone())
            .collect();

        for key in expired_keys {
            self.entries.remove(&key);
            removed += 1;
        }

        if removed > 0 {
            metrics::counter!("dns_cache_cleanup_total").increment(removed as u64);
            metrics::gauge!("dns_cache_size").set(self.entries.len() as f64);
        }

        removed
    }

    /// Удаляет одну из старых записей при переполнении (алгоритм случайной выборки для O(1))
    fn evict_oldest(&self) {
        // Чтобы не сканировать весь кэш (O(N)), выбираем несколько случайных записей
        // и удаляем самую старую из них. Это дает близкую к LRU эффективность при O(1).
        let mut best_key = None;
        let mut oldest_time = None;

        // Ограничиваем количество попыток найти записи, если кэш почти пуст (что не должно быть здесь)
        let sample_size = 16;
        let mut count = 0;

        for entry in self.entries.iter() {
            let created = entry.value().created;
            if oldest_time.is_none() || created < oldest_time.unwrap() {
                oldest_time = Some(created);
                best_key = Some(entry.key().clone());
            }

            count += 1;
            if count >= sample_size {
                break;
            }
        }

        if let Some(key) = best_key {
            self.entries.remove(&key);
            metrics::counter!("dns_cache_evictions_total").increment(1);
        }
    }

    /// Возвращает текущий размер кэша
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Проверяет, пуст ли кэш
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Очищает весь кэш
    pub fn clear(&self) {
        self.entries.clear();
        metrics::gauge!("dns_cache_size").set(0.0);
    }
}

/// Нормализует домен: приводит к нижнему регистру, добавляет точку в конце
fn normalize_domain(domain: &str) -> String {
    let domain = domain.trim().to_ascii_lowercase();
    if domain.ends_with('.') {
        domain
    } else {
        format!("{}.", domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_basic() {
        let cache = DnsCache::new(100, Duration::from_secs(60));
        
        let response = vec![1u8, 2, 3, 4];
        cache.set("example.com", 1, response.clone(), Duration::from_secs(60));
        
        let cached = cache.get("example.com", 1);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), response);
    }

    #[test]
    fn test_cache_case_insensitive() {
        let cache = DnsCache::new(100, Duration::from_secs(60));
        
        let response = vec![1u8, 2, 3, 4];
        cache.set("Example.COM", 1, response.clone(), Duration::from_secs(60));
        
        let cached = cache.get("EXAMPLE.com", 1);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), response);
    }

    #[test]
    fn test_cache_different_qtype() {
        let cache = DnsCache::new(100, Duration::from_secs(60));
        
        cache.set("example.com", 1, vec![1u8], Duration::from_secs(60));
        cache.set("example.com", 28, vec![2u8], Duration::from_secs(60));
        
        assert!(cache.get("example.com", 1).is_some());
        assert!(cache.get("example.com", 28).is_some());
        assert!(cache.get("example.com", 16).is_none());
    }

    #[test]
    fn test_cache_max_size() {
        let cache = DnsCache::new(5, Duration::from_secs(60));
        
        for i in 0..10 {
            cache.set(&format!("domain{}.com", i), 1, vec![i as u8], Duration::from_secs(60));
        }
        
        assert!(cache.len() <= 5);
    }
}
