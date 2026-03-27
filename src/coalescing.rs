use std::{
    collections::HashMap,
    sync::Arc,
};

use parking_lot::Mutex;
use tokio::sync::watch;

/// Менеджер объединения идентичных DNS-запросов (Query Coalescing)
pub struct PendingQueries {
    /// Карта активных запросов: ключ -> отправитель результата
    queries: Mutex<HashMap<QueryKey, watch::Receiver<Option<Vec<u8>>>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct QueryKey {
    domain: Arc<str>,
    qtype: u16,
}

pub enum QueryState {
    /// Запрос уже выполняется, нужно ждать результата
    Waiting(watch::Receiver<Option<Vec<u8>>>),
    /// Мы первые, кто делает этот запрос
    New(watch::Sender<Option<Vec<u8>>>),
}

impl PendingQueries {
    pub fn new() -> Self {
        Self {
            queries: Mutex::new(HashMap::new()),
        }
    }

    /// Проверяет, выполняется ли уже такой запрос.
    /// Если да, возвращает ресивер для ожидания.
    /// Если нет, создает новый канал и возвращает сендер.
    pub fn get_or_create(&self, domain: &str, qtype: u16) -> QueryState {
        let key = QueryKey {
            domain: Arc::from(domain),
            qtype,
        };

        let mut queries = self.queries.lock();
        if let Some(rx) = queries.get(&key) {
            return QueryState::Waiting(rx.clone());
        }

        let (tx, rx) = watch::channel(None);
        queries.insert(key, rx);
        QueryState::New(tx)
    }

    /// Удаляет запрос из списка активных (после завершения)
    pub fn remove(&self, domain: &str, qtype: u16) {
        let key = QueryKey {
            domain: Arc::from(domain),
            qtype,
        };
        let mut queries = self.queries.lock();
        queries.remove(&key);
    }
}
