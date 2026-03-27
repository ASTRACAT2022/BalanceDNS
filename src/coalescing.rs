use std::{
    collections::HashMap,
};

use parking_lot::RwLock;
use tokio::sync::watch;

/// Manager for combining identical DNS queries (Query Coalescing)
pub struct PendingQueries {
    /// Active queries map: key -> result sender
    map: RwLock<HashMap<QueryKey, watch::Sender<Option<Vec<u8>>>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct QueryKey {
    domain: String,
    qtype: u16,
}

pub enum QueryState {
    /// Query is already in progress, wait for the result
    Waiting(watch::Receiver<Option<Vec<u8>>>),
    /// We are the first to make this query
    New(watch::Sender<Option<Vec<u8>>>),
}

impl PendingQueries {
    pub fn new() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
        }
    }

    /// Checks if the query is already in progress.
    /// If yes, returns a receiver to wait for the result.
    /// If no, creates a new channel and returns the sender.
    pub fn get_or_create(&self, domain: &str, qtype: u16) -> QueryState {
        let key = QueryKey {
            domain: domain.to_ascii_lowercase(),
            qtype,
        };

        let mut map = self.map.write();
        if let Some(tx) = map.get(&key) {
            QueryState::Waiting(tx.subscribe())
        } else {
            let (tx, _rx) = watch::channel(None);
            map.insert(key, tx.clone());
            QueryState::New(tx)
        }
    }

    /// Removes the query from the active list (after completion)
    pub fn remove(&self, domain: &str, qtype: u16) {
        let key = QueryKey {
            domain: domain.to_ascii_lowercase(),
            qtype,
        };
        let mut map = self.map.write();
        map.remove(&key);
    }
}
