use std::{
    collections::HashMap,
    net::SocketAddr,
};

use parking_lot::Mutex;
use tokio::sync::oneshot;

/// Responsible for matching incoming UDP responses with pending queries.
pub struct ResponseDispatcher {
    waiters: Mutex<HashMap<ResponseKey, oneshot::Sender<Vec<u8>>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ResponseKey {
    /// Socket index in the pool
    socket_id: usize,
    /// Upstream address
    upstream_addr: SocketAddr,
    /// DNS Transaction ID
    tid: u16,
}

impl ResponseDispatcher {
    pub fn new() -> Self {
        Self {
            waiters: Mutex::new(HashMap::new()),
        }
    }

    /// Registers a waiter for a response. Returns a receiver.
    pub fn register(&self, socket_id: usize, upstream_addr: SocketAddr, tid: u16) -> oneshot::Receiver<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        let key = ResponseKey {
            socket_id,
            upstream_addr,
            tid,
        };
        let mut waiters = self.waiters.lock();
        waiters.insert(key, tx);
        rx
    }

    /// Processes an incoming packet. If a matching waiter is found, sends the data.
    pub fn dispatch(&self, socket_id: usize, upstream_addr: SocketAddr, packet: &[u8]) -> bool {
        if packet.len() < 2 {
            return false;
        }
        let tid = u16::from_be_bytes([packet[0], packet[1]]);
        let key = ResponseKey {
            socket_id,
            upstream_addr,
            tid,
        };

        let mut waiters = self.waiters.lock();
        if let Some(tx) = waiters.remove(&key) {
            let _ = tx.send(packet.to_vec());
            return true;
        }
        false
    }

    /// Removes a waiter (e.g., on timeout)
    pub fn unregister(&self, socket_id: usize, upstream_addr: SocketAddr, tid: u16) {
        let key = ResponseKey {
            socket_id,
            upstream_addr,
            tid,
        };
        let mut waiters = self.waiters.lock();
        waiters.remove(&key);
    }
}
