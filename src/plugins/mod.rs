use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use log::{info, warn};
use reqwest;
use std::collections::{HashSet, HashMap};
use std::fs;
use std::time::Duration;
use tokio::time;

#[derive(Debug, PartialEq)]
pub enum PluginAction {
    Continue,
    #[allow(dead_code)]
    Drop,
    Block, // Returns NXDOMAIN or REFUSED
    Reply(std::net::IpAddr), // Returns specific IP
}

#[async_trait]
pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    async fn on_query(&self, name: &str, qtype: u16) -> PluginAction;
    async fn refresh(&self) {}
}

pub struct PluginManager {
    plugins: Vec<Box<dyn Plugin>>,
}

impl PluginManager {
    pub fn new() -> Self {
        PluginManager {
            plugins: Vec::new(),
        }
    }

    pub fn register(&mut self, plugin: Box<dyn Plugin>) {
        info!("Registering plugin: {}", plugin.name());
        self.plugins.push(plugin);
    }

    pub async fn on_query(&self, name: &str, qtype: u16) -> PluginAction {
        for plugin in &self.plugins {
            match plugin.on_query(name, qtype).await {
                PluginAction::Continue => continue,
                action => return action,
            }
        }
        PluginAction::Continue
    }

    pub async fn reload_lists(&self) {
        info!("Reloading all plugins...");
        for plugin in &self.plugins {
            plugin.refresh().await;
        }
    }
}

// --- Plugins ---

pub struct HostsPlugin {
    _hosts: RwLock<HashMap<String, String>>, // Domain -> IP
}

impl HostsPlugin {
    pub fn new(path: &str) -> Self {
        let mut hosts = HashMap::new();
        match fs::read_to_string(path) {
            Ok(content) => {
                let mut count = 0;
                for line in content.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if parts[0].starts_with('#') { continue; }
                        // Format: IP HOST [ALIASES...]
                        // We map HOST -> IP
                        // parts[0] is IP
                        let ip = parts[0];
                        for host in &parts[1..] {
                             // Normalize host: lowercase, trailing dot removal?
                             // Simple normalization for now
                             let key = host.trim_end_matches('.').to_lowercase();
                             hosts.insert(key, ip.to_string());
                             count += 1;
                        }
                    }
                }
                info!("Loaded {} hosts from {}", count, path);
            },
            Err(e) => {
                 warn!("Could not read hosts file {}: {}", path, e);
            }
        }

        HostsPlugin {
            _hosts: RwLock::new(hosts),
        }
    }
}

#[async_trait]
impl Plugin for HostsPlugin {
    fn name(&self) -> &str {
        "hosts"
    }

    async fn on_query(&self, name: &str, qtype: u16) -> PluginAction {
        // Only handle A records (IPv4) for now, as our map is simple IO
        // If qtype is A (1)
        if qtype == 1 {
            let key = name.trim_end_matches('.').to_lowercase();
            let ip_str = {
                let r = self._hosts.read().unwrap();
                r.get(&key).cloned()
            };

            if let Some(ip) = ip_str {
                if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                    return PluginAction::Reply(addr);
                }
            }
        }
        PluginAction::Continue
    }
}

#[derive(Clone)]
pub struct AdBlockPlugin {
    blocklist: Arc<RwLock<HashSet<String>>>,
    urls: Vec<String>,
}

impl AdBlockPlugin {
    pub fn new(urls: Vec<String>) -> Self {
        let plugin = AdBlockPlugin {
            blocklist: Arc::new(RwLock::new(HashSet::new())),
            urls,
        };

        let p = plugin.clone();
        tokio::spawn(async move {
            p.refresh_loop().await;
        });

        plugin
    }

    async fn refresh_loop(&self) {
        loop {
            self.refresh().await;
            time::sleep(Duration::from_secs(3600 * 24)).await; // Daily refresh
        }
    }

    async fn refresh(&self) {
        info!("Refreshing AdBlock list...");
        let mut new_list = HashSet::new();
        for url in &self.urls {
            match reqwest::get(url).await {
                Ok(resp) => {
                    if let Ok(text) = resp.text().await {
                        for line in text.lines() {
                            if line.starts_with('#') || line.is_empty() { continue; }
                            // StevenBlack hosts format: 0.0.0.0 domain.com
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 2 {
                                new_list.insert(parts[1].to_string());
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to fetch adblock list {}: {}", url, e);
                }
            }
        }

        let count = new_list.len();
        {
            let mut w = self.blocklist.write().unwrap();
            *w = new_list;
        }
        info!("AdBlock list updated with {} domains", count);
    }
}

#[async_trait]
impl Plugin for AdBlockPlugin {
    fn name(&self) -> &str {
        "adblock"
    }

    async fn on_query(&self, name: &str, _qtype: u16) -> PluginAction {
        let blocked = {
             let r = self.blocklist.read().unwrap();
             r.contains(name) || r.contains(&name.trim_end_matches('.').to_string())
        };

        if blocked {
            return PluginAction::Block;
        }
        PluginAction::Continue
    }

    async fn refresh(&self) {
        self.refresh().await;
    }
}
