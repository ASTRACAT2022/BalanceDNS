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
    _hosts: RwLock<HashMap<String, String>>, // Domain -> IP (simplified)
}

impl HostsPlugin {
    pub fn new(path: &str) -> Self {
        let mut hosts = HashMap::new();
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if parts[0].starts_with('#') { continue; }
                    hosts.insert(parts[1].to_string(), parts[0].to_string());
                }
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

    async fn on_query(&self, _name: &str, _qtype: u16) -> PluginAction {
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
