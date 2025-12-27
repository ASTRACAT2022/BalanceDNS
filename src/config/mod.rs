use std::fs;
use std::time::Duration;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub listen_addr: String,
    pub metrics_addr: String,
    pub admin_addr: String,
    pub metrics_storage_path: String,
    pub resolver: ResolverConfig,
    pub cache: CacheConfig,
    pub hosts: HostsConfig,
    pub adblock: AdBlockConfig,
    pub rate_limit: RateLimitConfig,
    pub admin: AdminConfig,
    pub httpsrr: HttpsRRConfig,
    pub doh: DoHConfig,
    pub dot: DoTConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverConfig {
    #[serde(rename = "type")]
    pub resolver_type: String,
    #[serde(with = "humantime_serde")]
    pub upstream_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
    pub max_workers: usize,
    pub upstream_addr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub lmdb_path: String,
    pub size: usize,
    #[serde(with = "humantime_serde")]
    pub max_ttl: Duration,
    #[serde(with = "humantime_serde")]
    pub min_ttl: Duration,
    #[serde(with = "humantime_serde")]
    pub stale_while_revalidate: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostsConfig {
    pub enabled: bool,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdBlockConfig {
    pub enabled: bool,
    pub blocklist_urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub qps: u32,
    pub burst: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoHConfig {
    pub enabled: bool,
    pub listen_addr: String,
    pub cert_file: String,
    pub key_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoTConfig {
    pub enabled: bool,
    pub listen_addr: String,
    pub cert_file: String,
    pub key_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpsRRRecordConfig {
    pub domain: String,
    pub ech: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpsRRConfig {
    pub enabled: bool,
    pub records: Vec<HttpsRRRecordConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen_addr: "0.0.0.0:5053".to_string(),
            metrics_addr: "0.0.0.0:9090".to_string(),
            admin_addr: "0.0.0.0:8080".to_string(),
            metrics_storage_path: "/tmp/dns_metrics.json".to_string(),
            resolver: ResolverConfig {
                resolver_type: "godns".to_string(),
                upstream_timeout: Duration::from_secs(5),
                request_timeout: Duration::from_secs(5),
                max_workers: 10,
                upstream_addr: None,
            },
            cache: CacheConfig {
                lmdb_path: "/tmp/dns_cache.lmdb".to_string(),
                size: 5000,
                max_ttl: Duration::from_secs(3600),
                min_ttl: Duration::from_secs(60),
                stale_while_revalidate: Duration::from_secs(60),
            },
            hosts: HostsConfig {
                enabled: true,
                path: "hosts".to_string(),
            },
            adblock: AdBlockConfig {
                enabled: true,
                blocklist_urls: vec![
                    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".to_string(),
                ],
            },
            rate_limit: RateLimitConfig {
                enabled: false,
                qps: 100,
                burst: 200,
            },
            admin: AdminConfig {
                username: "admin".to_string(),
                password: "change_me".to_string(),
            },
            doh: DoHConfig {
                enabled: false,
                listen_addr: "0.0.0.0:443".to_string(),
                cert_file: "".to_string(),
                key_file: "".to_string(),
            },
            dot: DoTConfig {
                enabled: false,
                listen_addr: "0.0.0.0:853".to_string(),
                cert_file: "".to_string(),
                key_file: "".to_string(),
            },
            httpsrr: HttpsRRConfig {
                enabled: false,
                records: vec![],
            },
        }
    }
}

impl Config {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(path: &str) -> anyhow::Result<Self> {
        if let Ok(data) = fs::read_to_string(path) {
            let config: Config = serde_yaml::from_str(&data)?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }

    #[allow(dead_code)]
    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let data = serde_yaml::to_string(self)?;
        fs::write(path, data)?;
        Ok(())
    }
}
