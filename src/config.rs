use std::{net::SocketAddr, path::Path, time::Duration};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    pub hosts_remote: Option<HostsRemoteConfig>,
    pub balancing: BalancingConfig,
    pub security: SecurityConfig,
    pub metrics: MetricsConfig,
    pub upstreams: Vec<UpstreamConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub udp_listen: SocketAddr,
    pub tcp_listen: SocketAddr,
    #[serde(default = "default_dot_listen")]
    pub dot_listen: SocketAddr,
    #[serde(default = "default_doh_listen")]
    pub doh_listen: SocketAddr,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TlsConfig {
    #[serde(default = "default_tls_cert")]
    pub cert_pem: String,
    #[serde(default = "default_tls_key")]
    pub key_pem: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostsRemoteConfig {
    pub url: String,
    #[serde(default = "default_hosts_refresh_seconds")]
    pub refresh_seconds: u64,
    #[serde(default = "default_hosts_ttl_seconds")]
    pub ttl_seconds: u32,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_pem: default_tls_cert(),
            key_pem: default_tls_key(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BalancingAlgorithm {
    RoundRobin,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BalancingConfig {
    pub algorithm: BalancingAlgorithm,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecurityConfig {
    #[serde(default = "default_deny_any")]
    pub deny_any: bool,
    #[serde(default = "default_deny_dnskey")]
    pub deny_dnskey: bool,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MetricsConfig {
    pub listen: SocketAddr,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpstreamConfig {
    pub name: String,
    #[serde(default)]
    pub proto: UpstreamProto,
    pub addr: Option<SocketAddr>,
    pub url: Option<String>,
    pub server_name: Option<String>,
    #[serde(default)]
    pub tls_insecure: bool,
    #[serde(default = "default_pool")]
    pub pool: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProto {
    Udp,
    Tcp,
    Dot,
    Doh,
}

impl Default for UpstreamProto {
    fn default() -> Self {
        Self::Udp
    }
}

impl AppConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config {}: {}", path.display(), e))?;
        let cfg: Self = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("failed to parse config {}: {}", path.display(), e))?;

        Ok(cfg.with_defaults().resolve_paths(path))
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.security.request_timeout_ms)
    }

    fn with_defaults(mut self) -> Self {
        if self.upstreams.is_empty() {
            self.upstreams.push(UpstreamConfig {
                name: "google-8.8.8.8".to_string(),
                proto: UpstreamProto::Udp,
                addr: Some("8.8.8.8:53".parse().unwrap()),
                url: None,
                server_name: None,
                tls_insecure: false,
                pool: "default".to_string(),
                weight: 1,
            });
        }
        self
    }

    fn resolve_paths(mut self, config_path: &Path) -> Self {
        let Some(dir) = config_path.parent() else {
            return self;
        };

        self.tls.cert_pem = resolve_path(dir, &self.tls.cert_pem);
        self.tls.key_pem = resolve_path(dir, &self.tls.key_pem);
        self
    }
}

fn resolve_path(base_dir: &Path, value: &str) -> String {
    let p = std::path::Path::new(value);
    if p.is_absolute() {
        return value.to_string();
    }
    base_dir.join(p).to_string_lossy().to_string()
}

fn default_deny_any() -> bool {
    true
}

fn default_deny_dnskey() -> bool {
    true
}

fn default_request_timeout_ms() -> u64 {
    1500
}

fn default_dot_listen() -> SocketAddr {
    "0.0.0.0:8853".parse().unwrap()
}

fn default_doh_listen() -> SocketAddr {
    "0.0.0.0:8443".parse().unwrap()
}

fn default_tls_cert() -> String {
    "config/tls/server.crt".to_string()
}

fn default_tls_key() -> String {
    "config/tls/server.key".to_string()
}

fn default_hosts_refresh_seconds() -> u64 {
    300
}

fn default_hosts_ttl_seconds() -> u32 {
    60
}

fn default_pool() -> String {
    "default".to_string()
}

fn default_weight() -> u32 {
    1
}
