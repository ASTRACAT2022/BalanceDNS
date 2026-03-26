use std::{net::SocketAddr, path::Path, time::Duration};

use serde::{de, Deserialize, Deserializer, Serialize};

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
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub udp_listen: SocketAddr,
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub tcp_listen: SocketAddr,
    #[serde(default = "default_dot_listen")]
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub dot_listen: SocketAddr,
    #[serde(default = "default_doh_listen")]
    #[serde(deserialize_with = "deserialize_socket_addr")]
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
    #[serde(default, deserialize_with = "deserialize_opt_socket_addr")]
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

        Ok(cfg.with_defaults().resolve_paths(path).normalize_strings())
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

    fn normalize_strings(mut self) -> Self {
        if let Some(hr) = &mut self.hosts_remote {
            hr.url = sanitize_url(&hr.url);
        }
        for u in &mut self.upstreams {
            if let Some(url) = &mut u.url {
                *url = sanitize_url(url);
            }
            if let Some(sn) = &mut u.server_name {
                *sn = sn.trim().to_string();
            }
        }
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

fn sanitize_url(value: &str) -> String {
    value.replace('`', "").trim().to_string()
}

fn deserialize_socket_addr<'de, D>(deserializer: D) -> Result<SocketAddr, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_socket_addr_loose(&s).map_err(de::Error::custom)
}

fn deserialize_opt_socket_addr<'de, D>(deserializer: D) -> Result<Option<SocketAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = Option::<String>::deserialize(deserializer)?;
    match s {
        None => Ok(None),
        Some(v) => parse_socket_addr_loose(&v).map(Some).map_err(de::Error::custom),
    }
}

fn parse_socket_addr_loose(value: &str) -> Result<SocketAddr, String> {
    let s = value.trim();
    if s.is_empty() {
        return Err("empty socket address".to_string());
    }

    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }

    if let Some(rest) = s.strip_prefix("[:") {
        if let Some((ip, port)) = rest.rsplit_once(":]:") {
            let fixed = format!("{}:{}", ip.trim(), port.trim());
            return fixed
                .parse::<SocketAddr>()
                .map_err(|_| format!("invalid socket address syntax: {}", value));
        }
    }

    if let Some(inner) = s.strip_prefix('[').and_then(|v| v.split_once(']').map(|(a, b)| (a, b))) {
        let (inside, tail) = inner;
        if !inside.contains(':') {
            if let Some(port) = tail.strip_prefix(':') {
                let fixed = format!("{}:{}", inside.trim(), port.trim());
                return fixed
                    .parse::<SocketAddr>()
                    .map_err(|_| format!("invalid socket address syntax: {}", value));
            }
        }
    }

    Err(format!("invalid socket address syntax: {}", value))
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
    "tls/server.crt".to_string()
}

fn default_tls_key() -> String {
    "tls/server.key".to_string()
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
