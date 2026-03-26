use std::{
    collections::HashMap,
    net::IpAddr,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use tokio::time;

use crate::{config::HostsRemoteConfig, dns};

#[derive(Clone)]
pub struct HostsRemote {
    url: Arc<str>,
    refresh: Duration,
    ttl_seconds: u32,
    table: Arc<ArcSwap<HostsTable>>,
    client: reqwest::Client,
}

#[derive(Default)]
pub struct HostsTable {
    by_name: HashMap<Arc<str>, Vec<IpAddr>>,
}

impl HostsRemote {
    pub fn new(cfg: HostsRemoteConfig) -> anyhow::Result<Self> {
        let refresh = Duration::from_secs(cfg.refresh_seconds.max(60));
        let table = Arc::new(ArcSwap::from_pointee(HostsTable::default()));
        let client = reqwest::Client::builder()
            .http2_adaptive_window(true)
            .pool_max_idle_per_host(16)
            .build()?;

        Ok(Self {
            url: Arc::from(cfg.url),
            refresh,
            ttl_seconds: cfg.ttl_seconds.max(1),
            table,
            client,
        })
    }

    pub async fn start(self: Arc<Self>) {
        match self.refresh_once().await {
            Ok(_) => {
                metrics::counter!("dns_hosts_refresh_total", "result" => "success").increment(1);
            }
            Err(err) => {
                metrics::counter!("dns_hosts_refresh_total", "result" => "error").increment(1);
                tracing::warn!(error = %err, url = %self.url, "hosts refresh failed");
            }
        }

        let mut ticker = time::interval(self.refresh);
        loop {
            ticker.tick().await;
            if let Err(err) = self.refresh_once().await {
                metrics::counter!("dns_hosts_refresh_total", "result" => "error").increment(1);
                tracing::warn!(error = %err, url = %self.url, "hosts refresh failed");
            } else {
                metrics::counter!("dns_hosts_refresh_total", "result" => "success").increment(1);
            }
        }
    }

    pub async fn refresh_once(&self) -> anyhow::Result<()> {
        let text = self
            .client
            .get(self.url.as_ref())
            .timeout(Duration::from_secs(10))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        let table = parse_hosts(&text);
        metrics::gauge!("dns_hosts_domains").set(table.by_name.len() as f64);
        let ip_count: usize = table.by_name.values().map(|v| v.len()).sum();
        metrics::gauge!("dns_hosts_ips").set(ip_count as f64);
        self.table.store(Arc::new(table));
        Ok(())
    }

    pub fn maybe_answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        let (name, qtype, qclass) = dns::read_qname_qtype_qclass(query)?;
        if qclass != 1 {
            return None;
        }

        let name = Arc::<str>::from(name);
        let table = self.table.load();
        let ips = table.by_name.get(&name)?;

        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for ip in ips {
            match ip {
                IpAddr::V4(v) => v4.push(*v),
                IpAddr::V6(v) => v6.push(*v),
            }
        }

        let answers = match qtype {
            1 => dns::Answers::A(v4),
            28 => dns::Answers::AAAA(v6),
            _ => return None,
        };

        if answers.is_empty() {
            return None;
        }

        dns::build_answer_response(query, &name, qtype, answers, self.ttl_seconds)
    }
}

fn parse_hosts(text: &str) -> HostsTable {
    let mut table = HostsTable::default();

    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let ip = match parts.next() {
            Some(ip) => ip,
            None => continue,
        };
        let ip = match IpAddr::from_str(ip) {
            Ok(ip) => ip,
            Err(_) => continue,
        };

        for host in parts {
            if let Some(name) = normalize_name(host) {
                table
                    .by_name
                    .entry(name)
                    .or_default()
                    .push(ip);
            }
        }
    }

    table
}

fn normalize_name(host: &str) -> Option<Arc<str>> {
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    if host.eq_ignore_ascii_case("localhost") {
        return Some(Arc::from("localhost."));
    }

    let mut out = host.to_ascii_lowercase();
    if !out.ends_with('.') {
        out.push('.');
    }
    Some(Arc::from(out))
}
