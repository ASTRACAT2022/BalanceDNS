use std::{
    collections::HashSet,
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use tokio::time;

use crate::{config::BlocklistRemoteConfig, dns};

#[derive(Clone)]
pub struct BlocklistRemote {
    url: Arc<str>,
    refresh: Duration,
    rules: Arc<ArcSwap<BlocklistRules>>,
    client: reqwest::Client,
}

#[derive(Default)]
pub struct BlocklistRules {
    exact: HashSet<Arc<str>>,
}

impl BlocklistRemote {
    pub fn new(cfg: BlocklistRemoteConfig) -> anyhow::Result<Self> {
        let refresh = Duration::from_secs(cfg.refresh_seconds.max(60));
        let rules = Arc::new(ArcSwap::from_pointee(BlocklistRules::default()));
        let client = reqwest::Client::builder()
            .http2_adaptive_window(true)
            .pool_max_idle_per_host(16)
            .build()?;
        Ok(Self {
            url: Arc::from(cfg.url),
            refresh,
            rules,
            client,
        })
    }

    pub async fn start(self: Arc<Self>) {
        match self.refresh_once().await {
            Ok(_) => {
                metrics::counter!("dns_blocklist_refresh_total", "result" => "success").increment(1);
            }
            Err(err) => {
                metrics::counter!("dns_blocklist_refresh_total", "result" => "error").increment(1);
                tracing::warn!(error = %err, url = %self.url, "blocklist refresh failed");
            }
        }
        let mut ticker = time::interval(self.refresh);
        loop {
            ticker.tick().await;
            if let Err(err) = self.refresh_once().await {
                metrics::counter!("dns_blocklist_refresh_total", "result" => "error").increment(1);
                tracing::warn!(error = %err, url = %self.url, "blocklist refresh failed");
            } else {
                metrics::counter!("dns_blocklist_refresh_total", "result" => "success").increment(1);
            }
        }
    }

    pub async fn refresh_once(&self) -> anyhow::Result<()> {
        let text = self
            .client
            .get(self.url.as_ref())
            .timeout(Duration::from_secs(15))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        let rules = parse_rules(&text);
        metrics::gauge!("dns_blocklist_domains").set(rules.exact.len() as f64);
        self.rules.store(Arc::new(rules));
        Ok(())
    }

    pub fn is_blocked(&self, query: &[u8]) -> bool {
        let (name, _qtype, qclass) = match dns::read_qname_qtype_qclass(query) {
            Some(v) => v,
            None => return false,
        };
        if qclass != 1 {
            return false;
        }

        let name = Arc::<str>::from(name);
        let rules = self.rules.load();
        rules.exact.contains(&name)
    }
}

fn parse_rules(text: &str) -> BlocklistRules {
    let mut rules = BlocklistRules::default();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('!') {
            continue;
        }

        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        if line.contains("##") || line.contains("#@#") {
            continue;
        }

        if let Some(domain) = parse_adblock_network_rule(line) {
            if let Some(n) = normalize_name(domain) {
                rules.exact.insert(n);
            }
            continue;
        }

        if let Some(domain) = parse_hosts_line(line) {
            if let Some(n) = normalize_name(domain) {
                rules.exact.insert(n);
            }
            continue;
        }

        if let Some(n) = normalize_name(line) {
            rules.exact.insert(n);
        }
    }

    rules
}

fn parse_adblock_network_rule(line: &str) -> Option<&str> {
    let l = line.trim();
    if !l.starts_with("||") {
        return None;
    }
    let rest = &l[2..];
    let end = rest
        .find(|c: char| c == '^' || c == '/' || c.is_whitespace())
        .unwrap_or(rest.len());
    let dom = rest[..end].trim();
    if dom.is_empty() {
        None
    } else {
        Some(dom)
    }
}

fn parse_hosts_line(line: &str) -> Option<&str> {
    let mut parts = line.split_whitespace();
    let first = parts.next()?;
    if first.parse::<std::net::IpAddr>().is_err() {
        return None;
    }
    parts.next()
}

fn normalize_name(host: &str) -> Option<Arc<str>> {
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    if host.contains('/') || host.contains(' ') || host.contains('\t') {
        return None;
    }
    if host.contains("::") {
        return None;
    }
    let host = host.trim_matches('.');
    if host.is_empty() {
        return None;
    }
    if !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_') {
        return None;
    }
    let mut out = host.to_ascii_lowercase();
    out.push('.');
    Some(Arc::from(out))
}
