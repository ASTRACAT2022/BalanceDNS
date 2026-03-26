use std::{
    collections::HashSet,
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use reqwest::{
    header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED},
    StatusCode,
};
use tokio::{sync::RwLock, time};

use crate::{config::BlocklistRemoteConfig, dns};

#[derive(Clone)]
pub struct BlocklistRemote {
    url: Arc<str>,
    refresh: Duration,
    rules: Arc<ArcSwap<BlocklistRules>>,
    validator: Arc<RwLock<CacheValidator>>,
    client: reqwest::Client,
}

#[derive(Default)]
pub struct BlocklistRules {
    exact: HashSet<Arc<str>>,
}

#[derive(Default)]
struct CacheValidator {
    etag: Option<String>,
    last_modified: Option<String>,
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
            validator: Arc::new(RwLock::new(CacheValidator::default())),
            client,
        })
    }

    pub async fn start(self: Arc<Self>) {
        if let Err(err) = self.refresh_once().await {
            tracing::warn!(error = %err, url = %self.url, "blocklist refresh failed");
        }
        let mut ticker = time::interval(self.refresh);
        loop {
            ticker.tick().await;
            if let Err(err) = self.refresh_once().await {
                tracing::warn!(error = %err, url = %self.url, "blocklist refresh failed");
            }
        }
    }

    pub async fn refresh_once(&self) -> anyhow::Result<()> {
        let validator = self.validator.read().await;
        let mut req = self.client.get(self.url.as_ref()).timeout(Duration::from_secs(15));
        if let Some(etag) = &validator.etag {
            req = req.header(IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = &validator.last_modified {
            req = req.header(IF_MODIFIED_SINCE, last_modified);
        }
        drop(validator);

        let resp = req.send().await?;
        if resp.status() == StatusCode::NOT_MODIFIED {
            metrics::counter!("dns_blocklist_refresh_total", "result" => "not_modified").increment(1);
            return Ok(());
        }
        let resp = match resp.error_for_status() {
            Ok(resp) => resp,
            Err(err) => {
                metrics::counter!("dns_blocklist_refresh_total", "result" => "error").increment(1);
                return Err(err.into());
            }
        };

        let mut validator = self.validator.write().await;
        validator.etag = resp
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        validator.last_modified = resp
            .headers()
            .get(LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        drop(validator);

        let text = resp.text().await?;

        let rules = parse_rules(&text);
        metrics::gauge!("dns_blocklist_domains").set(rules.exact.len() as f64);
        self.rules.store(Arc::new(rules));
        metrics::counter!("dns_blocklist_refresh_total", "result" => "success").increment(1);
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

        let rules = self.rules.load();
        rules.exact.contains(name.as_str())
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
