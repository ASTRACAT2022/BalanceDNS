use std::sync::Arc;
use crate::config::Config;
use crate::cache::Cache;
use crate::metrics::Metrics;
use async_trait::async_trait;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::op::Message;
use hickory_server::authority::MessageResponse;
use hickory_resolver::lookup::Lookup;
use hickory_proto::rr::{RecordType, Name};
use std::str::FromStr;

#[async_trait]
pub trait Resolver: Send + Sync {
    // We need to return something that can be converted to a DNS response
    async fn resolve(&self, name: &str, qtype: u16) -> anyhow::Result<Message>;
}

pub struct StandardResolver {
    inner: TokioAsyncResolver,
    metrics: Arc<Metrics>,
    cache: Arc<Cache>,
}

#[async_trait]
impl Resolver for StandardResolver {
    async fn resolve(&self, name: &str, qtype: u16) -> anyhow::Result<Message> {
        // TODO: Map u16 qtype to RecordType
        let record_type = RecordType::from(qtype);
        let name_parsed = Name::from_str(name)?;

        // 1. Check cache (to be implemented more fully, currently cache returns raw bytes)
        // For now, let's just delegate to hickory resolver

        // We use system config for now, but should use config from cfg
        let lookup_result = self.inner.lookup(name, record_type).await;

        match lookup_result {
            Ok(lookup) => {
                // Convert lookup to Message
                let mut msg = Message::new();
                msg.add_answers(lookup.records().iter().cloned());
                Ok(msg)
            }
            Err(e) => {
                 self.metrics.increment_cache_misses(); // It's not really a cache miss, but a resolution failure
                 Err(anyhow::anyhow!("Resolution failed: {}", e))
            }
        }
    }
}

pub async fn create_resolver(
    _resolver_type: &str,
    cfg: &Config,
    cache: Arc<Cache>,
    metrics: Arc<Metrics>
) -> anyhow::Result<Box<dyn Resolver>> {
    // Basic implementation creating a system resolver
    // TODO: Configure from cfg.resolver
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    Ok(Box::new(StandardResolver {
        inner: resolver,
        metrics,
        cache,
    }))
}
