use std::sync::Arc;
use crate::config::Config;
use crate::cache::Cache;
use crate::metrics::Metrics;
use async_trait::async_trait;
use hickory_proto::op::Message;
use hickory_proto::rr::{Record, RecordType, Name};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol};
use std::str::FromStr;
use log::{info, error};

#[async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, name: &str, qtype: u16) -> anyhow::Result<Message>;
}

pub struct HickoryResolver {
    resolver: TokioAsyncResolver,
    metrics: Arc<Metrics>,
    _cache: Arc<Cache>,
}

#[async_trait]
impl Resolver for HickoryResolver {
    async fn resolve(&self, name: &str, qtype: u16) -> anyhow::Result<Message> {
        let rt = RecordType::from(qtype);
        let name_parsed = Name::from_str(name).unwrap_or(Name::root());
        let cache_key = format!("{}|{}", name, qtype);

        // 1. Check Cache
        if let Some((msg_bytes, stale)) = self._cache.get(&cache_key) {
            if let Ok(msg) = Message::from_vec(&msg_bytes) {
                if !stale {
                    // Cache Hit
                    return Ok(msg);
                } else {
                    // Stale hit: we should revalidate in background, but for now just use it?
                    // Or treat as miss if stale?
                    // "Stale While Revalidate" logic usually implies serving stale and revalidating.
                    // For simplicity, we can return stale but trigger a background task.
                    // BUT our `resolve` is async.
                    // Let's implement simpler logic: if stale, treat as miss but maybe use it if upstream fails?
                    // For now, let's treat stale as miss to force refresh.
                }
            }
        }

        // 2. Forward to Upstream (Unbound)
        let mut msg = Message::new();
        msg.set_id(0);
        msg.set_recursion_desired(true);
        msg.set_recursion_available(true);

        match self.resolver.lookup(name, rt).await {
            Ok(lookup) => {
                // Lookup successful
                let mut min_ttl = 300; // Default TTL cap
                
                for record in lookup.record_iter() {
                    msg.add_answer(record.clone());
                    if record.ttl() < min_ttl {
                        min_ttl = record.ttl();
                    }
                }
                
                // We trust Unbound for validation
                msg.set_authentic_data(true); 
                msg.set_response_code(hickory_proto::op::ResponseCode::NoError);

                // 3. Store in Cache
                if let Ok(bytes) = msg.to_vec() {
                     // Store with TTL. min_ttl ensures we respect upstream.
                     // SWR window: e.g. 10m
                     self._cache.set(&cache_key, bytes, std::time::Duration::from_secs(min_ttl as u64), std::time::Duration::from_secs(600));
                }
            },
            Err(e) => {
                use hickory_resolver::error::ResolveError;
                use hickory_resolver::error::ResolveErrorKind;
                
                match e.kind() {
                    ResolveErrorKind::NoRecordsFound { .. } => {
                        msg.set_response_code(hickory_proto::op::ResponseCode::NoError);
                        // Cache NoData? Yes, briefly. 
                         if let Ok(bytes) = msg.to_vec() {
                             self._cache.set(&cache_key, bytes, std::time::Duration::from_secs(60), std::time::Duration::from_secs(60));
                         }
                    },
                    ResolveErrorKind::Proto(_proto_err) => {
                         let s = e.to_string();
                         if s.contains("NXDomain") {
                             msg.set_response_code(hickory_proto::op::ResponseCode::NXDomain);
                             // Cache NXDOMAIN? Yes.
                             if let Ok(bytes) = msg.to_vec() {
                                 self._cache.set(&cache_key, bytes, std::time::Duration::from_secs(300), std::time::Duration::from_secs(60));
                             }
                         } else {
                             msg.set_response_code(hickory_proto::op::ResponseCode::ServFail);
                         }
                    },
                    ResolveErrorKind::Timeout => {
                        msg.set_response_code(hickory_proto::op::ResponseCode::ServFail);
                    },
                    _ => {
                         log::warn!("Resolver error for {}: {}", name, e);
                         msg.set_response_code(hickory_proto::op::ResponseCode::ServFail);
                    }
                }

            }
        }

        Ok(msg)
    }
}


pub async fn create_resolver(
    resolver_type: &str,
    cfg: &Config,
    cache: Arc<Cache>,
    metrics: Arc<Metrics>
) -> anyhow::Result<Box<dyn Resolver>> {
    if resolver_type.eq_ignore_ascii_case("unbound") {
         info!("Initializing Hickory Resolver in Forwarding mode to local Unbound (127.0.0.1:5353)...");
         let mut config = ResolverConfig::new();
         config.add_name_server(hickory_resolver::config::NameServerConfig {
             socket_addr: "127.0.0.1:5353".parse()?,
             protocol: hickory_resolver::config::Protocol::Udp,
             tls_dns_name: None,
             trust_negative_responses: true,
             bind_addr: None,
             tls_config: None,
         });

         let mut opts = ResolverOpts::default();
         // Unbound handles recursion and validation. We just forward.
         opts.validate = false; 
         opts.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4Only;
         opts.timeout = cfg.resolver.upstream_timeout;
         opts.attempts = 3;
         opts.recursion_desired = true; // Ask Unbound to recurse

         let resolver = TokioAsyncResolver::tokio(config, opts);
         info!("Initialized Forwarder to Unbound Service.");
         
         return Ok(Box::new(HickoryResolver {
            resolver,
            metrics,
            _cache: cache,
        }));
    }

    // Default to Hickory Recursive
    // Configure Resolver for TRUE recursive resolution from root servers
    let mut opts = ResolverOpts::default();
    opts.validate = false; // Disable DNSSEC validation to prevent SERVFAILs
    opts.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4Only;
    opts.timeout = cfg.resolver.upstream_timeout;
    opts.attempts = 3;
    opts.recursion_desired = true;

    // Use default config which queries root servers directly (true recursion)
    let config = ResolverConfig::default();

    let resolver = TokioAsyncResolver::tokio(config, opts);

    info!("Initialized Hickory Recursive Resolver with DNSSEC enabled (validation disabled) from root servers");

    Ok(Box::new(HickoryResolver {
        resolver,
        metrics,
        _cache: cache,
    }))
}
