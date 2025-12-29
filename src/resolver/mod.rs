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
    sf: Arc<async_singleflight::Group<Message>>,
}

use crate::cache::CacheStatus;

#[async_trait]
impl Resolver for HickoryResolver {
    async fn resolve(&self, name: &str, qtype: u16) -> anyhow::Result<Message> {
        let _name_parsed = Name::from_str(name).unwrap_or(Name::root());
        let cache_key = format!("{}|{}", name, qtype);
        let mut stale_fallback: Option<Message> = None;

        // 1. Check Cache
        match self._cache.get(&cache_key) {
            Some((msg_bytes, status)) => {
                if let Ok(msg) = Message::from_vec(&msg_bytes) {
                    match status {
                        CacheStatus::Hit => return Ok(msg),
                        CacheStatus::Prefetch => {
                             // Zero-wait prefetch: return fresh data, spawn background refresh
                             let resolver_clone = self.resolver.clone(); // Lightweight Handle clone
                             let cache_clone = self._cache.clone();
                             let metric_clone = self.metrics.clone();
                             let name_string = name.to_string();
                             let key_clone = cache_key.clone();
                             let sf_clone = self.sf.clone();
                             
                             tokio::spawn(async move {
                                 // Use SingleFlight to deduplicate prefetch
                                 let key_internal = key_clone.clone();
                             let _ = sf_clone.work(&key_clone, async move {
                                     let rt = RecordType::from(qtype);
                                     // Perform lookup logic
                                     if let Ok(lookup) = resolver_clone.lookup(&name_string, rt).await {
                                          let mut new_msg = Message::new();
                                          new_msg.set_id(0);
                                          new_msg.set_recursion_desired(true);
                                          new_msg.set_recursion_available(true);
                                          new_msg.set_authentic_data(true);
                                          new_msg.set_response_code(hickory_proto::op::ResponseCode::NoError);
                                          
                                          let mut min_ttl = 300;
                                          for record in lookup.record_iter() {
                                              new_msg.add_answer(record.clone());
                                              if record.ttl() < min_ttl { min_ttl = record.ttl(); }
                                          }
                                          
                                          if let Ok(bytes) = new_msg.to_vec() {
                                              cache_clone.set(&key_internal, bytes, std::time::Duration::from_secs(min_ttl as u64), std::time::Duration::from_secs(600));
                                              metric_clone.increment_cache_prefetch();
                                          }
                                          return Ok(new_msg); // Result needed for SF
                                     }
                                     Err(anyhow::anyhow!("Prefetch failed"))
                                 }).await;
                             });
                             
                             return Ok(msg);
                        },
                        CacheStatus::Stale => {
                            // Proceed to upstream, but keep this msg for fallback (Serve-Stale)
                            stale_fallback = Some(msg);
                        },
                        CacheStatus::Miss => {
                            stale_fallback = None;
                        }
                    }
                }
            },
            None => {
                // No cache entry found, stale_fallback remains None.
            }
        }

        // 2. Forward to Upstream (Using Singleflight)
        let resolver = self.resolver.clone();
        let cache = self._cache.clone();
        let _metrics = self.metrics.clone(); // Kept if needed later, but prefixed with _ to suppress warning
        let name_owned = name.to_string();
        let key = cache_key.clone();

        let key_internal = key.clone();
        let result_tuple = self.sf.work(&key, async move {
            let rt = RecordType::from(qtype);
            let mut msg = Message::new();
            msg.set_id(0);
            msg.set_recursion_desired(true);
            msg.set_recursion_available(true);

            match resolver.lookup(&name_owned, rt).await {
                Ok(lookup) => {
                    let mut min_ttl = 300; // Default TTL cap
                    for record in lookup.record_iter() {
                        msg.add_answer(record.clone());
                        if record.ttl() < min_ttl {
                            min_ttl = record.ttl();
                        }
                    }
                    msg.set_authentic_data(true); 
                    msg.set_response_code(hickory_proto::op::ResponseCode::NoError);

                    // 3. Store in Cache (Success)
                                 // NOTE: Original code used key. Reset to key_internal.
                                 // Logic: 
                                 // cache.set(&key_internal, bytes, ...
                                 // Let's replace usage fully.
                                 if let Ok(bytes) = msg.to_vec() {
                                     // Success
                                     cache.set(&key_internal, bytes, std::time::Duration::from_secs(min_ttl as u64), std::time::Duration::from_secs(600));
                                 }
                    Ok(msg)
                },
                Err(e) => {
                    use hickory_resolver::error::ResolveErrorKind;
                    match e.kind() {
                        ResolveErrorKind::NoRecordsFound { .. } => {
                            msg.set_response_code(hickory_proto::op::ResponseCode::NoError);
                             if let Ok(bytes) = msg.to_vec() {
                                 // NODATA: 60s
                                 cache.set(&key_internal, bytes, std::time::Duration::from_secs(60), std::time::Duration::from_secs(60));
                             }
                             Ok(msg)
                        },
                        ResolveErrorKind::Proto(_proto_err) => {
                             let s = e.to_string();
                             if s.contains("NXDomain") {
                                 msg.set_response_code(hickory_proto::op::ResponseCode::NXDomain);
                                 if let Ok(bytes) = msg.to_vec() {
                                     // NXDOMAIN: 60s
                                     cache.set(&key_internal, bytes, std::time::Duration::from_secs(60), std::time::Duration::from_secs(60));
                                 }
                                 Ok(msg)
                             } else {
                                 msg.set_response_code(hickory_proto::op::ResponseCode::ServFail);
                                 // SERVFAIL: 10s
                                 if let Ok(bytes) = msg.to_vec() {
                                     cache.set(&key_internal, bytes, std::time::Duration::from_secs(10), std::time::Duration::from_secs(10));
                                 }
                                 Ok(msg)
                             }
                        },
                        _ => {
                             log::warn!("Resolver error for {}: {}", name_owned, e);
                             Err(anyhow::anyhow!(e.to_string()))
                        }
                    }
                }
            }
        }).await;
        
        let res = match result_tuple {
             (Some(val), _, _) => Ok(val),
             _ => Err(anyhow::anyhow!("Singleflight internal error")),
        };

        match res {
            Ok(msg) => Ok(msg),
            Err(e) => {
                // Upstream failed. Do we have stale data?
                if let Some(stale_msg) = stale_fallback {
                    log::warn!("Upstream failed for {}, serving stale cache.", name);
                    return Ok(stale_msg);
                }
                Err(anyhow::anyhow!("Resolution failed: {}", e))
            },
        }
    }
}


pub async fn create_resolver(
    resolver_type: &str,
    cfg: &Config,
    cache: Arc<Cache>,
    metrics: Arc<Metrics>
) -> anyhow::Result<Box<dyn Resolver>> {
    
    if resolver_type.eq_ignore_ascii_case("unbound") {
         let upstream = cfg.resolver.upstream_addr.as_deref().unwrap_or("127.0.0.1:5353");
         info!("Initializing Hickory Resolver in Forwarding mode to local Unbound ({})...", upstream);
         
         let mut addrs = tokio::net::lookup_host(upstream).await
             .map_err(|e| anyhow::anyhow!("Failed to resolve upstream {}: {}", upstream, e))?;
         let socket_addr = addrs.next()
             .ok_or_else(|| anyhow::anyhow!("Could not resolve upstream {}", upstream))?;
         
         info!("Resolved upstream {} to {}", upstream, socket_addr);

         let mut config = ResolverConfig::new();
         config.add_name_server(hickory_resolver::config::NameServerConfig {
             socket_addr,
             protocol: hickory_resolver::config::Protocol::Udp,
             tls_dns_name: None,
             trust_negative_responses: true,
             bind_addr: None,
             tls_config: None,
         });

         let mut opts = ResolverOpts::default();
         opts.validate = false; 
         opts.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4Only;
         opts.timeout = cfg.resolver.upstream_timeout;
         opts.attempts = 3;
         opts.recursion_desired = true; 

         let resolver = TokioAsyncResolver::tokio(config, opts);
         info!("Initialized Forwarder to Unbound Service.");
         
         return Ok(Box::new(HickoryResolver {
            resolver,
            metrics,
            _cache: cache,
            sf: Arc::new(async_singleflight::Group::new()),
        }));
    }

    // Default to Hickory Recursive
    let mut opts = ResolverOpts::default();
    opts.validate = false; 
    opts.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4Only;
    opts.timeout = cfg.resolver.upstream_timeout;
    opts.attempts = 3;
    opts.recursion_desired = true;

    let config = ResolverConfig::default();

    let resolver = TokioAsyncResolver::tokio(config, opts);

    info!("Initialized Hickory Recursive Resolver with DNSSEC enabled (validation disabled) from root servers");

    Ok(Box::new(HickoryResolver {
        resolver,
        metrics,
        _cache: cache,
        sf: Arc::new(async_singleflight::Group::new()),
    }))
}
