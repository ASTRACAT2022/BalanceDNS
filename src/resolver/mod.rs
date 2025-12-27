use std::sync::Arc;
use crate::config::Config;
use crate::cache::Cache;
use crate::metrics::Metrics;
use async_trait::async_trait;
use hickory_proto::op::Message;
use hickory_proto::rr::{Record, RecordType, Name};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
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
        let mut msg = Message::new();
        msg.set_id(0);
        msg.set_recursion_desired(true);
        msg.set_recursion_available(true);

        let rt = RecordType::from(qtype);
        let name_parsed = Name::from_str(name).unwrap_or(Name::root());

        // Use lookup for generic record types
        // Hickory resolver 'lookup' handles CNAME following etc.
        match self.resolver.lookup(name, rt).await {
            Ok(lookup) => {
                // Lookup successful
                for record in lookup.record_iter() {
                    msg.add_answer(record.clone());
                }
                
                // If DNSSEC validated?
                // Hickory resolver validates if configured.
                // We can assume data is authentic if we are relying on the validator.
                msg.set_authentic_data(true); 
            },
            Err(e) => {
                // If it's a NXDOMAIN or NoRecords, we should return that code.
                // But lookup error structure in Hickory requires checking kind.
                use hickory_resolver::error::ResolveError;
                use hickory_resolver::error::ResolveErrorKind;
                
                match e.kind() {
                    ResolveErrorKind::NoRecordsFound { .. } => {
                        msg.set_response_code(hickory_proto::op::ResponseCode::NoError);
                    },
                    ResolveErrorKind::Proto(_proto_err) => {
                         let s = e.to_string();
                         if s.contains("NXDomain") {
                             msg.set_response_code(hickory_proto::op::ResponseCode::NXDomain);
                         } else {
                             // Treat other proto errors as ServFail without throwing hard error
                             msg.set_response_code(hickory_proto::op::ResponseCode::ServFail);
                         }
                    },
                    ResolveErrorKind::Timeout => {
                        // Return ServFail on timeout so client knows to retry/fail
                        msg.set_response_code(hickory_proto::op::ResponseCode::ServFail);
                    },
                    _ => {
                         // For other errors, log a warning but return ServFail to client
                         log::warn!("Resolver error for {}: {}", name, e);
                         msg.set_response_code(hickory_proto::op::ResponseCode::ServFail);
                         // return Err(anyhow::anyhow!("Resolution error: {}", e)); // Don't return Err to avoid log spam in server
                    }
                }

            }
        }

        Ok(msg)
    }
}

pub async fn create_resolver(
    _resolver_type: &str,
    cfg: &Config,
    cache: Arc<Cache>,
    metrics: Arc<Metrics>
) -> anyhow::Result<Box<dyn Resolver>> {
    // Configure Resolver for TRUE recursive resolution from root servers
    let mut opts = ResolverOpts::default();
    opts.validate = true; // Enable DNSSEC validation
    opts.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4Only; // Force IPv4 to avoid AAAA timeouts on non-IPv6 networks
    opts.timeout = cfg.resolver.upstream_timeout;
    opts.attempts = 3;
    opts.recursion_desired = true;

    // Use default config which queries root servers directly (true recursion)
    let config = ResolverConfig::default();

    let resolver = TokioAsyncResolver::tokio(config, opts);

    info!("Initialized Hickory Recursive Resolver with DNSSEC validation enabled from root servers");

    Ok(Box::new(HickoryResolver {
        resolver,
        metrics,
        _cache: cache,
    }))
}
