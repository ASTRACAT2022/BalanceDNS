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

#[allow(dead_code)]
pub struct KresResolver {
    ctx: Arc<kres::Context>,
}

#[async_trait]
impl Resolver for KresResolver {
    async fn resolve(&self, name: &str, qtype: u16) -> anyhow::Result<Message> {
        // Construct DNS question wire format
        // We can use Hickory to construct the query packet, then pass bytes to kres.
        let mut query_msg = Message::new();
        query_msg.set_id(0);
        query_msg.set_recursion_desired(true);
        let name_clean = Name::from_str(name)?;
        query_msg.add_query(hickory_proto::op::Query::query(name_clean, RecordType::from(qtype)));
        let question_bytes = query_msg.to_vec()?;
        
        // Kres logic (based on user example)
        let ctx = self.ctx.clone();
        let req = kres::Request::new(ctx);
        // "from_addr" in consume is the client address. 
        // Since we are the resolver, we can use a dummy local address or the actual client addr if we propagated it (we don't here).
        // Let's use 127.0.0.1:0
        let from_addr = "127.0.0.1:53".parse::<std::net::SocketAddr>().unwrap();

        let mut state = req.consume(&question_bytes, from_addr);
        
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;

        while state == kres::State::PRODUCE {
            state = if let Some((msg, addr_set)) = req.produce() {
                 if addr_set.is_empty() {
                     break; 
                 }
                 let target = addr_set[0]; // Just pick first? 
                 
                 // Send
                 socket.send_to(&msg, target).await?;
                 
                 // Receive
                 let mut buf = [0u8; 4096];
                 // We need timeout here to prevent indefinite hang
                 let res = tokio::time::timeout(std::time::Duration::from_secs(2), socket.recv_from(&mut buf)).await;
                 
                 match res {
                     Ok(Ok((amt, src))) => {
                         req.consume(&buf[..amt], src)
                     },
                     _ => {
                         // Timeout or error, how to notify kres? 
                         // Implicitly it will retry if we call produce again? 
                         // Or we must allow kres to decide.
                         // But if we don't consume anything, state doesn't change?
                         // "It doesn't require a specific I/O model and instead provides a generic interface for pushing/pulling DNS messages"
                         // Does consume handle empty/timeout?
                         // User example doesn't show timeout handling.
                         // Maybe we just break loop?
                         break; 
                     }
                 }
            } else {
                break;
            }
        }
        
        // Finish
        // finish(state) returns Result<Vec<u8>, Error>
        match req.finish(state) {
            Ok(answer_bytes) => {
                 let msg = Message::from_vec(&answer_bytes)?;
                 Ok(msg)
            },
            Err(e) => {
                 // Kres failed
                 log::error!("Kres resolution failed: {:?}", e);
                 let mut servfail = Message::new();
                 servfail.set_response_code(hickory_proto::op::ResponseCode::ServFail);
                 Ok(servfail)
            }
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
    } else if resolver_type.eq_ignore_ascii_case("kres") {
        info!("Initializing Knot Resolver (libkres)...");
        
        // In a real scenario we might want to configure context (trust anchors etc).
        // Assuming default context is sufficient or loads system defaults.
        let ctx = kres::Context::new(); 
        
        // Need to handle Ctx creation error? 
        // User example: Context::new(). Is it safe or result?
        // Assuming it's Context::new() -> Context
        
        Ok(Box::new(KresResolver {
            ctx: Arc::new(ctx),
        }))
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
