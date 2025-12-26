use std::sync::Arc;
use crate::config::Config;
use crate::metrics::Metrics;
use crate::resolver::Resolver;
use crate::protection::Protection;
use crate::plugins::{PluginManager, PluginAction};
use hickory_server::ServerFuture;
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::net::TcpListener;
use hickory_proto::op::{ResponseCode, Header};
use std::time::{Instant, Duration};

pub struct Server {
    config: Config,
    metrics: Arc<Metrics>,
    resolver: Arc<Box<dyn Resolver>>,
    pm: Arc<PluginManager>,
    protection: Arc<Protection>,
}

struct Handler {
    metrics: Arc<Metrics>,
    resolver: Arc<Box<dyn Resolver>>,
    pm: Arc<PluginManager>,
    protection: Arc<Protection>,
}

#[async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(&self, request: &Request, mut response_handle: R) -> ResponseInfo {
        let start_time = Instant::now();
        // Correctly access query from request
        // Request has a Deref to MessageRequest
        // MessageRequest has queries() returning &[LowerQuery]
        // LowerQuery has name() and query_type()

        let query = request.query();
        let name = query.name().to_string();
        let qtype = u16::from(query.query_type());
        let qtype_str = query.query_type().to_string();

        self.metrics.increment_queries(&name);
        self.metrics.record_query_type(&qtype_str);

        // 0. Protection (Rate Limit / Blocklist)
        let src_ip = request.src().ip().to_string();
        if !self.protection.allow_request(&src_ip) {
            log::warn!("Dropped request from {} due to protection policy", src_ip);
            return ResponseInfo::from(Header::response_from_request(request.header()));
        }

        // 1. Run Plugins
        match self.pm.on_query(&name, qtype).await {
            PluginAction::Block => {
                self.metrics.increment_blocked_domains();

                let builder = MessageResponseBuilder::from_message_request(request);
                let mut header = Header::response_from_request(request.header());
                header.set_recursion_available(true);
                header.set_response_code(ResponseCode::NXDomain);
                let response = builder.build(header, std::iter::empty(), std::iter::empty(), std::iter::empty(), std::iter::empty());

                 if let Ok(_) = response_handle.send_response(response).await {
                     self.metrics.record_response_code("NXDOMAIN");
                     return ResponseInfo::from(header);
                 }
                 return ResponseInfo::from(Header::response_from_request(request.header()));
            }
            PluginAction::Drop => {
                 // Do nothing
                 return ResponseInfo::from(Header::response_from_request(request.header()));
            }
            PluginAction::Continue => {}
        }

        // 2. Resolve (Cache is inside resolver for now)
        match self.resolver.resolve(&name, qtype).await {
            Ok(msg) => {
                 let rcode = msg.response_code().to_string();
                 self.metrics.record_response_code(&rcode);

                 let builder = MessageResponseBuilder::from_message_request(request);
                 let mut header = Header::response_from_request(request.header());
                 header.set_recursion_available(true);
                 header.set_response_code(msg.response_code());

                 let answers = msg.answers();
                 let name_servers = msg.name_servers();
                 let additionals = msg.additionals();

                 let response = builder.build(header, answers.iter(), name_servers.iter(), std::iter::empty(), additionals.iter());

                 if let Err(e) = response_handle.send_response(response).await {
                     log::error!("Failed to send response: {}", e);
                 }
            }
            Err(e) => {
                log::error!("Resolution failed for {}: {}", name, e);
                // Send ServFail
                let builder = MessageResponseBuilder::from_message_request(request);
                let mut header = Header::response_from_request(request.header());
                header.set_recursion_available(true);
                header.set_response_code(ResponseCode::ServFail);
                let response = builder.build(header, std::iter::empty(), std::iter::empty(), std::iter::empty(), std::iter::empty());

                let _ = response_handle.send_response(response).await;
                self.metrics.record_response_code("SERVFAIL");
            }
        }

        let latency = start_time.elapsed();
        self.metrics.record_latency(&name, latency);

        // Return generic info, real info was sent via response_handle
        ResponseInfo::from(Header::response_from_request(request.header()))
    }
}

impl Server {
    pub fn new(
        config: Config,
        metrics: Arc<Metrics>,
        resolver: Arc<Box<dyn Resolver>>,
        pm: Arc<PluginManager>,
        protection: Arc<Protection>,
    ) -> Self {
        Server {
            config,
            metrics,
            resolver,
            pm,
            protection,
        }
    }

    pub async fn listen_and_serve(&self) -> anyhow::Result<()> {
        log::info!("DNS Server listening on {}", self.config.listen_addr);

        let handler = Handler {
            metrics: self.metrics.clone(),
            resolver: self.resolver.clone(),
            pm: self.pm.clone(),
            protection: self.protection.clone(),
        };

        let mut server = ServerFuture::new(handler);

        // Register UDP
        let udp_socket = UdpSocket::bind(&self.config.listen_addr).await?;
        server.register_socket(udp_socket);

        // Register TCP
        let tcp_listener = TcpListener::bind(&self.config.listen_addr).await?;
        server.register_listener(tcp_listener, Duration::from_secs(5));

        // register DNS-over-TLS
        if self.config.dot.enabled {
            log::info!("Enabling DNS-over-TLS on {}", self.config.dot.listen_addr);
            let certs = load_certs(&self.config.dot.cert_file)?;
            let key = load_private_key(&self.config.dot.key_file)?;
            
            let tcp_listener = TcpListener::bind(&self.config.dot.listen_addr).await?;
            server.register_tls_listener(tcp_listener, Duration::from_secs(5), (certs, key));
        }

        // register DNS-over-HTTPS
        if self.config.doh.enabled {
             log::info!("Enabling DNS-over-HTTPS on {}", self.config.doh.listen_addr);
             let certs = load_certs(&self.config.doh.cert_file)?;
             let key = load_private_key(&self.config.doh.key_file)?;
            
             let tcp_listener = TcpListener::bind(&self.config.doh.listen_addr).await?;
             // register_https_listener(listener, duration, (certs, key), dns_hostname)
             server.register_https_listener(tcp_listener, Duration::from_secs(5), (certs, key), None);
        }


        server.block_until_done().await?;

        Ok(())
    }
}

// Helpers for Rustls
use std::fs::File;
use std::io::BufReader;
use rustls::{Certificate, PrivateKey};

fn load_certs(path: &str) -> anyhow::Result<Vec<Certificate>> {
    let certfile = File::open(path).map_err(|e| anyhow::anyhow!("Failed to open cert file {}: {}", path, e))?;
    let mut reader = BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|e| anyhow::anyhow!("Failed to read certs: {:?}", e))?;
    
    Ok(certs.into_iter().map(Certificate).collect())
}

fn load_private_key(path: &str) -> anyhow::Result<PrivateKey> {
    let keyfile = File::open(path).map_err(|e| anyhow::anyhow!("Failed to open key file {}: {}", path, e))?;
    let mut reader = BufReader::new(keyfile);

    // Try PKCS8 first
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
         .map_err(|e| anyhow::anyhow!("Failed to read PKCS8 keys: {:?}", e))?;
    
    if !keys.is_empty() {
        return Ok(PrivateKey(keys[0].clone()));
    }
    
    // Rewind and try RSA
    let keyfile = File::open(path)?;
    let mut reader = BufReader::new(keyfile);
    let keys = rustls_pemfile::rsa_private_keys(&mut reader)
         .map_err(|e| anyhow::anyhow!("Failed to read RSA keys: {:?}", e))?;

    if !keys.is_empty() {
        return Ok(PrivateKey(keys[0].clone()));
    }

    Err(anyhow::anyhow!("No private key found in {}", path))
}
