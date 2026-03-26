use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use base64::Engine as _;
use http::{Method, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper::{body::Bytes, service::service_fn, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time,
};

use crate::{
    blocklist_remote::BlocklistRemote,
    cache::DnsCache,
    config::{SecurityConfig, TlsConfig},
    hosts_remote::HostsRemote,
    proxy::{forward_candidates, maybe_refuse},
    tls,
    upstream::{Balancer, UpstreamSet},
};

pub struct DotServer {
    listen: SocketAddr,
    listener: TcpListener,
    tls: TlsConfig,
    upstreams: Arc<UpstreamSet>,
    balancer: Arc<Balancer>,
    security: SecurityConfig,
    hosts: Option<Arc<HostsRemote>>,
    blocklist: Option<Arc<BlocklistRemote>>,
    cache: Option<Arc<DnsCache>>,
    request_timeout: Duration,
}

pub struct DohServer {
    listen: SocketAddr,
    listener: TcpListener,
    tls: TlsConfig,
    upstreams: Arc<UpstreamSet>,
    balancer: Arc<Balancer>,
    security: SecurityConfig,
    hosts: Option<Arc<HostsRemote>>,
    blocklist: Option<Arc<BlocklistRemote>>,
    cache: Option<Arc<DnsCache>>,
    request_timeout: Duration,
}

impl DotServer {
    pub async fn new(
        listen: SocketAddr,
        tls: TlsConfig,
        upstreams: Arc<UpstreamSet>,
        balancer: Arc<Balancer>,
        security: SecurityConfig,
        hosts: Option<Arc<HostsRemote>>,
        blocklist: Option<Arc<BlocklistRemote>>,
        cache: Option<Arc<DnsCache>>,
    ) -> anyhow::Result<Self> {
        let request_timeout = Duration::from_millis(security.request_timeout_ms);
        let listener = TcpListener::bind(listen).await?;
        let listen = listener.local_addr()?;
        Ok(Self {
            listen,
            listener,
            tls,
            upstreams,
            balancer,
            security,
            hosts,
            blocklist,
            cache,
            request_timeout,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.listen
    }

    pub async fn run(self) -> anyhow::Result<()> {
        tracing::info!(listen = %self.listen, "dot listening");

        let acceptor = tls::server_tls_acceptor(
            &PathBuf::from(self.tls.cert_pem),
            &PathBuf::from(self.tls.key_pem),
        )?;

        loop {
            let (stream, peer) = self.listener.accept().await?;
            let acceptor = acceptor.clone();
            let upstreams = self.upstreams.clone();
            let balancer = self.balancer.clone();
            let security = self.security.clone();
            let hosts = self.hosts.clone();
            let blocklist = self.blocklist.clone();
            let cache = self.cache.clone();
            let timeout = self.request_timeout;

            tokio::spawn(async move {
                if let Err(err) = handle_dot_conn(
                    stream,
                    peer,
                    acceptor,
                    upstreams,
                    balancer,
                    security,
                    hosts,
                    blocklist,
                    cache,
                    timeout,
                )
                .await
                {
                    tracing::debug!(peer = %peer, error = %err, "dot conn failed");
                }
            });
        }
    }

}

impl DohServer {
    pub async fn new(
        listen: SocketAddr,
        tls: TlsConfig,
        upstreams: Arc<UpstreamSet>,
        balancer: Arc<Balancer>,
        security: SecurityConfig,
        hosts: Option<Arc<HostsRemote>>,
        blocklist: Option<Arc<BlocklistRemote>>,
        cache: Option<Arc<DnsCache>>,
    ) -> anyhow::Result<Self> {
        let request_timeout = Duration::from_millis(security.request_timeout_ms);
        let listener = TcpListener::bind(listen).await?;
        let listen = listener.local_addr()?;
        Ok(Self {
            listen,
            listener,
            tls,
            upstreams,
            balancer,
            security,
            hosts,
            blocklist,
            cache,
            request_timeout,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.listen
    }

    pub async fn run(self) -> anyhow::Result<()> {
        tracing::info!(listen = %self.listen, "doh listening");

        let acceptor = tls::server_tls_acceptor(
            &PathBuf::from(self.tls.cert_pem),
            &PathBuf::from(self.tls.key_pem),
        )?;

        loop {
            let (stream, peer) = self.listener.accept().await?;
            let acceptor = acceptor.clone();
            let upstreams = self.upstreams.clone();
            let balancer = self.balancer.clone();
            let security = self.security.clone();
            let hosts = self.hosts.clone();
            let blocklist = self.blocklist.clone();
            let cache = self.cache.clone();
            let timeout = self.request_timeout;
            tokio::spawn(async move {
                if let Err(err) = handle_doh_conn(stream, peer, acceptor, upstreams, balancer, security, hosts, blocklist, cache, timeout).await {
                    tracing::debug!(peer = %peer, error = %err, "doh conn failed");
                }
            });
        }
    }
}

async fn handle_dot_conn(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    upstreams: Arc<UpstreamSet>,
    balancer: Arc<Balancer>,
    security: SecurityConfig,
    hosts: Option<Arc<HostsRemote>>,
    blocklist: Option<Arc<BlocklistRemote>>,
    cache: Option<Arc<DnsCache>>,
    timeout: Duration,
) -> anyhow::Result<()> {
    let mut tls = acceptor.accept(stream).await?;

    loop {
        let mut len_buf = [0u8; 2];
        if tls.read_exact(&mut len_buf).await.is_err() {
            return Ok(());
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 4096 {
            return Ok(());
        }
        let mut msg = vec![0u8; len];
        tls.read_exact(&mut msg).await?;
        metrics::counter!("dns_requests_total", "proto" => "dot").increment(1);

        if let Some(resp) = maybe_refuse(&msg, &security) {
            metrics::counter!("dns_denied_total", "proto" => "dot").increment(1);
            tls.write_all(&(resp.len() as u16).to_be_bytes()).await?;
            tls.write_all(&resp).await?;
            continue;
        }

        if let Some(hosts) = &hosts {
            if let Some(resp) = hosts.maybe_answer(&msg) {
                metrics::counter!("dns_hosts_hits_total", "proto" => "dot").increment(1);
                tls.write_all(&(resp.len() as u16).to_be_bytes()).await?;
                tls.write_all(&resp).await?;
                continue;
            }
        }

        if let Some(bl) = &blocklist {
            if bl.is_blocked(&msg) {
                if let Some(resp) = crate::dns::build_nxdomain_response(&msg) {
                    metrics::counter!("dns_blocked_total", "proto" => "dot").increment(1);
                    tls.write_all(&(resp.len() as u16).to_be_bytes()).await?;
                    tls.write_all(&resp).await?;
                    continue;
                }
            }
        }

        // Проверка кэша
        if let Some(cache) = &cache {
            if let Some((domain, qtype, _qclass)) = crate::dns::read_qname_qtype_qclass(&msg) {
                if let Some(cached_resp) = cache.get(&domain, qtype) {
                    metrics::counter!("dns_cache_hits_total", "proto" => "dot").increment(1);
                    let mut resp = cached_resp;
                    if let Some(orig_id) = crate::dns::read_id(&msg) {
                        crate::dns::write_id(&mut resp, orig_id);
                    }
                    tls.write_all(&(resp.len() as u16).to_be_bytes()).await?;
                    tls.write_all(&resp).await?;
                    continue;
                }
            }
        }

        let client_ip = Some(peer.ip());
        let candidates = upstreams.candidates("default", &balancer, client_ip);
        if candidates.is_empty() {
            return Err(anyhow::anyhow!("no upstream"));
        }

        let start = Instant::now();
        match forward_candidates(&candidates, &msg, timeout).await {
            Ok((upstream, resp, _upstream_proto)) => {
                // Сохраняем в кэш
                if let Some(cache) = &cache {
                    if let Some((domain, qtype, _qclass)) = crate::dns::read_qname_qtype_qclass(&msg) {
                        let ttl = extract_ttl_from_response(&resp).unwrap_or(Duration::from_secs(300));
                        cache.set(&domain, qtype, resp.clone(), ttl);
                    }
                }
                
                observe_latency("dot", &upstream.name, start);
                tls.write_all(&(resp.len() as u16).to_be_bytes()).await?;
                tls.write_all(&resp).await?;
            }
            Err(err) => {
                metrics::counter!("dns_upstream_errors_total", "proto" => "dot").increment(1);
                return Err(err);
            }
        }
    }
}

async fn handle_doh_conn(
    stream: TcpStream,
    _peer: SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    upstreams: Arc<UpstreamSet>,
    balancer: Arc<Balancer>,
    security: SecurityConfig,
    hosts: Option<Arc<HostsRemote>>,
    blocklist: Option<Arc<BlocklistRemote>>,
    cache: Option<Arc<DnsCache>>,
    timeout: Duration,
) -> anyhow::Result<()> {
    let tls_stream = acceptor.accept(stream).await?;
    let io = TokioIo::new(tls_stream);

    let service = service_fn(move |req| {
        let upstreams = upstreams.clone();
        let balancer = balancer.clone();
        let security = security.clone();
        let hosts = hosts.clone();
        let blocklist = blocklist.clone();
        let cache = cache.clone();
        async move {
            Ok::<_, std::convert::Infallible>(
                handle_doh_request(req, upstreams, balancer, security, hosts, blocklist, cache, timeout).await,
            )
        }
    });

    hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(io, service)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    Ok(())
}

async fn handle_doh_request(
    req: Request<hyper::body::Incoming>,
    upstreams: Arc<UpstreamSet>,
    balancer: Arc<Balancer>,
    security: SecurityConfig,
    hosts: Option<Arc<HostsRemote>>,
    blocklist: Option<Arc<BlocklistRemote>>,
    cache: Option<Arc<DnsCache>>,
    timeout: Duration,
) -> Response<Full<Bytes>> {
    let (parts, body) = req.into_parts();
    if parts.uri.path() != "/dns-query" {
        return response(StatusCode::NOT_FOUND, Bytes::new());
    }

    let query = match parts.method {
        Method::POST => match time::timeout(timeout, body.collect()).await {
            Ok(Ok(collected)) => collected.to_bytes().to_vec(),
            Ok(Err(_)) => return response(StatusCode::BAD_REQUEST, Bytes::new()),
            Err(_) => return response(StatusCode::REQUEST_TIMEOUT, Bytes::new()),
        },
        Method::GET => {
            let Some(dns_param) = parts
                .uri
                .query()
                .and_then(|q| q.split('&').find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == "dns").map(|(_, v)| v)))
            else {
                return response(StatusCode::BAD_REQUEST, Bytes::new());
            };

            match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(dns_param.as_bytes()) {
                Ok(decoded) => decoded,
                Err(_) => return response(StatusCode::BAD_REQUEST, Bytes::new()),
            }
        }
        _ => return response(StatusCode::METHOD_NOT_ALLOWED, Bytes::new()),
    };

    if query.len() < 12 {
        return response(StatusCode::BAD_REQUEST, Bytes::new());
    }

    metrics::counter!("dns_requests_total", "proto" => "doh").increment(1);

    if let Some(resp) = maybe_refuse(&query, &security) {
        metrics::counter!("dns_denied_total", "proto" => "doh").increment(1);
        return response_dns(resp);
    }

    if let Some(hosts) = &hosts {
        if let Some(resp) = hosts.maybe_answer(&query) {
            metrics::counter!("dns_hosts_hits_total", "proto" => "doh").increment(1);
            return response_dns(resp);
        }
    }

    if let Some(bl) = &blocklist {
        if bl.is_blocked(&query) {
            if let Some(resp) = crate::dns::build_nxdomain_response(&query) {
                metrics::counter!("dns_blocked_total", "proto" => "doh").increment(1);
                return response_dns(resp);
            }
        }
    }

    // Проверка кэша
    if let Some(cache) = &cache {
        if let Some((domain, qtype, _qclass)) = crate::dns::read_qname_qtype_qclass(&query) {
            if let Some(cached_resp) = cache.get(&domain, qtype) {
                metrics::counter!("dns_cache_hits_total", "proto" => "doh").increment(1);
                return response_dns(cached_resp);
            }
        }
    }

    let candidates = upstreams.candidates("default", &balancer, None);
    if candidates.is_empty() {
        return response(StatusCode::BAD_GATEWAY, Bytes::new());
    }

    let start = Instant::now();
    match forward_candidates(&candidates, &query, timeout).await {
        Ok((upstream, resp, _upstream_proto)) => {
            // Сохраняем в кэш
            if let Some(cache) = &cache {
                if let Some((domain, qtype, _qclass)) = crate::dns::read_qname_qtype_qclass(&query) {
                    let ttl = extract_ttl_from_response(&resp).unwrap_or(Duration::from_secs(300));
                    cache.set(&domain, qtype, resp.clone(), ttl);
                }
            }
            
            observe_latency("doh", &upstream.name, start);
            response_dns(resp)
        }
        Err(_) => {
            metrics::counter!("dns_upstream_errors_total", "proto" => "doh").increment(1);
            response(StatusCode::BAD_GATEWAY, Bytes::new())
        }
    }
}

fn response(status: StatusCode, body: Bytes) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-length", body.len().to_string())
        .body(Full::new(body))
        .unwrap()
}

fn response_dns(body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/dns-message")
        .header("content-length", body.len().to_string())
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn observe_latency(proto: &'static str, upstream_name: &Arc<str>, start: Instant) {
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    let upstream_label = upstream_name.to_string();
    metrics::histogram!(
        "dns_upstream_latency_ms",
        "proto" => proto,
        "upstream" => upstream_label
    )
    .record(latency_ms);
}

/// Извлекает TTL из DNS-ответа
fn extract_ttl_from_response(packet: &[u8]) -> Option<Duration> {
    if packet.len() < 12 {
        return None;
    }
    
    // Пропускаем заголовок (12 байт) и вопрос
    let offset = 12;
    let offset = crate::dns::skip_name(packet, offset)?;
    let offset = offset + 4; // QTYPE (2) + QCLASS (2)
    
    // Пропускаем секцию ответа для получения TTL первого RR
    let offset = crate::dns::skip_name(packet, offset)?;
    let offset = offset + 4; // TYPE + CLASS
    
    // Читаем TTL (4 байта)
    let ttl_bytes = [
        *packet.get(offset)?,
        *packet.get(offset + 1)?,
        *packet.get(offset + 2)?,
        *packet.get(offset + 3)?,
    ];
    let ttl_secs = u32::from_be_bytes(ttl_bytes);
    
    Some(Duration::from_secs(ttl_secs as u64))
}
