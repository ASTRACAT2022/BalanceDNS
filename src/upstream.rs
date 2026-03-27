use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering, AtomicUsize},
        Arc,
    },
    time::Duration,
};

use rand::Rng as _;
use reqwest::Url;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time,
};
use tokio_rustls::TlsConnector;
use trust_dns_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
};

use crate::config::{BalancingAlgorithm, UpstreamConfig, UpstreamProto};
use crate::dispatcher::ResponseDispatcher;
use crate::dns;

pub struct UpstreamSet {
    upstreams: Vec<Upstream>,
    transport: Arc<TransportContext>,
    udp_pool: Vec<PooledSocket>,
    next_socket: AtomicUsize,
    pub dispatcher: Arc<ResponseDispatcher>,
}

pub struct PooledSocket {
    pub id: usize,
    pub socket: Arc<UdpSocket>,
}

#[derive(Clone)]
pub struct UpstreamRef {
    pub name: Arc<str>,
    pub pool: Arc<str>,
    pub endpoint: UpstreamEndpointRef,
    pub transport: Arc<TransportContext>,
    pub weight: u32,
    pub udp_socket: Option<Arc<PooledSocket>>,
}

struct Upstream {
    name: Arc<str>,
    pool: Arc<str>,
    endpoint: UpstreamEndpoint,
    alive: AtomicBool,
    consecutive_failures: AtomicU64,
    weight: u32,
}

#[derive(Clone, Debug)]
pub enum UpstreamEndpointRef {
    Udp { addr: SocketAddr },
    Tcp { addr: SocketAddr },
    Dot {
        addr: SocketAddr,
        server_name: Arc<str>,
        tls_insecure: bool,
    },
    Doh { url: Arc<str>, tls_insecure: bool },
}

enum UpstreamEndpoint {
    Udp { addr: SocketAddr },
    Tcp { addr: SocketAddr },
    Dot {
        addr: SocketAddr,
        server_name: Arc<str>,
        tls_insecure: bool,
    },
    Doh { url: Arc<str>, tls_insecure: bool },
}

pub struct TransportContext {
    pub doh: reqwest::Client,
    pub doh_insecure: reqwest::Client,
    pub tls: Arc<rustls::ClientConfig>,
    pub tls_insecure: Arc<rustls::ClientConfig>,
}

impl UpstreamSet {
    pub fn new(configs: Vec<UpstreamConfig>) -> anyhow::Result<Self> {
        crate::tls::ensure_rustls_crypto_provider();
        if configs.is_empty() {
            return Err(anyhow::anyhow!("no upstreams configured"));
        }

        let transport = Arc::new(TransportContext {
            doh: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(3))
                .http2_adaptive_window(true)
                .http2_keep_alive_interval(Duration::from_secs(15))
                .http2_keep_alive_timeout(Duration::from_secs(10))
                .http2_keep_alive_while_idle(true)
                .tcp_keepalive(Duration::from_secs(30))
                .pool_idle_timeout(Duration::from_secs(30))
                .pool_max_idle_per_host(32)
                .build()?,
            doh_insecure: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(3))
                .http2_adaptive_window(true)
                .http2_keep_alive_interval(Duration::from_secs(15))
                .http2_keep_alive_timeout(Duration::from_secs(10))
                .http2_keep_alive_while_idle(true)
                .tcp_keepalive(Duration::from_secs(30))
                .pool_idle_timeout(Duration::from_secs(30))
                .pool_max_idle_per_host(32)
                .danger_accept_invalid_certs(true)
                .build()?,
            tls: Arc::new(build_rustls_config()?),
            tls_insecure: Arc::new(build_insecure_rustls_config()?),
        });

        let upstreams = configs
            .into_iter()
            .map(|c| {
                let endpoint = parse_upstream_endpoint(&c)?;
                Ok(Upstream {
                    name: Arc::from(c.name),
                    pool: Arc::from(c.pool),
                    endpoint,
                    alive: AtomicBool::new(true),
                    consecutive_failures: AtomicU64::new(0),
                    weight: c.weight.max(1),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(Self {
            upstreams,
            transport,
            udp_pool: Vec::new(),
            next_socket: AtomicUsize::new(0),
            dispatcher: Arc::new(ResponseDispatcher::new()),
        })
    }

    pub async fn init_udp_pool(&mut self, count: u16) -> anyhow::Result<()> {
        let mut pool = Vec::with_capacity(count as usize);
        for i in 0..count {
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            let socket = Arc::new(socket);
            pool.push(PooledSocket {
                id: i as usize,
                socket: socket.clone(),
            });

            // Spawn listener task for this socket
            let dispatcher = self.dispatcher.clone();
            let socket_id = i as usize;
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match socket.recv_from(&mut buf).await {
                        Ok((n, addr)) => {
                            dispatcher.dispatch(socket_id, addr, &buf[..n]);
                        }
                        Err(e) => {
                            tracing::error!("UDP pool socket error: {}", e);
                            break;
                        }
                    }
                }
            });
        }
        self.udp_pool = pool;
        Ok(())
    }

    pub fn get_pooled_socket(&self) -> Option<Arc<PooledSocket>> {
        if self.udp_pool.is_empty() {
            return None;
        }
        let idx = self.next_socket.fetch_add(1, Ordering::Relaxed) % self.udp_pool.len();
        Some(Arc::new(PooledSocket {
            id: self.udp_pool[idx].id,
            socket: self.udp_pool[idx].socket.clone(),
        }))
    }

    pub fn candidates(&self, pool: &str, balancer: &Balancer, domain: Option<&str>, client_ip: Option<IpAddr>) -> Vec<UpstreamRef> {
        let alive_indices: Vec<usize> = self
            .upstreams
            .iter()
            .enumerate()
            .filter(|(_, u)| u.pool.as_ref() == pool)
            .filter(|(_, u)| u.alive.load(Ordering::Relaxed))
            .map(|(idx, _)| idx)
            .collect();

        let unhealthy_indices: Vec<usize> = self
            .upstreams
            .iter()
            .enumerate()
            .filter(|(_, u)| u.pool.as_ref() == pool)
            .filter(|(_, u)| !u.alive.load(Ordering::Relaxed))
            .map(|(idx, _)| idx)
            .collect();

        let mut eligible = Vec::with_capacity(alive_indices.len() + unhealthy_indices.len());

        if !alive_indices.is_empty() {
            let weights: Vec<u32> = alive_indices.iter().map(|&i| self.upstreams[i].weight).collect();
            eligible.extend(ordered_candidates_weighted(&alive_indices, &weights, balancer, domain, client_ip));
        }

        if !unhealthy_indices.is_empty() {
            let weights: Vec<u32> = unhealthy_indices.iter().map(|&i| self.upstreams[i].weight).collect();
            eligible.extend(ordered_candidates_weighted(&unhealthy_indices, &weights, balancer, domain, client_ip));
        }

        if eligible.is_empty() {
            return Vec::new();
        }

        eligible.into_iter().map(|idx| self.make_ref(idx)).collect()
    }

    pub async fn forward_candidates(
        &self,
        candidates: &[UpstreamRef],
        query: &[u8],
        timeout: Duration,
    ) -> anyhow::Result<(UpstreamRef, Vec<u8>, &'static str)> {
        if candidates.is_empty() {
            return Err(anyhow::anyhow!("no upstream candidates"));
        }

        let mut tasks = tokio::task::JoinSet::new();
        // EdgeDNS approach: try top candidates
        for candidate in candidates.iter().take(3).cloned() {
            let query = query.to_vec();
            let dispatcher = self.dispatcher.clone();
            tasks.spawn(async move {
                let result = forward_candidate(&candidate, &query, timeout, dispatcher).await;
                (candidate, result)
            });
        }

        let mut last_error = None;
        let mut first_negative_resp = None;

        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((candidate, Ok((resp, upstream_proto)))) => {
                    if is_positive_response(&resp) {
                        tasks.abort_all();
                        return Ok((candidate, resp, upstream_proto));
                    } else if is_valid_response(&resp) && first_negative_resp.is_none() {
                        first_negative_resp = Some((candidate, resp, upstream_proto));
                    }
                }
                Ok((candidate, Err(err))) => {
                    tracing::debug!(upstream = %candidate.name, error = %err, "upstream attempt failed");
                    last_error = Some(err);
                }
                Err(err) => {
                    last_error = Some(anyhow::anyhow!("upstream task failed: {}", err));
                }
            }
        }

        if let Some(neg) = first_negative_resp {
            return Ok(neg);
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no upstream candidates")))
    }

    fn make_ref(&self, idx: usize) -> UpstreamRef {
        let u = &self.upstreams[idx];
        UpstreamRef {
            name: u.name.clone(),
            pool: u.pool.clone(),
            endpoint: u.endpoint.as_ref(),
            transport: self.transport.clone(),
            weight: u.weight,
            udp_socket: self.get_pooled_socket(),
        }
    }

    pub async fn healthcheck_loop(self: Arc<Self>, interval: Duration) {
        let mut ticker = time::interval(interval);
        loop {
            ticker.tick().await;
            self.run_healthchecks(Duration::from_millis(2500)).await;
        }
    }

    async fn run_healthchecks(&self, timeout: Duration) {
        let query = build_healthcheck_query();
        let mut tasks = tokio::task::JoinSet::new();

        for u in &self.upstreams {
            let query = query.clone();
            let transport = self.transport.clone();
            let name = u.name.clone();
            let endpoint = u.endpoint.as_ref();

            tasks.spawn(async move {
                let ok = match tokio::time::timeout(timeout, probe_endpoint(&endpoint, &transport, &query)).await {
                    Ok(Ok(())) => true,
                    _ => false,
                };
                (name, ok)
            });
        }

        while let Some(res) = tasks.join_next().await {
            if let Ok((name, ok)) = res {
                let Some(u) = self.upstreams.iter().find(|u| u.name == name) else {
                    continue;
                };

                let prev = u.alive.load(Ordering::Relaxed);
                let (alive, failures) = update_health_state(prev, &u.consecutive_failures, ok);
                u.alive.store(alive, Ordering::Relaxed);

                metrics::gauge!("dns_upstream_alive", "upstream" => name.to_string())
                    .set(if alive { 1.0 } else { 0.0 });

                if prev != alive {
                    metrics::counter!(
                        "dns_upstream_health_changes_total",
                        "upstream" => name.to_string(),
                        "alive" => if alive { "true" } else { "false" }
                    )
                    .increment(1);
                    tracing::warn!(upstream = %name, alive = alive, failures = failures, "upstream health changed");
                }
            }
        }
    }
}

async fn forward_candidate(
    candidate: &UpstreamRef,
    query: &[u8],
    timeout: Duration,
    dispatcher: Arc<ResponseDispatcher>,
) -> anyhow::Result<(Vec<u8>, &'static str)> {
    match &candidate.endpoint {
        UpstreamEndpointRef::Udp { addr } => {
            let resp = forward_udp_once(*addr, query, timeout, candidate.udp_socket.clone(), dispatcher).await?;
            if dns::is_truncated_response(&resp) {
                let tcp_resp = forward_tcp_once(*addr, query, timeout).await?;
                return Ok((tcp_resp, "tcp"));
            }
            Ok((resp, "udp"))
        }
        UpstreamEndpointRef::Tcp { addr } => Ok((forward_tcp_once(*addr, query, timeout).await?, "tcp")),
        UpstreamEndpointRef::Dot {
            addr,
            server_name,
            tls_insecure,
        } => Ok((
            forward_dot_once(&candidate.transport, *addr, server_name, *tls_insecure, query, timeout).await?,
            "dot",
        )),
        UpstreamEndpointRef::Doh { url, tls_insecure } => Ok((
            forward_doh_once(&candidate.transport, url, *tls_insecure, query, timeout).await?,
            "doh",
        )),
    }
}

async fn forward_udp_once(
    addr: SocketAddr,
    query: &[u8],
    timeout: Duration,
    udp_socket: Option<Arc<PooledSocket>>,
    dispatcher: Arc<ResponseDispatcher>,
) -> anyhow::Result<Vec<u8>> {
    if let Some(pooled) = udp_socket {
        let tid = dns::read_id(query).ok_or_else(|| anyhow::anyhow!("invalid query id"))?;
        let rx = dispatcher.register(pooled.id, addr, tid);
        pooled.socket.send_to(query, addr).await?;

        match time::timeout(timeout, rx).await {
            Ok(Ok(resp)) => return Ok(resp),
            Ok(Err(_)) => return Err(anyhow::anyhow!("dispatcher error")),
            Err(_) => {
                dispatcher.unregister(pooled.id, addr, tid);
                return Err(anyhow::anyhow!("upstream timeout"));
            }
        }
    }

    let bind_addr = match addr {
        SocketAddr::V4(v4) if v4.ip().is_loopback() => "127.0.0.1:0",
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(v6) if v6.ip().is_loopback() => "[::1]:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let sock = UdpSocket::bind(bind_addr).await?;
    sock.connect(addr).await?;
    time::timeout(timeout, sock.send(query)).await??;
    let mut buf = vec![0u8; 4096];
    let n = time::timeout(timeout, sock.recv(&mut buf)).await??;
    buf.truncate(n);
    Ok(buf)
}

async fn forward_tcp_once(addr: SocketAddr, query: &[u8], timeout: Duration) -> anyhow::Result<Vec<u8>> {
    let mut conn = time::timeout(timeout, TcpStream::connect(addr)).await??;
    conn.write_all(&(query.len() as u16).to_be_bytes()).await?;
    conn.write_all(query).await?;
    read_tcp_response(&mut conn, timeout).await
}

async fn forward_dot_once(
    transport: &TransportContext,
    addr: SocketAddr,
    server_name: &Arc<str>,
    tls_insecure: bool,
    query: &[u8],
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    let tcp = time::timeout(timeout, TcpStream::connect(addr)).await??;
    let name = rustls::pki_types::ServerName::try_from(server_name.to_string())?;
    let connector = if tls_insecure {
        TlsConnector::from(transport.tls_insecure.clone())
    } else {
        TlsConnector::from(transport.tls.clone())
    };
    let mut tls = time::timeout(timeout, connector.connect(name, tcp)).await??;
    tls.write_all(&(query.len() as u16).to_be_bytes()).await?;
    tls.write_all(query).await?;
    read_tcp_response(&mut tls, timeout).await
}

async fn forward_doh_once(
    transport: &TransportContext,
    url: &Arc<str>,
    tls_insecure: bool,
    query: &[u8],
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    let url = Url::parse(url.as_ref())?;
    let client = if tls_insecure {
        &transport.doh_insecure
    } else {
        &transport.doh
    };
    let resp = time::timeout(
        timeout,
        client
            .post(url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(query.to_vec())
            .send(),
    )
    .await??;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("http status {}", resp.status()));
    }
    let bytes = time::timeout(timeout, resp.bytes()).await??;
    Ok(bytes.to_vec())
}

async fn read_tcp_response<S>(stream: &mut S, timeout: Duration) -> anyhow::Result<Vec<u8>>
where
    S: AsyncReadExt + Unpin,
{
    let mut resp_len_buf = [0u8; 2];
    time::timeout(timeout, stream.read_exact(&mut resp_len_buf)).await??;
    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
    if resp_len == 0 || resp_len > 65535 {
        return Err(anyhow::anyhow!("invalid upstream tcp length"));
    }
    let mut resp = vec![0u8; resp_len];
    time::timeout(timeout, stream.read_exact(&mut resp)).await??;
    Ok(resp)
}

fn is_positive_response(packet: &[u8]) -> bool {
    if packet.len() < 4 {
        return false;
    }
    let rcode = packet[3] & 0x0F;
    rcode == 0
}

fn is_valid_response(packet: &[u8]) -> bool {
    if packet.len() < 4 {
        return false;
    }
    let rcode = packet[3] & 0x0F;
    rcode == 0 || rcode == 3
}

pub struct Balancer {
    algorithm: BalancingAlgorithm,
    rr: AtomicU64,
    jumphasher: jumphash::JumpHasher,
}

impl Balancer {
    pub fn new(algorithm: BalancingAlgorithm) -> Self {
        Self {
            algorithm,
            rr: AtomicU64::new(0),
            jumphasher: jumphash::JumpHasher::new(),
        }
    }

    pub fn pick_weighted(&self, indices: &[usize], weights: &[u32], domain: Option<&str>) -> usize {
        match self.algorithm {
            BalancingAlgorithm::RoundRobin => {
                let total_weight: u32 = weights.iter().sum();
                if total_weight == 0 {
                    return indices[0];
                }
                let count = self.rr.fetch_add(1, Ordering::Relaxed);
                let mut val = (count % total_weight as u64) as u32;

                for (i, &weight) in weights.iter().enumerate() {
                    if val < weight {
                        return indices[i];
                    }
                    val -= weight;
                }
                indices[0]
            }
            BalancingAlgorithm::JumpHash => {
                let key = domain.unwrap_or("");
                let idx = self.jumphasher.slot(&key, indices.len() as u32) as usize;
                indices[idx]
            }
        }
    }
}

fn build_healthcheck_query() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let id: u16 = rng.r#gen();
    let name = Name::from_ascii("example.com.").unwrap_or_else(|_| Name::root());

    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.add_query(Query::query(name, RecordType::A));
    msg.set_recursion_desired(true);
    msg.to_vec().unwrap_or_default()
}

fn update_health_state(prev_alive: bool, failures: &AtomicU64, probe_ok: bool) -> (bool, u64) {
    if probe_ok {
        failures.store(0, Ordering::Relaxed);
        return (true, 0);
    }

    let failure_count = failures.fetch_add(1, Ordering::Relaxed) + 1;
    if prev_alive && failure_count < 3 {
        return (true, failure_count);
    }

    (false, failure_count)
}

fn ordered_candidates_weighted(
    indices: &[usize],
    weights: &[u32],
    balancer: &Balancer,
    domain: Option<&str>,
    _client_ip: Option<IpAddr>,
) -> Vec<usize> {
    if indices.is_empty() {
        return Vec::new();
    }

    let start_idx = balancer.pick_weighted(indices, weights, domain);
    let start_pos = indices.iter().position(|idx| *idx == start_idx).unwrap_or(0);

    indices
        .iter()
        .cycle()
        .skip(start_pos)
        .take(indices.len())
        .copied()
        .collect()
}

fn parse_upstream_endpoint(cfg: &UpstreamConfig) -> anyhow::Result<UpstreamEndpoint> {
    match cfg.proto {
        UpstreamProto::Udp => {
            let addr = cfg.addr.ok_or_else(|| anyhow::anyhow!("upstream {}: missing addr", cfg.name))?;
            Ok(UpstreamEndpoint::Udp { addr })
        }
        UpstreamProto::Tcp => {
            let addr = cfg.addr.ok_or_else(|| anyhow::anyhow!("upstream {}: missing addr", cfg.name))?;
            Ok(UpstreamEndpoint::Tcp { addr })
        }
        UpstreamProto::Dot => {
            let addr = cfg.addr.ok_or_else(|| anyhow::anyhow!("upstream {}: missing addr", cfg.name))?;
            let server_name = cfg
                .server_name
                .clone()
                .ok_or_else(|| anyhow::anyhow!("upstream {}: missing server_name", cfg.name))?;
            Ok(UpstreamEndpoint::Dot {
                addr,
                server_name: Arc::from(server_name),
                tls_insecure: cfg.tls_insecure,
            })
        }
        UpstreamProto::Doh => {
            let url = cfg
                .url
                .clone()
                .ok_or_else(|| anyhow::anyhow!("upstream {}: missing url", cfg.name))?;
            let _ = Url::parse(&url)
                .map_err(|e| anyhow::anyhow!("upstream {}: invalid url: {}", cfg.name, e))?;
            Ok(UpstreamEndpoint::Doh {
                url: Arc::from(url),
                tls_insecure: cfg.tls_insecure,
            })
        }
    }
}

impl UpstreamEndpoint {
    fn as_ref(&self) -> UpstreamEndpointRef {
        match self {
            UpstreamEndpoint::Udp { addr } => UpstreamEndpointRef::Udp { addr: *addr },
            UpstreamEndpoint::Tcp { addr } => UpstreamEndpointRef::Tcp { addr: *addr },
            UpstreamEndpoint::Dot {
                addr,
                server_name,
                tls_insecure,
            } => UpstreamEndpointRef::Dot {
                addr: *addr,
                server_name: server_name.clone(),
                tls_insecure: *tls_insecure,
            },
            UpstreamEndpoint::Doh { url, tls_insecure } => UpstreamEndpointRef::Doh {
                url: url.clone(),
                tls_insecure: *tls_insecure,
            },
        }
    }
}

fn build_rustls_config() -> anyhow::Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    if let Ok(certs) = native {
        for cert in certs {
            let _ = roots.add(cert);
        }
    }

    if roots.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(cfg)
}

fn build_insecure_rustls_config() -> anyhow::Result<rustls::ClientConfig> {
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    cfg.dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification));
    Ok(cfg)
}

async fn probe_endpoint(
    endpoint: &UpstreamEndpointRef,
    transport: &TransportContext,
    query: &[u8],
) -> anyhow::Result<()> {
    match endpoint {
        UpstreamEndpointRef::Udp { addr } => probe_udp(*addr, query).await,
        UpstreamEndpointRef::Tcp { addr } => probe_tcp(*addr, query, Duration::from_millis(900)).await,
        UpstreamEndpointRef::Dot {
            addr,
            server_name,
            tls_insecure,
        } => {
            probe_dot(
                *addr,
                server_name,
                *tls_insecure,
                transport,
                query,
                Duration::from_millis(1200),
            )
            .await
        }
        UpstreamEndpointRef::Doh { url, tls_insecure } => {
            probe_doh(url, *tls_insecure, transport, query, Duration::from_millis(1200)).await
        }
    }
}

async fn probe_udp(addr: SocketAddr, query: &[u8]) -> anyhow::Result<()> {
    let bind_addr = match addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let sock = tokio::net::UdpSocket::bind(bind_addr).await?;
    sock.send_to(query, addr).await?;
    let mut buf = [0u8; 2048];
    let (n, _) = sock.recv_from(&mut buf).await?;
    if n < 12 {
        return Err(anyhow::anyhow!("short response"));
    }
    Ok(())
}

async fn probe_tcp(addr: SocketAddr, query: &[u8], timeout: Duration) -> anyhow::Result<()> {
    use tokio::{io::AsyncReadExt, io::AsyncWriteExt, net::TcpStream};

    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr)).await??;
    let len = (query.len() as u16).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(query).await?;

    let mut resp_len = [0u8; 2];
    tokio::time::timeout(timeout, stream.read_exact(&mut resp_len)).await??;
    let n = u16::from_be_bytes(resp_len) as usize;
    let mut buf = vec![0u8; n];
    tokio::time::timeout(timeout, stream.read_exact(&mut buf)).await??;
    if buf.len() < 12 {
        return Err(anyhow::anyhow!("short response"));
    }
    Ok(())
}

async fn probe_dot(
    addr: SocketAddr,
    server_name: &Arc<str>,
    tls_insecure: bool,
    transport: &TransportContext,
    query: &[u8],
    timeout: Duration,
) -> anyhow::Result<()> {
    use tokio::{io::AsyncReadExt, io::AsyncWriteExt, net::TcpStream};

    let tcp = tokio::time::timeout(timeout, TcpStream::connect(addr)).await??;
    let name = rustls::pki_types::ServerName::try_from(server_name.to_string())?;
    let connector = if tls_insecure {
        TlsConnector::from(transport.tls_insecure.clone())
    } else {
        TlsConnector::from(transport.tls.clone())
    };
    let mut tls = tokio::time::timeout(timeout, connector.connect(name, tcp)).await??;

    let len = (query.len() as u16).to_be_bytes();
    tls.write_all(&len).await?;
    tls.write_all(query).await?;

    let mut resp_len = [0u8; 2];
    tokio::time::timeout(timeout, tls.read_exact(&mut resp_len)).await??;
    let n = u16::from_be_bytes(resp_len) as usize;
    let mut buf = vec![0u8; n];
    tokio::time::timeout(timeout, tls.read_exact(&mut buf)).await??;
    if buf.len() < 12 {
        return Err(anyhow::anyhow!("short response"));
    }
    Ok(())
}

async fn probe_doh(
    url: &Arc<str>,
    tls_insecure: bool,
    transport: &TransportContext,
    query: &[u8],
    timeout: Duration,
) -> anyhow::Result<()> {
    let url = Url::parse(url.as_ref())?;
    let client = if tls_insecure {
        &transport.doh_insecure
    } else {
        &transport.doh
    };
    let resp = tokio::time::timeout(
        timeout,
        client
            .post(url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(query.to_vec())
            .send(),
    )
    .await??;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("http status {}", resp.status()));
    }
    let bytes = tokio::time::timeout(timeout, resp.bytes()).await??;
    if bytes.len() < 12 {
        return Err(anyhow::anyhow!("short response"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthcheck_requires_multiple_failures_before_marking_dead() {
        let failures = AtomicU64::new(0);

        assert_eq!(update_health_state(true, &failures, false), (true, 1));
        assert_eq!(update_health_state(true, &failures, false), (true, 2));
        assert_eq!(update_health_state(true, &failures, false), (false, 3));
        assert_eq!(update_health_state(false, &failures, true), (true, 0));
    }

    #[test]
    fn ordered_candidates_weighted_uses_balancer() {
        let balancer = Balancer::new(BalancingAlgorithm::RoundRobin);
        assert_eq!(ordered_candidates_weighted(&[1, 2], &[1, 1], &balancer, None, None), vec![1, 2]);
        assert_eq!(ordered_candidates_weighted(&[3, 4], &[1, 1], &balancer, None, None), vec![4, 3]);
    }
}

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}
