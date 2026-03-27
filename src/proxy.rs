use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use reqwest::Url;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
    time::{self, Instant},
};

use tokio_rustls::TlsConnector;

use crate::{
    blocklist_remote::BlocklistRemote,
    cache::DnsCache,
    config::SecurityConfig,
    dns,
    hosts_remote::HostsRemote,
    upstream::{Balancer, TransportContext, UpstreamEndpointRef, UpstreamRef, UpstreamSet},
};

const MIN_TCP_CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TCP_CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const MIN_TCP_CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_TCP_CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(15);

pub struct UdpProxy {
    listen: SocketAddr,
    socket: Arc<UdpSocket>,
    upstreams: Arc<UpstreamSet>,
    balancer: Arc<Balancer>,
    security: SecurityConfig,
    hosts: Option<Arc<HostsRemote>>,
    hosts_local: Option<Arc<std::collections::HashMap<String, String>>>,
    blocklist: Option<Arc<BlocklistRemote>>,
    cache: Option<Arc<DnsCache>>,
    request_timeout: Duration,
}

pub struct TcpProxy {
    listen: SocketAddr,
    listener: TcpListener,
    upstreams: Arc<UpstreamSet>,
    balancer: Arc<Balancer>,
    security: SecurityConfig,
    hosts: Option<Arc<HostsRemote>>,
    hosts_local: Option<Arc<std::collections::HashMap<String, String>>>,
    blocklist: Option<Arc<BlocklistRemote>>,
    cache: Option<Arc<DnsCache>>,
    request_timeout: Duration,
}

impl UdpProxy {
    pub async fn new(
        listen: SocketAddr,
        upstreams: Arc<UpstreamSet>,
        balancer: Arc<Balancer>,
        security: SecurityConfig,
        hosts: Option<Arc<HostsRemote>>,
        hosts_local: Option<Arc<std::collections::HashMap<String, String>>>,
        blocklist: Option<Arc<BlocklistRemote>>,
        cache: Option<Arc<DnsCache>>,
    ) -> anyhow::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(listen).await?);
        let listen = socket.local_addr()?;

        let request_timeout = Duration::from_millis(security.request_timeout_ms);
        Ok(Self {
            listen,
            socket,
            upstreams,
            balancer,
            security,
            hosts,
            hosts_local,
            blocklist,
            cache,
            request_timeout,
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        tracing::info!(listen = %self.listen, "udp listening");

        let mut buf = vec![0u8; 4096];
        loop {
            let (n, client) = self.socket.recv_from(&mut buf).await?;
            metrics::counter!("dns_requests_total", "proto" => "udp").increment(1);
            let packet = &buf[..n];

            if let Some(resp) = maybe_refuse(packet, &self.security) {
                metrics::counter!("dns_denied_total", "proto" => "udp").increment(1);
                let _ = self.socket.send_to(&resp, client).await;
                continue;
            }

            if let Some(hl) = &self.hosts_local {
                if let Some(resp) = maybe_answer_local(packet, hl) {
                    metrics::counter!("dns_hosts_hits_total", "proto" => "udp", "source" => "local").increment(1);
                    let _ = self.socket.send_to(&resp, client).await;
                    continue;
                }
            }

            if let Some(hosts) = &self.hosts {
                if let Some(resp) = hosts.maybe_answer(packet) {
                    metrics::counter!("dns_hosts_hits_total", "proto" => "udp", "source" => "remote").increment(1);
                    let _ = self.socket.send_to(&resp, client).await;
                    continue;
                }
            }

            if let Some(bl) = &self.blocklist {
                if bl.is_blocked(packet) {
                    if let Some(resp) = dns::build_nxdomain_response(packet) {
                        metrics::counter!("dns_blocked_total", "proto" => "udp").increment(1);
                        let _ = self.socket.send_to(&resp, client).await;
                        continue;
                    }
                }
            }

            // Проверка кэша
            if let Some(cache) = &self.cache {
                if let Some((domain, qtype, _qclass)) = dns::read_qname_qtype_qclass(packet) {
                    if let Some(cached_resp) = cache.get(&domain, qtype) {
                        metrics::counter!("dns_cache_hits_total", "proto" => "udp").increment(1);
                        // Восстанавливаем оригинальный ID запроса
                        let mut resp = cached_resp;
                        if let Some(orig_id) = dns::read_id(packet) {
                            dns::write_id(&mut resp, orig_id);
                        }
                        let _ = self.socket.send_to(&resp, client).await;
                        continue;
                    }
                }
            }

            let client_ip = Some(client.ip());
            let candidates = self.upstreams.candidates("default", &self.balancer, client_ip);
            if candidates.is_empty() {
                metrics::counter!("dns_upstream_errors_total", "proto" => "udp").increment(1);
                continue;
            }

            let listener = self.socket.clone();
            let cache = self.cache.clone();
            let mut owned = Vec::with_capacity(n);
            owned.extend_from_slice(packet);
            let timeout = self.request_timeout;
            tokio::spawn(async move {
                let start = Instant::now();
                match forward_candidates(&candidates, &owned, timeout).await {
                    Ok((upstream, resp, _upstream_proto)) => {
                        if let Some(cache) = &cache {
                            if let Some((domain, qtype, _qclass)) = dns::read_qname_qtype_qclass(&owned) {
                                let ttl = dns::extract_min_ttl(&resp).unwrap_or(Duration::from_secs(300));
                                cache.set(&domain, qtype, resp.clone(), ttl);
                            }
                        }
                        observe_udp_latency(&upstream.name, start);
                        let _ = listener.send_to(&resp, client).await;
                    }
                    Err(err) => {
                        tracing::debug!(error = %err, "udp forward failed");
                        metrics::counter!("dns_upstream_errors_total", "proto" => "udp").increment(1);
                    }
                }
            });
        }
    }

    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }
}

impl TcpProxy {
    pub async fn new(
        listen: SocketAddr,
        upstreams: Arc<UpstreamSet>,
        balancer: Arc<Balancer>,
        security: SecurityConfig,
        hosts: Option<Arc<HostsRemote>>,
        hosts_local: Option<Arc<std::collections::HashMap<String, String>>>,
        blocklist: Option<Arc<BlocklistRemote>>,
        cache: Option<Arc<DnsCache>>,
    ) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(listen).await?;
        let listen = listener.local_addr()?;
        let request_timeout = Duration::from_millis(security.request_timeout_ms);
        Ok(Self {
            listen,
            listener,
            upstreams,
            balancer,
            security,
            hosts,
            hosts_local,
            blocklist,
            cache,
            request_timeout,
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        tracing::info!(listen = %self.listen, "tcp listening");
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let upstreams = self.upstreams.clone();
            let balancer = self.balancer.clone();
            let security = self.security.clone();
            let hosts = self.hosts.clone();
            let hosts_local = self.hosts_local.clone();
            let blocklist = self.blocklist.clone();
            let cache = self.cache.clone();
            let timeout = self.request_timeout;

            tokio::spawn(async move {
                if let Err(err) = handle_tcp_conn(stream, peer, upstreams, balancer, security, hosts, hosts_local, blocklist, cache, timeout).await {
                    tracing::debug!(peer = %peer, error = %err, "tcp conn failed");
                }
            });
        }
    }

    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.listen)
    }
}

async fn handle_tcp_conn(
    mut client: TcpStream,
    peer: SocketAddr,
    upstreams: Arc<UpstreamSet>,
    balancer: Arc<Balancer>,
    security: SecurityConfig,
    hosts: Option<Arc<HostsRemote>>,
    hosts_local: Option<Arc<std::collections::HashMap<String, String>>>,
    blocklist: Option<Arc<BlocklistRemote>>,
    cache: Option<Arc<DnsCache>>,
    timeout: Duration,
) -> anyhow::Result<()> {
    metrics::counter!("dns_tcp_connections_total").increment(1);
    let client_idle_timeout = tcp_client_idle_timeout(timeout);
    let client_io_timeout = tcp_client_io_timeout(timeout);
    loop {
        let msg = match time::timeout(client_idle_timeout, read_tcp_query(&mut client)).await {
            Ok(Ok(msg)) => msg,
            Ok(Err(err)) => return Err(err),
            Err(_) => return Ok(()),
        };
        metrics::counter!("dns_requests_total", "proto" => "tcp").increment(1);
        if let Some(resp) = maybe_refuse(&msg, &security) {
            metrics::counter!("dns_denied_total", "proto" => "tcp").increment(1);
            time::timeout(client_io_timeout, write_tcp_response(&mut client, &resp)).await??;
            continue;
        }

        if let Some(hl) = &hosts_local {
            if let Some(resp) = maybe_answer_local(&msg, hl) {
                metrics::counter!("dns_hosts_hits_total", "proto" => "tcp", "source" => "local").increment(1);
                time::timeout(client_io_timeout, write_tcp_response(&mut client, &resp)).await??;
                continue;
            }
        }

        if let Some(hosts) = &hosts {
            if let Some(resp) = hosts.maybe_answer(&msg) {
                metrics::counter!("dns_hosts_hits_total", "proto" => "tcp", "source" => "remote").increment(1);
                time::timeout(client_io_timeout, write_tcp_response(&mut client, &resp)).await??;
                continue;
            }
        }

        if let Some(bl) = &blocklist {
            if bl.is_blocked(&msg) {
                if let Some(resp) = dns::build_nxdomain_response(&msg) {
                    metrics::counter!("dns_blocked_total", "proto" => "tcp").increment(1);
                    time::timeout(client_io_timeout, write_tcp_response(&mut client, &resp)).await??;
                    continue;
                }
            }
        }

        if let Some(cache) = &cache {
            if let Some((domain, qtype, _qclass)) = dns::read_qname_qtype_qclass(&msg) {
                if let Some(cached_resp) = cache.get(&domain, qtype) {
                    metrics::counter!("dns_cache_hits_total", "proto" => "tcp").increment(1);
                    let mut resp = cached_resp;
                    if let Some(orig_id) = dns::read_id(&msg) {
                        dns::write_id(&mut resp, orig_id);
                    }
                    time::timeout(client_io_timeout, write_tcp_response(&mut client, &resp)).await??;
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
        // For TCP, we use specialized forwarder as it needs new connections
        let (upstream, resp, upstream_proto) = forward_candidates_tcp(&candidates, &msg, timeout).await?;
        if let Some(cache) = &cache {
            if let Some((domain, qtype, _qclass)) = dns::read_qname_qtype_qclass(&msg) {
                let ttl = dns::extract_min_ttl(&resp).unwrap_or(Duration::from_secs(300));
                cache.set(&domain, qtype, resp.clone(), ttl);
            }
        }

        observe_tcp_latency(&upstream.name, upstream_proto, start);
        time::timeout(client_io_timeout, write_tcp_response(&mut client, &resp)).await??;
    }
}

fn observe_tcp_latency(upstream_name: &Arc<str>, upstream_proto: &'static str, start: Instant) {
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    let upstream_label = upstream_name.to_string();
    metrics::histogram!(
        "dns_upstream_latency_ms",
        "proto" => "tcp",
        "upstream" => upstream_label,
        "upstream_proto" => upstream_proto
    )
    .record(latency_ms);
}

pub(crate) fn maybe_answer_local(
    query: &[u8],
    hosts_local: &std::collections::HashMap<String, String>,
) -> Option<Vec<u8>> {
    let (name, qtype, qclass) = dns::read_qname_qtype_qclass(query)?;
    if qclass != 1 {
        return None;
    }

    let ip_str = hosts_local.get(name.as_str())?;
    let ip = ip_str.parse::<std::net::IpAddr>().ok()?;

    let answers = match qtype {
        1 => {
            if let std::net::IpAddr::V4(v4) = ip {
                dns::Answers::A(vec![v4])
            } else {
                return None;
            }
        }
        28 => {
            if let std::net::IpAddr::V6(v6) = ip {
                dns::Answers::AAAA(vec![v6])
            } else {
                return None;
            }
        }
        _ => return None,
    };

    dns::build_answer_response(query, &name, qtype, answers, 60)
}

fn observe_udp_latency(upstream_name: &Arc<str>, start: Instant) {
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    let upstream_label = upstream_name.to_string();
    metrics::histogram!(
        "dns_upstream_latency_ms",
        "proto" => "udp",
        "upstream" => upstream_label
    )
    .record(latency_ms);
}

fn tcp_client_idle_timeout(request_timeout: Duration) -> Duration {
    request_timeout
        .saturating_mul(8)
        .max(MIN_TCP_CLIENT_IDLE_TIMEOUT)
        .min(MAX_TCP_CLIENT_IDLE_TIMEOUT)
}

fn tcp_client_io_timeout(request_timeout: Duration) -> Duration {
    request_timeout
        .saturating_mul(2)
        .max(MIN_TCP_CLIENT_IO_TIMEOUT)
        .min(MAX_TCP_CLIENT_IO_TIMEOUT)
}

async fn read_tcp_query(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 4096 {
        return Err(anyhow::anyhow!("invalid tcp length"));
    }
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).await?;
    Ok(msg)
}

async fn write_tcp_response(stream: &mut TcpStream, resp: &[u8]) -> anyhow::Result<()> {
    let len = (resp.len() as u16).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(resp).await?;
    Ok(())
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

pub(crate) async fn forward_once(
    transport: &TransportContext,
    endpoint: &UpstreamEndpointRef,
    query: &[u8],
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    match endpoint {
        UpstreamEndpointRef::Udp { addr } => forward_udp_once(*addr, query, timeout).await,
        UpstreamEndpointRef::Tcp { addr } => forward_tcp_once(*addr, query, timeout).await,
        UpstreamEndpointRef::Dot {
            addr,
            server_name,
            tls_insecure,
        } => {
            forward_dot_once(transport, *addr, server_name, *tls_insecure, query, timeout).await
        }
        UpstreamEndpointRef::Doh { url, tls_insecure } => {
            forward_doh_once(transport, url, *tls_insecure, query, timeout).await
        }
    }
}

pub(crate) async fn forward_candidates(
    candidates: &[UpstreamRef],
    query: &[u8],
    timeout: Duration,
) -> anyhow::Result<(UpstreamRef, Vec<u8>, &'static str)> {
    if candidates.is_empty() {
        return Err(anyhow::anyhow!("no upstream candidates"));
    }

    let mut tasks = JoinSet::new();
    // Limit to top 3 candidates for efficiency
    for candidate in candidates.iter().take(3).cloned() {
        let query = query.to_vec();
        tasks.spawn(async move {
            let result = forward_candidate(&candidate, &query, timeout).await;
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

pub(crate) async fn forward_candidates_tcp(
    candidates: &[UpstreamRef],
    query: &[u8],
    timeout: Duration,
) -> anyhow::Result<(UpstreamRef, Vec<u8>, &'static str)> {
    if candidates.is_empty() {
        return Err(anyhow::anyhow!("no upstream candidates"));
    }

    let mut tasks = JoinSet::new();
    for candidate in candidates.iter().take(3).cloned() {
        let query = query.to_vec();
        tasks.spawn(async move {
            // TCP/DoT/DoH always create new connections or use connection pools,
            // so they don't need shared UDP sockets.
            let result = forward_candidate_tcp_aware(&candidate, &query, timeout).await;
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

async fn forward_candidate(
    candidate: &UpstreamRef,
    query: &[u8],
    timeout: Duration,
) -> anyhow::Result<(Vec<u8>, &'static str)> {
    match &candidate.endpoint {
        UpstreamEndpointRef::Udp { addr } => {
            let resp = forward_udp_once(*addr, query, timeout).await?;
            if dns::is_truncated_response(&resp) {
                let tcp_resp = forward_tcp_once(*addr, query, timeout).await?;
                return Ok((tcp_resp, "tcp"));
            }
            Ok((resp, "udp"))
        }
        UpstreamEndpointRef::Tcp { .. } => Ok((
            forward_once(&candidate.transport, &candidate.endpoint, query, timeout).await?,
            "tcp",
        )),
        UpstreamEndpointRef::Dot { .. } => Ok((
            forward_once(&candidate.transport, &candidate.endpoint, query, timeout).await?,
            "dot",
        )),
        UpstreamEndpointRef::Doh { .. } => Ok((
            forward_once(&candidate.transport, &candidate.endpoint, query, timeout).await?,
            "doh",
        )),
    }
}

async fn forward_candidate_tcp_aware(
    candidate: &UpstreamRef,
    query: &[u8],
    timeout: Duration,
) -> anyhow::Result<(Vec<u8>, &'static str)> {
    match &candidate.endpoint {
        UpstreamEndpointRef::Udp { addr } => {
            let resp = forward_udp_once(*addr, query, timeout).await?;
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


async fn forward_udp_once(addr: SocketAddr, query: &[u8], timeout: Duration) -> anyhow::Result<Vec<u8>> {
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

pub(crate) fn maybe_refuse(packet: &[u8], security: &SecurityConfig) -> Option<Vec<u8>> {
    let qtype = dns::read_qtype(packet)?;
    let denied = (security.deny_any && qtype == 255) || (security.deny_dnskey && qtype == 48);
    if !denied {
        return None;
    }
    Some(build_refused(packet))
}


fn is_positive_response(packet: &[u8]) -> bool {
    if packet.len() < 4 {
        return false;
    }
    let rcode = packet[3] & 0x0F;
    // Only NoError (0) is a terminal success.
    // NXDomain (3) is valid but might be a result of censorship/filtering,
    // so we should wait for other upstreams.
    rcode == 0
}

fn is_valid_response(packet: &[u8]) -> bool {
    if packet.len() < 4 {
        return false;
    }
    let rcode = packet[3] & 0x0F;
    // NoError (0) or NXDomain (3) are "valid" (non-error) responses
    rcode == 0 || rcode == 3
}

fn build_refused(packet: &[u8]) -> Vec<u8> {
    let mut resp = packet.to_vec();
    if resp.len() < 12 {
        return vec![0u8; 0];
    }

    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    let rd = flags & 0x0100;
    let opcode = flags & 0x7800;
    let new_flags = 0x8000 | opcode | rd | 0x0005;
    let b = new_flags.to_be_bytes();
    resp[2] = b[0];
    resp[3] = b[1];

    resp[6] = 0;
    resp[7] = 0;
    resp[8] = 0;
    resp[9] = 0;
    resp[10] = 0;
    resp[11] = 0;
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_timeouts_have_safe_bounds() {
        assert_eq!(tcp_client_idle_timeout(Duration::from_millis(100)), Duration::from_secs(5));
        assert_eq!(tcp_client_idle_timeout(Duration::from_secs(20)), Duration::from_secs(60));
        assert_eq!(tcp_client_io_timeout(Duration::from_millis(100)), Duration::from_secs(2));
        assert_eq!(tcp_client_io_timeout(Duration::from_secs(20)), Duration::from_secs(15));
    }
}
