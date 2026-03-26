use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use dashmap::DashMap;
use rand::Rng as _;
use reqwest::Url;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{self, Instant},
};

use tokio_rustls::TlsConnector;

use crate::{
    blocklist_remote::BlocklistRemote,
    config::SecurityConfig,
    dns,
    hosts_remote::HostsRemote,
    upstream::{Balancer, TransportContext, UpstreamEndpointRef, UpstreamSet},
};

pub struct UdpProxy {
    listen: SocketAddr,
    socket: Arc<UdpSocket>,
    upstreams: Arc<UpstreamSet>,
    balancer: Arc<Balancer>,
    security: SecurityConfig,
    hosts: Option<Arc<HostsRemote>>,
    blocklist: Option<Arc<BlocklistRemote>>,
    upstream_workers: Vec<Arc<UdpUpstreamWorker>>,
    request_timeout: Duration,
}

pub struct TcpProxy {
    listen: SocketAddr,
    listener: TcpListener,
    upstreams: Arc<UpstreamSet>,
    balancer: Arc<Balancer>,
    security: SecurityConfig,
    hosts: Option<Arc<HostsRemote>>,
    blocklist: Option<Arc<BlocklistRemote>>,
    request_timeout: Duration,
}

impl UdpProxy {
    pub async fn new(
        listen: SocketAddr,
        upstreams: Arc<UpstreamSet>,
        balancer: Arc<Balancer>,
        security: SecurityConfig,
        hosts: Option<Arc<HostsRemote>>,
        blocklist: Option<Arc<BlocklistRemote>>,
    ) -> anyhow::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(listen).await?);
        let listen = socket.local_addr()?;

        let mut upstream_workers = Vec::new();
        for (name, addr) in upstreams.all_udp() {
            upstream_workers.push(Arc::new(UdpUpstreamWorker::new(name, addr).await?));
        }

        let request_timeout = Duration::from_millis(security.request_timeout_ms);
        Ok(Self {
            listen,
            socket,
            upstreams,
            balancer,
            security,
            hosts,
            blocklist,
            upstream_workers,
            request_timeout,
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        tracing::info!(listen = %self.listen, "udp listening");

        for worker in &self.upstream_workers {
            let listener = self.socket.clone();
            let w = worker.clone();
            tokio::spawn(async move {
                w.run_receiver(listener).await;
            });
            let w = worker.clone();
            tokio::spawn(async move {
                w.run_sweeper(Duration::from_millis(200)).await;
            });
        }

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

            if let Some(hosts) = &self.hosts {
                if let Some(resp) = hosts.maybe_answer(packet) {
                    metrics::counter!("dns_hosts_hits_total", "proto" => "udp").increment(1);
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

            let client_ip = Some(client.ip());
            let upstream = match self.upstreams.pick("default", &self.balancer, client_ip) {
                Some(u) => u,
                None => {
                    metrics::counter!("dns_upstream_errors_total", "proto" => "udp").increment(1);
                    continue;
                }
            };

            match &upstream.endpoint {
                UpstreamEndpointRef::Udp { addr } => {
                    let worker = match self.upstream_workers.iter().find(|w| w.addr == *addr).cloned() {
                        Some(w) => w,
                        None => {
                            metrics::counter!("dns_upstream_errors_total", "proto" => "udp").increment(1);
                            continue;
                        }
                    };

                    let listener = self.socket.clone();
                    let mut owned = Vec::with_capacity(n);
                    owned.extend_from_slice(packet);
                    let timeout = self.request_timeout;
                    tokio::spawn(async move {
                        if let Err(err) = worker.forward(listener, client, owned, timeout).await {
                            tracing::debug!(error = %err, "udp forward failed");
                            metrics::counter!("dns_upstream_errors_total", "proto" => "udp").increment(1);
                        }
                    });
                }
                _ => {
                    let listener = self.socket.clone();
                    let mut owned = Vec::with_capacity(n);
                    owned.extend_from_slice(packet);
                    let timeout = self.request_timeout;
                    tokio::spawn(async move {
                        match forward_once(&upstream.transport, &upstream.endpoint, &owned, timeout).await {
                            Ok(resp) => {
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
        blocklist: Option<Arc<BlocklistRemote>>,
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
            blocklist,
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
            let blocklist = self.blocklist.clone();
            let timeout = self.request_timeout;

            tokio::spawn(async move {
                if let Err(err) = handle_tcp_conn(stream, peer, upstreams, balancer, security, hosts, blocklist, timeout).await {
                    tracing::debug!(peer = %peer, error = %err, "tcp conn failed");
                }
            });
        }
    }

    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.listen)
    }
}

struct Pending {
    client: SocketAddr,
    orig_id: u16,
    start: Instant,
    expires_at: Instant,
}

struct UdpUpstreamWorker {
    name: Arc<str>,
    addr: SocketAddr,
    socket: Arc<UdpSocket>,
    pending: DashMap<u16, Pending>,
}

impl UdpUpstreamWorker {
    async fn new(name: Arc<str>, addr: SocketAddr) -> anyhow::Result<Self> {
        let bind_addr = match addr {
            SocketAddr::V4(v4) if v4.ip().is_loopback() => "127.0.0.1:0",
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(v6) if v6.ip().is_loopback() => "[::1]:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        Ok(Self {
            name,
            addr,
            socket: Arc::new(socket),
            pending: DashMap::new(),
        })
    }

    async fn forward(
        &self,
        listener: Arc<UdpSocket>,
        client: SocketAddr,
        mut packet: Vec<u8>,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let orig_id = dns::read_id(&packet).unwrap_or(0);
        let internal_id = self.alloc_id();
        dns::write_id(&mut packet, internal_id);
        let now = Instant::now();
        self.pending.insert(
            internal_id,
            Pending {
                client,
                orig_id,
                start: now,
                expires_at: now + timeout,
            },
        );

        if let Err(err) = self.socket.send_to(&packet, self.addr).await {
            let local = self.socket.local_addr().ok();
            tracing::debug!(
                upstream = %self.name,
                local = ?local,
                target = %self.addr,
                error = %err,
                "udp send_to failed"
            );
            self.pending.remove(&internal_id);
            drop(listener);
            return Err(err.into());
        }
        Ok(())
    }

    async fn run_receiver(self: Arc<Self>, listener: Arc<UdpSocket>) {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, from) = match self.socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(err) => {
                    tracing::warn!(upstream = %self.name, error = %err, "udp recv failed");
                    time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };

            if from != self.addr {
                continue;
            }

            let mut resp = Vec::with_capacity(n);
            resp.extend_from_slice(&buf[..n]);
            let internal_id = match dns::read_id(&resp) {
                Some(id) => id,
                None => continue,
            };

            let pending = match self.pending.remove(&internal_id) {
                Some((_, p)) => p,
                None => continue,
            };

            dns::write_id(&mut resp, pending.orig_id);
            let latency_ms = pending.start.elapsed().as_secs_f64() * 1000.0;
            let upstream_label = self.name.to_string();
            metrics::histogram!(
                "dns_upstream_latency_ms",
                "proto" => "udp",
                "upstream" => upstream_label
            )
            .record(latency_ms);

            let _ = listener.send_to(&resp, pending.client).await;
        }
    }

    async fn run_sweeper(self: Arc<Self>, interval: Duration) {
        let mut ticker = time::interval(interval);
        loop {
            ticker.tick().await;
            let now = Instant::now();
            let mut expired = Vec::new();
            for entry in self.pending.iter() {
                if entry.value().expires_at <= now {
                    expired.push(*entry.key());
                }
            }
            for id in expired {
                if self.pending.remove(&id).is_some() {
                    let upstream_label = self.name.to_string();
                    metrics::counter!(
                        "dns_timeouts_total",
                        "proto" => "udp",
                        "upstream" => upstream_label
                    )
                    .increment(1);
                }
            }
        }
    }

    fn alloc_id(&self) -> u16 {
        let mut rng = rand::thread_rng();
        for _ in 0..16 {
            let id: u16 = rng.r#gen();
            if !self.pending.contains_key(&id) {
                return id;
            }
        }
        rng.r#gen()
    }
}

async fn handle_tcp_conn(
    mut client: TcpStream,
    peer: SocketAddr,
    upstreams: Arc<UpstreamSet>,
    balancer: Arc<Balancer>,
    security: SecurityConfig,
    hosts: Option<Arc<HostsRemote>>,
    blocklist: Option<Arc<BlocklistRemote>>,
    timeout: Duration,
) -> anyhow::Result<()> {
    let client_ip = Some(peer.ip());
    let upstream = upstreams
        .pick("default", &balancer, client_ip)
        .ok_or_else(|| anyhow::anyhow!("no upstream"))?;

    tracing::debug!(peer = %peer, upstream = %upstream.name, "tcp picked upstream");

    metrics::counter!("dns_tcp_connections_total").increment(1);
    match upstream.endpoint.clone() {
        UpstreamEndpointRef::Tcp { addr } => {
            tracing::debug!(peer = %peer, upstream = %upstream.name, addr = %addr, "tcp connect upstream");
            let mut upstream_conn = time::timeout(timeout, TcpStream::connect(addr)).await??;
            loop {
                let msg = read_tcp_query(&mut client).await?;
                metrics::counter!("dns_requests_total", "proto" => "tcp").increment(1);
        if let Some(resp) = maybe_refuse(&msg, &security) {
                    metrics::counter!("dns_denied_total", "proto" => "tcp").increment(1);
                    write_tcp_response(&mut client, &resp).await?;
                    continue;
                }

        if let Some(hosts) = &hosts {
            if let Some(resp) = hosts.maybe_answer(&msg) {
                metrics::counter!("dns_hosts_hits_total", "proto" => "tcp").increment(1);
                write_tcp_response(&mut client, &resp).await?;
                continue;
            }
        }

        if let Some(bl) = &blocklist {
            if bl.is_blocked(&msg) {
                if let Some(resp) = dns::build_nxdomain_response(&msg) {
                    metrics::counter!("dns_blocked_total", "proto" => "tcp").increment(1);
                    write_tcp_response(&mut client, &resp).await?;
                    continue;
                }
            }
        }

                let start = Instant::now();
                upstream_conn.write_all(&(msg.len() as u16).to_be_bytes()).await?;
                upstream_conn.write_all(&msg).await?;

                let resp = read_tcp_response(&mut upstream_conn, timeout).await?;
                observe_tcp_latency(&upstream.name, "tcp", start);
                write_tcp_response(&mut client, &resp).await?;
            }
        }
        UpstreamEndpointRef::Dot {
            addr,
            server_name,
            tls_insecure,
        } => {
            tracing::debug!(peer = %peer, upstream = %upstream.name, addr = %addr, server_name = %server_name, tls_insecure = tls_insecure, "tcp connect dot upstream");
            let tcp = time::timeout(timeout, TcpStream::connect(addr)).await??;
            let name = rustls::pki_types::ServerName::try_from(server_name.to_string())?;
            let connector = if tls_insecure {
                TlsConnector::from(upstream.transport.tls_insecure.clone())
            } else {
                TlsConnector::from(upstream.transport.tls.clone())
            };
            let mut tls = time::timeout(timeout, connector.connect(name, tcp)).await??;

            loop {
                let msg = read_tcp_query(&mut client).await?;
                metrics::counter!("dns_requests_total", "proto" => "tcp").increment(1);
                if let Some(resp) = maybe_refuse(&msg, &security) {
                    metrics::counter!("dns_denied_total", "proto" => "tcp").increment(1);
                    write_tcp_response(&mut client, &resp).await?;
                    continue;
                }

                let start = Instant::now();
                tls.write_all(&(msg.len() as u16).to_be_bytes()).await?;
                tls.write_all(&msg).await?;

                let resp = read_tcp_response(&mut tls, timeout).await?;
                observe_tcp_latency(&upstream.name, "dot", start);
                write_tcp_response(&mut client, &resp).await?;
            }
        }
        UpstreamEndpointRef::Udp { addr } => loop {
            let msg = read_tcp_query(&mut client).await?;
            metrics::counter!("dns_requests_total", "proto" => "tcp").increment(1);
            if let Some(resp) = maybe_refuse(&msg, &security) {
                metrics::counter!("dns_denied_total", "proto" => "tcp").increment(1);
                write_tcp_response(&mut client, &resp).await?;
                continue;
            }

            let start = Instant::now();
            let resp = forward_udp_once(addr, &msg, timeout).await?;
            observe_tcp_latency(&upstream.name, "udp", start);
            write_tcp_response(&mut client, &resp).await?;
        },
        UpstreamEndpointRef::Doh { url, tls_insecure } => loop {
            let msg = read_tcp_query(&mut client).await?;
            metrics::counter!("dns_requests_total", "proto" => "tcp").increment(1);
            if let Some(resp) = maybe_refuse(&msg, &security) {
                metrics::counter!("dns_denied_total", "proto" => "tcp").increment(1);
                write_tcp_response(&mut client, &resp).await?;
                continue;
            }

            let start = Instant::now();
            let resp = forward_doh_once(&upstream.transport, &url, tls_insecure, &msg, timeout).await?;
            observe_tcp_latency(&upstream.name, "doh", start);
            write_tcp_response(&mut client, &resp).await?;
        },
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
