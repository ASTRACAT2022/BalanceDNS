use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};


use rand::Rng as _;
use reqwest::Url;
use tokio::time;
use tokio_rustls::TlsConnector;
use trust_dns_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
};

use crate::config::{BalancingAlgorithm, UpstreamConfig, UpstreamProto};

pub struct UpstreamSet {
    upstreams: Vec<Upstream>,
    transport: Arc<TransportContext>,
}

#[derive(Clone)]
pub struct UpstreamRef {
    pub name: Arc<str>,
    pub pool: Arc<str>,
    pub endpoint: UpstreamEndpointRef,
    pub transport: Arc<TransportContext>,
}

struct Upstream {
    name: Arc<str>,
    pool: Arc<str>,
    endpoint: UpstreamEndpoint,
    alive: AtomicBool,
    consecutive_failures: AtomicU64,
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
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(Self { upstreams, transport })
    }

    pub fn transport(&self) -> Arc<TransportContext> {
        self.transport.clone()
    }

    pub fn pick(&self, pool: &str, balancer: &Balancer, client_ip: Option<IpAddr>) -> Option<UpstreamRef> {
        self.candidates(pool, balancer, client_ip).into_iter().next()
    }

    pub fn candidates(&self, pool: &str, balancer: &Balancer, client_ip: Option<IpAddr>) -> Vec<UpstreamRef> {
        let mut eligible: Vec<usize> = self
            .upstreams
            .iter()
            .enumerate()
            .filter(|(_, u)| u.pool.as_ref() == pool)
            .filter(|(_, u)| u.alive.load(Ordering::Relaxed))
            .map(|(idx, _)| idx)
            .collect();

        if eligible.is_empty() {
            eligible = self
                .upstreams
                .iter()
                .enumerate()
                .filter(|(_, u)| u.pool.as_ref() == pool)
                .map(|(idx, _)| idx)
                .collect();
        }

        if eligible.is_empty() {
            return Vec::new();
        }

        let start_idx = balancer.pick(&eligible, client_ip);
        let start_pos = eligible
            .iter()
            .position(|idx| *idx == start_idx)
            .unwrap_or(0);

        eligible
            .iter()
            .cycle()
            .skip(start_pos)
            .take(eligible.len())
            .map(|idx| self.make_ref(*idx))
            .collect()
    }

    pub fn all_udp(&self) -> Vec<(Arc<str>, SocketAddr)> {
        self.upstreams
            .iter()
            .filter_map(|u| match u.endpoint {
                UpstreamEndpoint::Udp { addr } => Some((u.name.clone(), addr)),
                _ => None,
            })
            .collect()
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
        for u in &self.upstreams {
            let ok = match tokio::time::timeout(timeout, probe(u, &self.transport, &query)).await {
                Ok(Ok(())) => true,
                _ => false,
            };
            let prev = u.alive.load(Ordering::Relaxed);
            let (alive, failures) = update_health_state(prev, &u.consecutive_failures, ok);
            u.alive.store(alive, Ordering::Relaxed);

            metrics::gauge!("dns_upstream_alive", "upstream" => u.name.to_string())
                .set(if alive { 1.0 } else { 0.0 });

            if prev != alive {
                metrics::counter!(
                    "dns_upstream_health_changes_total",
                    "upstream" => u.name.to_string(),
                    "alive" => if alive { "true" } else { "false" }
                )
                .increment(1);
                tracing::warn!(upstream = %u.name, alive = alive, failures = failures, "upstream health changed");
            }
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

impl UpstreamSet {
    fn make_ref(&self, idx: usize) -> UpstreamRef {
        let u = &self.upstreams[idx];
        UpstreamRef {
            name: u.name.clone(),
            pool: u.pool.clone(),
            endpoint: u.endpoint.as_ref(),
            transport: self.transport.clone(),
        }
    }
}

pub struct Balancer {
    algorithm: BalancingAlgorithm,
    rr: AtomicU64,
}

impl Balancer {
    pub fn new(algorithm: BalancingAlgorithm) -> Self {
        Self {
            algorithm,
            rr: AtomicU64::new(0),
        }
    }

    pub fn pick(&self, eligible_indices: &[usize], _client_ip: Option<IpAddr>) -> usize {
        match self.algorithm {
            BalancingAlgorithm::RoundRobin => {
                let n = eligible_indices.len() as u64;
                let idx = self.rr.fetch_add(1, Ordering::Relaxed) % n;
                eligible_indices[idx as usize]
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

async fn probe(upstream: &Upstream, transport: &TransportContext, query: &[u8]) -> anyhow::Result<()> {
    match &upstream.endpoint {
        UpstreamEndpoint::Udp { addr } => probe_udp(*addr, query).await,
        UpstreamEndpoint::Tcp { addr } => probe_tcp(*addr, query, Duration::from_millis(900)).await,
        UpstreamEndpoint::Dot {
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
        UpstreamEndpoint::Doh { url, tls_insecure } => {
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
