use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{self, Instant},
};

use crate::{
    blocklist_remote::BlocklistRemote,
    cache::DnsCache,
    coalescing::{PendingQueries, QueryState},
    config::SecurityConfig,
    dns,
    hooks::{Hooks, Stage},
    hosts_remote::HostsRemote,
    upstream::{Balancer, UpstreamSet},
};

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
    hooks: Arc<Hooks>,
    pending: Arc<PendingQueries>,
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
    hooks: Arc<Hooks>,
    pending: Arc<PendingQueries>,
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
        hooks: Arc<Hooks>,
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
            hooks,
            pending: Arc::new(PendingQueries::new()),
            request_timeout,
        })
    }

    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    pub async fn run(self) -> anyhow::Result<()> {
        tracing::info!(listen = %self.listen, "UDP listening (EdgeDNS flow)");

        let mut buf = vec![0u8; 4096];
        loop {
            let (n, client) = self.socket.recv_from(&mut buf).await?;
            metrics::counter!("dns_requests_total", "proto" => "udp").increment(1);

            let packet = if self.hooks.enabled(Stage::Deliver) {
                let p = buf[..n].to_vec();
                self.hooks.apply(p.clone(), Stage::Deliver).unwrap_or(p)
            } else {
                buf[..n].to_vec()
            };

            // 2. Security Checks
            if let Some(resp) = maybe_refuse(&packet, &self.security) {
                metrics::counter!("dns_denied_total", "proto" => "udp").increment(1);
                let _ = self.socket.send_to(&resp, client).await;
                continue;
            }

            // 3. Local answer (hosts/blocklist)
            if let Some(hl) = &self.hosts_local {
                if let Some(resp) = maybe_answer_local(&packet, hl) {
                    metrics::counter!("dns_hosts_hits_total", "proto" => "udp", "source" => "local").increment(1);
                    let _ = self.socket.send_to(&resp, client).await;
                    continue;
                }
            }

            if let Some(hosts) = &self.hosts {
                if let Some(resp) = hosts.maybe_answer(&packet) {
                    metrics::counter!("dns_hosts_hits_total", "proto" => "udp", "source" => "remote").increment(1);
                    let _ = self.socket.send_to(&resp, client).await;
                    continue;
                }
            }

            if let Some(bl) = &self.blocklist {
                if bl.is_blocked(&packet) {
                    if let Some(resp) = dns::build_nxdomain_response(&packet) {
                        metrics::counter!("dns_blocked_total", "proto" => "udp").increment(1);
                        let _ = self.socket.send_to(&resp, client).await;
                        continue;
                    }
                }
            }

            // 4. Cache Check
            let qinfo = dns::read_qname_qtype_qclass(&packet);
            if let Some(cache) = &self.cache {
                if let Some((domain, qtype, _qclass)) = &qinfo {
                    if let Some(cached_resp) = cache.get(domain, *qtype) {
                        metrics::counter!("dns_cache_hits_total", "proto" => "udp").increment(1);
                        let mut resp = cached_resp;
                        if let Some(orig_id) = dns::read_id(&packet) {
                            dns::write_id(&mut resp, orig_id);
                        }
                        let _ = self.socket.send_to(&resp, client).await;
                        continue;
                    }
                }
            }

            // 5. Forwarding
            let client_ip = Some(client.ip());
            let domain_str = qinfo.as_ref().map(|(d, _, _)| d.as_str());
            let candidates = self.upstreams.candidates("default", &self.balancer, domain_str, client_ip);
            if candidates.is_empty() {
                metrics::counter!("dns_upstream_errors_total", "proto" => "udp").increment(1);
                continue;
            }

            let socket = self.socket.clone();
            let cache = self.cache.clone();
            let pending = self.pending.clone();
            let upstreams = self.upstreams.clone();
            let timeout = self.request_timeout;

            tokio::spawn(async move {
                let start = Instant::now();

                let (domain, qtype) = if let Some((d, t, _)) = dns::read_qname_qtype_qclass(&packet) {
                    (d, t)
                } else {
                    return;
                };

                let resp = match pending.get_or_create(&domain, qtype) {
                    QueryState::New(tx) => {
                        let res = upstreams.forward_candidates(&candidates, &packet, timeout).await;
                        let result_packet = match res {
                            Ok((upstream, resp, _upstream_proto)) => {
                                if let Some(cache) = &cache {
                                    let ttl = dns::extract_min_ttl(&resp).unwrap_or(Duration::from_secs(300));
                                    // In resolver mode (the only one here), we cache the response.
                                    cache.set(&domain, qtype, resp.clone(), ttl);
                                }
                                observe_latency("udp", &upstream.name, start);
                                Some(resp)
                            }
                            Err(err) => {
                                tracing::debug!(error = %err, "UDP forward failed");
                                metrics::counter!("dns_upstream_errors_total", "proto" => "udp").increment(1);
                                None
                            }
                        };
                        let _ = tx.send(result_packet.clone());
                        pending.remove(&domain, qtype);
                        result_packet
                    }
                    QueryState::Waiting(mut rx) => {
                        let _ = rx.changed().await;
                        rx.borrow().clone()
                    }
                };

                if let Some(mut resp) = resp {
                    if let Some(orig_id) = dns::read_id(&packet) {
                        dns::write_id(&mut resp, orig_id);
                    }
                    let _ = socket.send_to(&resp, client).await;
                }
            });
        }
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
        hooks: Arc<Hooks>,
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
            hooks,
            pending: Arc::new(PendingQueries::new()),
            request_timeout,
        })
    }

    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.listen)
    }

    pub async fn run(self) -> anyhow::Result<()> {
        tracing::info!(listen = %self.listen, "TCP listening (EdgeDNS flow)");
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let upstreams = self.upstreams.clone();
            let balancer = self.balancer.clone();
            let security = self.security.clone();
            let hosts = self.hosts.clone();
            let hosts_local = self.hosts_local.clone();
            let blocklist = self.blocklist.clone();
            let cache = self.cache.clone();
            let hooks = self.hooks.clone();
            let pending = self.pending.clone();
            let timeout = self.request_timeout;

            tokio::spawn(async move {
                if let Err(err) = handle_tcp_conn(stream, peer, upstreams, balancer, security, hosts, hosts_local, blocklist, cache, hooks, pending, timeout).await {
                    tracing::debug!(peer = %peer, error = %err, "TCP connection failed");
                }
            });
        }
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
    hooks: Arc<Hooks>,
    pending: Arc<PendingQueries>,
    timeout: Duration,
) -> anyhow::Result<()> {
    metrics::counter!("dns_tcp_connections_total").increment(1);
    let idle_timeout = timeout.saturating_mul(8).max(Duration::from_secs(5));

    loop {
        let mut len_buf = [0u8; 2];
        match time::timeout(idle_timeout, client.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) | Err(_) => return Ok(()),
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 4096 {
            return Ok(());
        }
        let mut raw_packet = vec![0u8; len];
        match time::timeout(idle_timeout, client.read_exact(&mut raw_packet)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) | Err(_) => return Ok(()),
        }
        metrics::counter!("dns_requests_total", "proto" => "tcp").increment(1);

        // 1. Hook: Deliver stage
        let packet = if hooks.enabled(Stage::Deliver) {
            hooks.apply(raw_packet.clone(), Stage::Deliver).unwrap_or(raw_packet)
        } else {
            raw_packet
        };

        // 2. Security Checks
        if let Some(resp) = maybe_refuse(&packet, &security) {
            metrics::counter!("dns_denied_total", "proto" => "tcp").increment(1);
            let _ = write_tcp_response(&mut client, &resp).await;
            continue;
        }

        // 3. Local answer
        if let Some(hl) = &hosts_local {
            if let Some(resp) = maybe_answer_local(&packet, hl) {
                metrics::counter!("dns_hosts_hits_total", "proto" => "tcp", "source" => "local").increment(1);
                let _ = write_tcp_response(&mut client, &resp).await;
                continue;
            }
        }

        if let Some(hosts) = &hosts {
            if let Some(resp) = hosts.maybe_answer(&packet) {
                metrics::counter!("dns_hosts_hits_total", "proto" => "tcp", "source" => "remote").increment(1);
                let _ = write_tcp_response(&mut client, &resp).await;
                continue;
            }
        }

        if let Some(bl) = &blocklist {
            if bl.is_blocked(&packet) {
                if let Some(resp) = dns::build_nxdomain_response(&packet) {
                    metrics::counter!("dns_blocked_total", "proto" => "tcp").increment(1);
                    let _ = write_tcp_response(&mut client, &resp).await;
                    continue;
                }
            }
        }

        // 4. Cache Check
        let qinfo = dns::read_qname_qtype_qclass(&packet);
        if let Some(cache) = &cache {
            if let Some((domain, qtype, _qclass)) = &qinfo {
                if let Some(cached_resp) = cache.get(domain, *qtype) {
                    metrics::counter!("dns_cache_hits_total", "proto" => "tcp").increment(1);
                    let mut resp = cached_resp;
                    if let Some(orig_id) = dns::read_id(&packet) {
                        dns::write_id(&mut resp, orig_id);
                    }
                    let _ = write_tcp_response(&mut client, &resp).await;
                    continue;
                }
            }
        }

        // 5. Forwarding
        let client_ip = Some(peer.ip());
        let domain_str = qinfo.as_ref().map(|(d, _, _)| d.as_str());
        let candidates = upstreams.candidates("default", &balancer, domain_str, client_ip);
        if candidates.is_empty() {
            return Err(anyhow::anyhow!("no upstream"));
        }

        let start = Instant::now();
        let (domain, qtype) = if let Some((d, t, _)) = qinfo {
            (d, t)
        } else {
            return Err(anyhow::anyhow!("invalid query"));
        };

        let resp = match pending.get_or_create(&domain, qtype) {
            QueryState::New(tx) => {
                let res = upstreams.forward_candidates(&candidates, &packet, timeout).await;
                let result_packet = match res {
                    Ok((upstream, resp, _upstream_proto)) => {
                        if let Some(cache) = &cache {
                            let ttl = dns::extract_min_ttl(&resp).unwrap_or(Duration::from_secs(300));
                            cache.set(&domain, qtype, resp.clone(), ttl);
                        }
                        observe_latency("tcp", &upstream.name, start);
                        Some(resp)
                    }
                    Err(_) => None,
                };
                let _ = tx.send(result_packet.clone());
                pending.remove(&domain, qtype);
                result_packet
            }
            QueryState::Waiting(mut rx) => {
                let _ = rx.changed().await;
                rx.borrow().clone()
            }
        };

        if let Some(mut resp) = resp {
            if let Some(orig_id) = dns::read_id(&packet) {
                dns::write_id(&mut resp, orig_id);
            }
            write_tcp_response(&mut client, &resp).await?;
        } else {
            return Err(anyhow::anyhow!("upstream failed"));
        }
    }
}

pub(crate) async fn write_tcp_response(stream: &mut TcpStream, resp: &[u8]) -> anyhow::Result<()> {
    let len = (resp.len() as u16).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(resp).await?;
    Ok(())
}

pub(crate) fn maybe_refuse(packet: &[u8], security: &SecurityConfig) -> Option<Vec<u8>> {
    let qtype = dns::read_qtype(packet)?;
    let denied = (security.deny_any && qtype == 255) || (security.deny_dnskey && qtype == 48);
    if !denied {
        return None;
    }
    Some(build_refused(packet))
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

fn observe_latency(proto: &'static str, upstream_name: &Arc<str>, start: Instant) {
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    metrics::histogram!(
        "dns_upstream_latency_ms",
        "proto" => proto,
        "upstream" => upstream_name.to_string()
    )
    .record(latency_ms);
}
