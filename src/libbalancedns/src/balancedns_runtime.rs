use base64;
use base64::Engine;
use cache::Cache;
use config::{Config, RoutingRuleConfig, UpstreamConfig, UpstreamProtocol};
use dns;
use parking_lot::{Mutex, RwLock};
use plugins::{PacketAction, PluginManager};
use prometheus::{Encoder, TextEncoder};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection, StreamOwned};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;
use std::time::Duration as StdDuration;
use url::Url;
use varz::Varz;

const TCP_SESSION_PREFETCH_MAX: usize = 4;
const TCP_SESSION_PREFETCH_READ_TIMEOUT_MS: u64 = 5;

trait SessionStream: Read + Write {
    fn set_read_timeout(&self, timeout: Option<StdDuration>) -> io::Result<()>;
}

impl SessionStream for TcpStream {
    fn set_read_timeout(&self, timeout: Option<StdDuration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }
}

impl SessionStream for StreamOwned<ServerConnection, TcpStream> {
    fn set_read_timeout(&self, timeout: Option<StdDuration>) -> io::Result<()> {
        self.sock.set_read_timeout(timeout)
    }
}

pub struct BalanceDnsRuntime {
    config: Config,
    cache: Cache,
    local_hosts: HashMap<String, IpAddr>,
    remote_hosts: RwLock<HashMap<String, IpAddr>>,
    remote_blocklist: RwLock<HashSet<String>>,
    plugins: PluginManager,
    rr_counter: AtomicUsize,
    varz: Arc<Varz>,
    http_client: Client,
    stale_refresh_inflight: Mutex<HashSet<dns::NormalizedQuestionKey>>,
}

struct InflightQueryGuard<'a> {
    varz: &'a Varz,
}

impl<'a> InflightQueryGuard<'a> {
    fn new(varz: &'a Varz) -> Self {
        varz.inflight_queries.inc();
        InflightQueryGuard { varz }
    }
}

impl<'a> Drop for InflightQueryGuard<'a> {
    fn drop(&mut self) {
        self.varz.inflight_queries.dec();
    }
}

impl BalanceDnsRuntime {
    pub fn new(config: Config, varz: Arc<Varz>) -> Arc<Self> {
        let local_hosts = config
            .hosts_local
            .iter()
            .filter_map(|(name, ip)| ip.parse().ok().map(|ip| (name.clone(), ip)))
            .collect::<HashMap<String, IpAddr>>();
        let http_client = Client::builder()
            .connect_timeout(StdDuration::from_millis((config.request_timeout_ms / 2).max(500)))
            .pool_max_idle_per_host(16)
            .pool_idle_timeout(Some(StdDuration::from_secs(90)))
            .tcp_keepalive(Some(StdDuration::from_secs(30)))
            .timeout(StdDuration::from_millis(config.request_timeout_ms))
            .build()
            .expect("Unable to initialize HTTP client");
        Arc::new(BalanceDnsRuntime {
            cache: Cache::new(config.clone()),
            config: config.clone(),
            local_hosts,
            remote_hosts: RwLock::new(HashMap::new()),
            remote_blocklist: RwLock::new(HashSet::new()),
            plugins: PluginManager::from_paths(&config.plugin_libraries),
            rr_counter: AtomicUsize::new(0),
            varz,
            http_client,
            stale_refresh_inflight: Mutex::new(HashSet::new()),
        })
    }

    pub fn run(self: &Arc<Self>) -> io::Result<()> {
        self.spawn_refreshers();
        let mut handles = Vec::new();
        if let Some(ref listen_addr) = self.config.udp_listen_addr {
            handles.push(self.spawn_udp_listener(listen_addr.clone())?);
        }
        if let Some(ref listen_addr) = self.config.tcp_listen_addr {
            handles.push(self.spawn_tcp_listener(listen_addr.clone())?);
        }
        if let Some(ref listen_addr) = self.config.dot_listen_addr {
            handles.push(self.spawn_dot_listener(listen_addr.clone())?);
        }
        if let Some(ref listen_addr) = self.config.doh_listen_addr {
            handles.push(self.spawn_doh_listener(listen_addr.clone())?);
        }
        if self.config.webservice_enabled {
            handles.push(self.spawn_metrics_listener(self.config.webservice_listen_addr.clone())?);
        }
        if handles.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No listeners have been configured",
            ));
        }
        info!("BalanceDNS is ready to process requests");
        for handle in handles {
            let _ = handle.join();
        }
        Ok(())
    }

    fn spawn_refreshers(self: &Arc<Self>) {
        if self.config.hosts_remote.is_some() {
            let runtime = self.clone();
            thread::Builder::new()
                .name("remote_hosts_refresh".to_string())
                .spawn(move || {
                    runtime.refresh_remote_hosts_loop();
                })
                .unwrap();
        }
        if self.config.blocklist_remote.is_some() {
            let runtime = self.clone();
            thread::Builder::new()
                .name("remote_blocklist_refresh".to_string())
                .spawn(move || {
                    runtime.refresh_remote_blocklist_loop();
                })
                .unwrap();
        }
    }

    fn spawn_udp_listener(self: &Arc<Self>, listen_addr: String) -> io::Result<thread::JoinHandle<()>> {
        let socket = UdpSocket::bind(&listen_addr)?;
        let sender_socket = socket.try_clone()?;
        let default_workers = thread::available_parallelism()
            .map(|parallelism| parallelism.get())
            .unwrap_or(4)
            .min(8);
        let worker_count = if self.config.udp_acceptor_threads > 1 {
            self.config.udp_acceptor_threads
        } else {
            default_workers.max(2)
        };
        let (tx, rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>();
        let rx = Arc::new(Mutex::new(rx));
        for worker_id in 0..worker_count {
            let runtime = self.clone();
            let socket = sender_socket.try_clone()?;
            let rx = rx.clone();
            thread::Builder::new()
                .name(format!("balancedns_udp_worker_{}", worker_id))
                .spawn(move || loop {
                    let (addr, packet) = match rx.lock().recv() {
                        Ok(job) => job,
                        Err(_) => break,
                    };
                    runtime.varz.client_queries.inc();
                    runtime.varz.client_queries_udp.inc();
                    match runtime.process_query(&packet) {
                        Ok(response) => {
                            let _ = socket.send_to(&response, addr);
                        }
                        Err(err) => {
                            runtime.varz.client_queries_errors.inc();
                            debug!("UDP query failed from {}: {}", addr, err);
                        }
                    }
                })
                .unwrap();
        }
        info!("UDP listener is ready on {}", listen_addr);
        thread::Builder::new()
            .name("balancedns_udp".to_string())
            .spawn(move || {
                let mut buf = [0u8; 65535];
                loop {
                    match socket.recv_from(&mut buf) {
                        Ok((len, addr)) => {
                            let packet = buf[..len].to_vec();
                            if tx.send((addr, packet)).is_err() {
                                error!("UDP worker queue unexpectedly closed on {}", listen_addr);
                                break;
                            }
                        }
                        Err(err) => {
                            error!("UDP listener error on {}: {}", listen_addr, err);
                        }
                    }
                }
            })
    }

    fn spawn_tcp_listener(self: &Arc<Self>, listen_addr: String) -> io::Result<thread::JoinHandle<()>> {
        let listener = TcpListener::bind(&listen_addr)?;
        info!("TCP listener is ready on {}", listen_addr);
        thread::Builder::new()
            .name("balancedns_tcp".to_string())
            .spawn({
                let runtime = self.clone();
                move || loop {
                    match listener.accept() {
                        Ok((stream, addr)) => {
                            let runtime = runtime.clone();
                            thread::spawn(move || {
                                let _ = stream.set_nodelay(true);
                                if let Err(err) = runtime.handle_tcp_session(stream) {
                                    debug!("TCP session closed for {}: {}", addr, err);
                                }
                            });
                        }
                        Err(err) => error!("TCP accept error on {}: {}", listen_addr, err),
                    }
                }
            })
    }

    fn spawn_dot_listener(self: &Arc<Self>, listen_addr: String) -> io::Result<thread::JoinHandle<()>> {
        let listener = TcpListener::bind(&listen_addr)?;
        let tls_config = Arc::new(load_tls_server_config(
            &self.config,
            TlsApplicationProtocol::Dns,
        )?);
        info!("DoT listener is ready on {}", listen_addr);
        thread::Builder::new()
            .name("balancedns_dot".to_string())
            .spawn({
                let runtime = self.clone();
                move || loop {
                    match listener.accept() {
                        Ok((stream, addr)) => {
                            let runtime = runtime.clone();
                            let tls_config = tls_config.clone();
                            thread::spawn(move || {
                                let _ = stream.set_nodelay(true);
                                let connection = ServerConnection::new(tls_config).map_err(io::Error::other);
                                match connection {
                                    Ok(connection) => {
                                        let tls_stream = StreamOwned::new(connection, stream);
                                        if let Err(err) = runtime.handle_tls_session(tls_stream) {
                                            debug!("DoT session closed for {}: {}", addr, err);
                                        }
                                    }
                                    Err(err) => debug!("DoT TLS error for {}: {}", addr, err),
                                }
                            });
                        }
                        Err(err) => error!("DoT accept error on {}: {}", listen_addr, err),
                    }
                }
            })
    }

    fn spawn_doh_listener(self: &Arc<Self>, listen_addr: String) -> io::Result<thread::JoinHandle<()>> {
        let listener = TcpListener::bind(&listen_addr)?;
        let tls_config = Arc::new(load_tls_server_config(
            &self.config,
            TlsApplicationProtocol::Http11,
        )?);
        info!("DoH listener is ready on https://{}/dns-query", listen_addr);
        thread::Builder::new()
            .name("balancedns_doh".to_string())
            .spawn({
                let runtime = self.clone();
                move || loop {
                    match listener.accept() {
                        Ok((stream, addr)) => {
                            let runtime = runtime.clone();
                            let tls_config = tls_config.clone();
                            thread::spawn(move || {
                                let _ = stream.set_nodelay(true);
                                let connection = ServerConnection::new(tls_config).map_err(io::Error::other);
                                match connection {
                                    Ok(connection) => {
                                        let mut tls_stream = StreamOwned::new(connection, stream);
                                        if let Err(err) = runtime.handle_doh_session(&mut tls_stream) {
                                            debug!("DoH session closed for {}: {}", addr, err);
                                        }
                                    }
                                    Err(err) => debug!("DoH TLS error for {}: {}", addr, err),
                                }
                            });
                        }
                        Err(err) => error!("DoH accept error on {}: {}", listen_addr, err),
                    }
                }
            })
    }

    fn spawn_metrics_listener(self: &Arc<Self>, listen_addr: String) -> io::Result<thread::JoinHandle<()>> {
        let listener = TcpListener::bind(&listen_addr)?;
        info!("Metrics listener is ready on http://{}/metrics", listen_addr);
        thread::Builder::new()
            .name("balancedns_metrics".to_string())
            .spawn({
                let runtime = self.clone();
                move || loop {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            if let Err(err) = runtime.handle_metrics_session(&mut stream) {
                                if err.kind() != io::ErrorKind::UnexpectedEof {
                                    debug!("Metrics session failed on {}: {}", listen_addr, err);
                                    let _ = write_http_response(
                                        &mut stream,
                                        "400 Bad Request",
                                        "text/plain; charset=utf-8",
                                        err.to_string().as_bytes(),
                                    );
                                }
                            }
                        }
                        Err(err) => error!("Metrics accept error on {}: {}", listen_addr, err),
                    }
                }
            })
    }

    fn handle_tcp_session<S: SessionStream>(self: &Arc<Self>, mut stream: S) -> io::Result<()> {
        stream.set_read_timeout(Some(StdDuration::from_millis(
            TCP_SESSION_PREFETCH_READ_TIMEOUT_MS,
        )))?;
        let mut pending_bytes = Vec::new();
        let mut prefetched_packets = VecDeque::new();
        let mut stream_ended = false;

        loop {
            prefetch_tcp_packets(
                &mut stream,
                &mut pending_bytes,
                &mut prefetched_packets,
                &mut stream_ended,
            )?;

            let packet = match prefetched_packets.pop_front() {
                Some(packet) => packet,
                None if stream_ended => {
                    return if pending_bytes.is_empty() {
                        Ok(())
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Truncated DNS packet on TCP session",
                        ))
                    };
                }
                None => {
                    let mut len_buf = [0u8; 2];
                    match stream.read_exact(&mut len_buf) {
                        Ok(_) => {}
                        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                        Err(err) => return Err(err),
                    }
                    let packet_len = ((len_buf[0] as usize) << 8) | len_buf[1] as usize;
                    if packet_len < 12 || packet_len > 65535 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Suspicious DNS packet size",
                        ));
                    }
                    let mut packet = vec![0u8; packet_len];
                    stream.read_exact(&mut packet)?;
                    packet
                }
            };

            self.varz.client_queries.inc();
            self.varz.client_queries_tcp.inc();
            let response = self.process_query(&packet)?;
            write_tcp_response_frame(&mut stream, &response)?;
        }
    }

    fn handle_tls_session<S: Read + Write>(self: &Arc<Self>, mut stream: S) -> io::Result<()> {
        loop {
            let packet = match read_tcp_query_frame(&mut stream) {
                Ok(packet) => packet,
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(err) => return Err(err),
            };
            self.varz.client_queries.inc();
            self.varz.client_queries_tcp.inc();
            let response = self.process_query(&packet)?;
            write_tcp_response_frame(&mut stream, &response)?;
        }
    }

    fn handle_doh_session<S: Read + Write>(self: &Arc<Self>, stream: &mut S) -> io::Result<()> {
        let request = read_http_request(stream)?;
        if http_target_path(&request.target)? != "/dns-query" {
            write_http_response(
                stream,
                "404 Not Found",
                "text/plain; charset=utf-8",
                b"not found",
            )?;
            return Ok(());
        }
        let body = match request.method.as_str() {
            "GET" => parse_doh_get_request(&request.target)?,
            "POST" => {
                let content_type = request
                    .headers
                    .get("content-type")
                    .cloned()
                    .unwrap_or_default();
                if !content_type.contains("application/dns-message") {
                    write_http_response(
                        stream,
                        "415 Unsupported Media Type",
                        "text/plain; charset=utf-8",
                        b"unsupported content-type",
                    )?;
                    return Ok(());
                }
                request.body
            }
            _ => {
                write_http_response(
                    stream,
                    "405 Method Not Allowed",
                    "text/plain; charset=utf-8",
                    b"method not allowed",
                )?;
                return Ok(());
            }
        };
        self.varz.client_queries.inc();
        self.varz.client_queries_tcp.inc();
        match self.process_query(&body) {
            Ok(response) => write_http_response(
                stream,
                "200 OK",
                "application/dns-message",
                &response,
            ),
            Err(err) => write_http_response(
                stream,
                "500 Internal Server Error",
                "text/plain; charset=utf-8",
                err.to_string().as_bytes(),
            ),
        }
    }

    fn process_query(self: &Arc<Self>, packet: &[u8]) -> io::Result<Vec<u8>> {
        let _inflight_query = InflightQueryGuard::new(&self.varz);
        let mut packet = packet.to_vec();
        if let Some(action) = self.plugins.apply_pre_query(&packet)? {
            match action {
                PacketAction::Continue(updated) => packet = updated,
                PacketAction::Respond(response) => return self.plugins.apply_post_response(&response),
            }
        }
        let normalized_question = dns::normalize(&packet, true)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let fqdn = dns::qname_to_fqdn(&normalized_question.qname)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

        if self.config.deny_any && normalized_question.qtype == dns::DNS_TYPE_ANY {
            return Ok(dns::build_refused_packet(&normalized_question)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?);
        }
        if self.config.deny_dnskey && normalized_question.qtype == dns::DNS_TYPE_DNSKEY {
            return Ok(dns::build_refused_packet(&normalized_question)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?);
        }
        if self.is_blocked(&fqdn) {
            return Ok(dns::build_nxdomain_packet(&normalized_question)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?);
        }
        if let Some((ip_addr, ttl)) = self.lookup_host(&fqdn) {
            let response = dns::build_address_packet(&normalized_question, ip_addr, ttl)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            return self.plugins.apply_post_response(&response);
        }

        if self.config.cache_enabled {
            let cache_entry = self.cache.get2(&normalized_question);
            if let Some(cache_entry) = cache_entry {
                if cache_entry.is_expired() {
                    self.varz.client_queries_expired.inc();
                    if self.config.stale_refresh_enabled
                        && cache_entry.is_servable_stale(self.config.stale_ttl_seconds)
                    {
                        self.schedule_stale_refresh(
                            normalized_question.clone(),
                            normalized_question.key(),
                            fqdn.clone(),
                        );
                        self.varz.client_queries_cached.inc();
                        let mut cached_packet = cache_entry.packet.clone();
                        let _ = dns::set_ttl(&mut cached_packet, 1);
                        dns::set_tid(&mut cached_packet, normalized_question.tid);
                        return self.plugins.apply_post_response(&cached_packet);
                    }
                } else {
                    self.varz.client_queries_cached.inc();
                    let mut cached_packet = cache_entry.packet.clone();
                    dns::set_tid(&mut cached_packet, normalized_question.tid);
                    return self.plugins.apply_post_response(&cached_packet);
                }
            }
        }

        let response = self.resolve_via_upstreams(&normalized_question, &fqdn)?;
        let response = self.plugins.apply_post_response(&response)?;
        if self.config.cache_enabled {
            let ttl = dns::min_ttl(
                &response,
                self.config.min_ttl,
                self.config.max_ttl,
                self.config.cache_ttl_seconds,
            )
            .unwrap_or(self.config.cache_ttl_seconds);
            let _ = self
                .cache
                .insert(normalized_question.key(), response.clone(), ttl);
        }
        self.update_cache_metrics();
        Ok(response)
    }

    fn schedule_stale_refresh(
        self: &Arc<Self>,
        normalized_question: dns::NormalizedQuestion,
        cache_key: dns::NormalizedQuestionKey,
        fqdn: String,
    ) {
        {
            let mut inflight = self.stale_refresh_inflight.lock();
            if inflight.contains(&cache_key) {
                return;
            }
            inflight.insert(cache_key.clone());
        }

        let runtime = self.clone();
        thread::spawn(move || {
            let refresh_result = runtime
                .resolve_via_upstreams(&normalized_question, &fqdn)
                .and_then(|response| runtime.plugins.apply_post_response(&response));

            if let Ok(response) = refresh_result {
                let ttl = dns::min_ttl(
                    &response,
                    runtime.config.min_ttl,
                    runtime.config.max_ttl,
                    runtime.config.cache_ttl_seconds,
                )
                .unwrap_or(runtime.config.cache_ttl_seconds);
                let _ = runtime.cache.insert(cache_key.clone(), response, ttl);
                runtime.update_cache_metrics();
            }

            runtime.stale_refresh_inflight.lock().remove(&cache_key);
        });
    }

    fn handle_metrics_session<S: Read + Write>(&self, stream: &mut S) -> io::Result<()> {
        let request = read_http_request(stream)?;
        if request.method != "GET" && request.method != "HEAD" {
            write_http_response(
                stream,
                "405 Method Not Allowed",
                "text/plain; charset=utf-8",
                b"method not allowed",
            )?;
            return Ok(());
        }
        if http_target_path(&request.target)? != "/metrics" {
            write_http_response(
                stream,
                "404 Not Found",
                "text/plain; charset=utf-8",
                b"not found",
            )?;
            return Ok(());
        }
        self.snapshot_metrics();
        let mut metrics = Vec::new();
        let encoder = TextEncoder::new();
        match encoder.encode(&prometheus::gather(), &mut metrics) {
            Ok(_) => {
                if request.method == "HEAD" {
                    write_http_response(stream, "200 OK", encoder.format_type(), b"")
                } else {
                    write_http_response(stream, "200 OK", encoder.format_type(), &metrics)
                }
            }
            Err(err) => write_http_response(
                stream,
                "500 Internal Server Error",
                "text/plain; charset=utf-8",
                err.to_string().as_bytes(),
            ),
        }
    }

    fn resolve_via_upstreams(
        &self,
        normalized_question: &dns::NormalizedQuestion,
        fqdn: &str,
    ) -> io::Result<Vec<u8>> {
        let (query_packet, upstream_question) = dns::build_query_packet(normalized_question, false)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let upstreams = self.ordered_upstreams(fqdn);
        let total_timeout = StdDuration::from_millis(self.config.request_timeout_ms);
        let started_at = std::time::Instant::now();
        let mut last_err = None;
        for upstream in upstreams {
            let elapsed = started_at.elapsed();
            if elapsed >= total_timeout {
                last_err = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Overall upstream resolution timed out",
                ));
                break;
            }
            let remaining_timeout = total_timeout.saturating_sub(elapsed);
            self.varz.upstream_sent.inc();
            match self.query_upstream(
                &upstream,
                &query_packet,
                &upstream_question,
                normalized_question.tid,
                remaining_timeout,
            ) {
                Ok(response) => {
                    self.varz.upstream_received.inc();
                    return Ok(response);
                }
                Err(err) => {
                    if is_timeout_error(&err) {
                        self.varz.upstream_timeout.inc();
                    } else {
                        self.varz.upstream_errors.inc();
                    }
                    last_err = Some(err);
                }
            }
        }
        let fallback = dns::build_servfail_packet(normalized_question)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        if let Some(err) = last_err {
            debug!("All upstreams failed: {}", err);
        }
        Ok(fallback)
    }

    fn query_upstream(
        &self,
        upstream: &UpstreamConfig,
        query_packet: &[u8],
        upstream_question: &dns::NormalizedQuestionMinimal,
        client_tid: u16,
        timeout: StdDuration,
    ) -> io::Result<Vec<u8>> {
        let started_at = Instant::now();
        let mut response = match upstream.proto {
            UpstreamProtocol::Udp => self.query_udp_upstream(upstream, query_packet, timeout)?,
            UpstreamProtocol::Doh => self.query_doh_upstream(upstream, query_packet, timeout)?,
        };
        let normalized_response = dns::normalize(&response, false)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        if normalized_response.tid != upstream_question.tid
            || normalized_response.qtype != upstream_question.qtype
            || normalized_response.qclass != upstream_question.qclass
            || dns::qname_to_fqdn(&normalized_response.qname)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
                != dns::qname_to_fqdn(&upstream_question.qname)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Upstream [{}] returned a mismatched response", upstream.name),
            ));
        }
        let sample_rtt = started_at.elapsed().as_secs_f64();
        let current_rtt = self.varz.upstream_avg_rtt.get();
        let updated_rtt = if current_rtt == 0.0 {
            sample_rtt
        } else {
            (current_rtt * 0.8) + (sample_rtt * 0.2)
        };
        self.varz.upstream_avg_rtt.set(updated_rtt);
        self.varz
            .upstream_response_sizes
            .observe(response.len() as f64);
        dns::set_tid(&mut response, client_tid);
        Ok(response)
    }

    fn query_udp_upstream(
        &self,
        upstream: &UpstreamConfig,
        query_packet: &[u8],
        timeout: StdDuration,
    ) -> io::Result<Vec<u8>> {
        let remote_addr: SocketAddr = upstream
            .addr
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing upstream addr"))?
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid upstream addr"))?;
        let bind_addr = match remote_addr {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;
        socket.send_to(query_packet, remote_addr)?;
        let mut buf = [0u8; 65535];
        let (len, _) = socket.recv_from(&mut buf)?;
        Ok(buf[..len].to_vec())
    }

    fn query_doh_upstream(
        &self,
        upstream: &UpstreamConfig,
        query_packet: &[u8],
        timeout: StdDuration,
    ) -> io::Result<Vec<u8>> {
        let url = upstream
            .url
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing upstream url"))?;
        let response = self
            .http_client
            .post(url)
            .header(ACCEPT, "application/dns-message")
            .header(CONTENT_TYPE, "application/dns-message")
            .timeout(timeout)
            .body(query_packet.to_vec())
            .send()
            .and_then(|response| response.error_for_status())
            .map_err(map_http_client_error)?;
        response
            .bytes()
            .map(|body| body.to_vec())
            .map_err(map_http_client_error)
    }

    fn ordered_upstreams(&self, fqdn: &str) -> Vec<UpstreamConfig> {
        route_upstreams_for_fqdn(
            fqdn,
            &self.config.routing_rules,
            &self.config.upstreams,
            &self.config.balancing_algorithm,
            &self.rr_counter,
        )
    }

    fn lookup_host(&self, fqdn: &str) -> Option<(IpAddr, u32)> {
        if let Some(ip_addr) = self.local_hosts.get(fqdn).copied() {
            return Some((ip_addr, self.config.cache_ttl_seconds));
        }
        self.remote_hosts
            .read()
            .get(fqdn)
            .copied()
            .map(|ip| {
                let ttl = self
                    .config
                    .hosts_remote
                    .as_ref()
                    .map_or(self.config.cache_ttl_seconds, |cfg| cfg.ttl_seconds);
                (ip, ttl)
            })
    }

    fn is_blocked(&self, fqdn: &str) -> bool {
        self.remote_blocklist.read().contains(fqdn)
    }

    fn refresh_remote_hosts_loop(&self) {
        let config = match self.config.hosts_remote.clone() {
            Some(config) => config,
            None => return,
        };
        loop {
            match fetch_text(&self.http_client, &config.url) {
                Ok(body) => {
                    let hosts = parse_hosts_mapping(&body);
                    *self.remote_hosts.write() = hosts;
                    info!("Loaded {} remote host overrides", self.remote_hosts.read().len());
                }
                Err(err) => error!("Unable to refresh remote hosts [{}]: {}", config.url, err),
            }
            thread::sleep(StdDuration::from_secs(config.refresh_seconds));
        }
    }

    fn refresh_remote_blocklist_loop(&self) {
        let config = match self.config.blocklist_remote.clone() {
            Some(config) => config,
            None => return,
        };
        loop {
            match fetch_text(&self.http_client, &config.url) {
                Ok(body) => {
                    let entries = parse_blocklist(&body);
                    *self.remote_blocklist.write() = entries;
                    info!("Loaded {} remote blocked domains", self.remote_blocklist.read().len());
                }
                Err(err) => error!("Unable to refresh blocklist [{}]: {}", config.url, err),
            }
            thread::sleep(StdDuration::from_secs(config.refresh_seconds));
        }
    }

    fn update_cache_metrics(&self) {
        let stats = self.cache.stats();
        self.varz.cache_frequent_len.set(stats.frequent_len as f64);
        self.varz.cache_recent_len.set(stats.recent_len as f64);
        self.varz.cache_test_len.set(stats.test_len as f64);
        self.varz.cache_inserted.set(stats.inserted as f64);
        self.varz.cache_evicted.set(stats.evicted as f64);
    }

    fn snapshot_metrics(&self) {
        self.varz.snapshot();
        self.update_cache_metrics();
    }
}

fn parse_hosts_mapping(body: &str) -> HashMap<String, IpAddr> {
    let mut hosts = HashMap::new();
    for line in body.lines() {
        let line = strip_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        let tokens = line.split_whitespace().collect::<Vec<&str>>();
        if tokens.len() == 1 {
            continue;
        }
        let (ip_str, names) = if tokens[0].parse::<IpAddr>().is_ok() {
            (tokens[0], &tokens[1..])
        } else if tokens[tokens.len() - 1].parse::<IpAddr>().is_ok() {
            (tokens[tokens.len() - 1], &tokens[..tokens.len() - 1])
        } else if tokens.len() == 2 && tokens[1].contains('=') {
            continue;
        } else if tokens.len() == 2 {
            (tokens[1], &tokens[..1])
        } else {
            continue;
        };
        if let Ok(ip_addr) = ip_str.parse::<IpAddr>() {
            for name in names {
                hosts.insert(normalize_domain(name), ip_addr);
            }
        }
    }
    hosts
}

fn parse_blocklist(body: &str) -> HashSet<String> {
    let mut blocked = HashSet::new();
    for line in body.lines() {
        let line = strip_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        let tokens = line.split_whitespace().collect::<Vec<&str>>();
        if tokens.is_empty() {
            continue;
        }
        if tokens[0].parse::<IpAddr>().is_ok() {
            for name in &tokens[1..] {
                blocked.insert(normalize_domain(name));
            }
            continue;
        }
        if tokens.len() == 2 && tokens[1].parse::<IpAddr>().is_ok() {
            blocked.insert(normalize_domain(tokens[0]));
            continue;
        }
        blocked.insert(normalize_domain(tokens[0]));
    }
    blocked
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    }
}

fn normalize_domain(value: &str) -> String {
    let mut normalized = value.trim().trim_matches('`').trim().to_ascii_lowercase();
    if !normalized.ends_with('.') {
        normalized.push('.');
    }
    normalized
}

fn fetch_text(client: &Client, url: &str) -> io::Result<String> {
    client
        .get(url)
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
        .text()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}

enum TlsApplicationProtocol {
    Dns,
    Http11,
}

fn load_tls_server_config(
    config: &Config,
    application_protocol: TlsApplicationProtocol,
) -> io::Result<ServerConfig> {
    let cert_path = config
        .tls_cert_pem
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "tls.cert_pem is required"))?;
    let key_path = config
        .tls_key_pem
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "tls.key_pem is required"))?;
    let mut cert_reader = BufReader::new(File::open(cert_path)?);
    let cert_chain = certs(&mut cert_reader)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid TLS certificate"))?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<Certificate>>();
    let mut key_reader = BufReader::new(File::open(key_path)?);
    let mut private_keys = pkcs8_private_keys(&mut key_reader)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid PKCS#8 TLS key"))?;
    if private_keys.is_empty() {
        let mut key_reader = BufReader::new(File::open(key_path)?);
        private_keys = rsa_private_keys(&mut key_reader)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid RSA TLS key"))?;
    }
    let private_key = private_keys
        .into_iter()
        .next()
        .map(PrivateKey)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TLS private key is missing"))?;
    let mut server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(io::Error::other)?;
    if let TlsApplicationProtocol::Http11 = application_protocol {
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    }
    Ok(server_config)
}

struct HttpRequest {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn read_http_request<S: Read>(stream: &mut S) -> io::Result<HttpRequest> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        let count = stream.read(&mut buf)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unexpected EOF while reading HTTP headers",
            ));
        }
        raw.push(buf[0]);
        if raw.len() > 65_536 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP headers are too large",
            ));
        }
    }
    let header_text = String::from_utf8(raw).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request headers are not valid UTF-8",
        )
    })?;
    let mut lines = header_text.split("\r\n").filter(|line| !line.is_empty());
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing HTTP request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing HTTP method"))?
        .to_owned();
    let target = request_parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing HTTP target"))?
        .to_owned();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some(idx) = line.find(':') {
            headers.insert(
                line[..idx].trim().to_ascii_lowercase(),
                line[idx + 1..].trim().to_owned(),
            );
        }
    }
    let content_length = headers
        .get("content-length")
        .and_then(|x| x.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        stream.read_exact(&mut body)?;
    }
    Ok(HttpRequest {
        method,
        target,
        headers,
        body,
    })
}

fn parse_doh_get_request(target: &str) -> io::Result<Vec<u8>> {
    let url = Url::parse(&format!("https://placeholder{}", target))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid DoH target"))?;
    let dns_param = url
        .query_pairs()
        .find_map(|(key, value)| if key == "dns" { Some(value.into_owned()) } else { None })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing dns parameter"))?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(dns_param.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid DoH dns parameter"))
}

fn http_target_path(target: &str) -> io::Result<String> {
    Url::parse(&format!("https://placeholder{}", target))
        .map(|url| url.path().to_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid HTTP target"))
}

fn map_http_client_error(err: reqwest::Error) -> io::Error {
    if err.is_timeout() {
        io::Error::new(io::ErrorKind::TimedOut, err.to_string())
    } else {
        io::Error::new(io::ErrorKind::Other, err.to_string())
    }
}

fn is_timeout_error(err: &io::Error) -> bool {
    matches!(err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
}

fn same_upstream(left: &UpstreamConfig, right: &UpstreamConfig) -> bool {
    left.name == right.name && left.proto == right.proto && left.addr == right.addr && left.url == right.url
}

fn select_upstreams(
    upstreams: &[UpstreamConfig],
    balancing_algorithm: &str,
    rr_counter: &AtomicUsize,
) -> Vec<UpstreamConfig> {
    if upstreams.is_empty() {
        return Vec::new();
    }

    let mut weighted_indices = Vec::new();
    for (index, upstream) in upstreams.iter().enumerate() {
        let copies = if upstream.weight == 0 { 1 } else { upstream.weight };
        for _ in 0..copies {
            weighted_indices.push(index);
        }
    }

    let primary_index = if weighted_indices.is_empty() {
        0
    } else {
        let start = match balancing_algorithm {
            "round_robin" => rr_counter.fetch_add(1, Ordering::Relaxed) % weighted_indices.len(),
            _ => 0,
        };
        weighted_indices[start]
    };

    let mut remaining_indices = (0..upstreams.len())
        .filter(|index| *index != primary_index)
        .collect::<Vec<_>>();
    remaining_indices.sort_by(|left, right| {
        upstreams[*right]
            .weight
            .cmp(&upstreams[*left].weight)
            .then_with(|| left.cmp(right))
    });

    let mut ordered = Vec::with_capacity(upstreams.len());
    ordered.push(upstreams[primary_index].clone());
    for index in remaining_indices {
        if !ordered.iter().any(|existing| same_upstream(existing, &upstreams[index])) {
            ordered.push(upstreams[index].clone());
        }
    }
    ordered
}

fn route_upstreams_for_fqdn(
    fqdn: &str,
    routing_rules: &[RoutingRuleConfig],
    upstreams: &[UpstreamConfig],
    balancing_algorithm: &str,
    rr_counter: &AtomicUsize,
) -> Vec<UpstreamConfig> {
    let ordered = select_upstreams(upstreams, balancing_algorithm, rr_counter);
    if ordered.is_empty() {
        return ordered;
    }
    let matched_rule = routing_rules
        .iter()
        .find(|rule| fqdn_matches_suffix(fqdn, &rule.suffix));

    let Some(rule) = matched_rule else {
        return ordered;
    };

    let mut prioritized = Vec::new();
    for upstream_name in &rule.upstreams {
        if let Some(upstream) = ordered.iter().find(|upstream| upstream.name == *upstream_name) {
            prioritized.push(upstream.clone());
        }
    }

    for upstream in ordered {
        if !prioritized
            .iter()
            .any(|existing| same_upstream(existing, &upstream))
        {
            prioritized.push(upstream);
        }
    }
    prioritized
}

fn fqdn_matches_suffix(fqdn: &str, suffix: &str) -> bool {
    let fqdn = fqdn.to_ascii_lowercase();
    let suffix = suffix.to_ascii_lowercase();
    suffix == "." || fqdn.ends_with(&suffix)
}

fn prefetch_tcp_packets<S: SessionStream>(
    stream: &mut S,
    pending_bytes: &mut Vec<u8>,
    prefetched_packets: &mut VecDeque<Vec<u8>>,
    stream_ended: &mut bool,
) -> io::Result<()> {
    while prefetched_packets.len() < TCP_SESSION_PREFETCH_MAX {
        if let Some(packet) = try_take_tcp_frame(pending_bytes)? {
            prefetched_packets.push_back(packet);
            continue;
        }
        if *stream_ended {
            break;
        }
        let mut buf = [0u8; 4096];
        match stream.read(&mut buf) {
            Ok(0) => {
                *stream_ended = true;
                break;
            }
            Ok(read_len) => pending_bytes.extend_from_slice(&buf[..read_len]),
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn try_take_tcp_frame(buffer: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
    if buffer.len() < 2 {
        return Ok(None);
    }
    let packet_len = ((buffer[0] as usize) << 8) | buffer[1] as usize;
    if packet_len < 12 || packet_len > 65535 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Suspicious DNS packet size",
        ));
    }
    let frame_len = 2 + packet_len;
    if buffer.len() < frame_len {
        return Ok(None);
    }
    let packet = buffer[2..frame_len].to_vec();
    buffer.drain(..frame_len);
    Ok(Some(packet))
}

fn read_tcp_query_frame<S: Read>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let packet_len = ((len_buf[0] as usize) << 8) | len_buf[1] as usize;
    if packet_len < 12 || packet_len > 65535 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Suspicious DNS packet size",
        ));
    }
    let mut packet = vec![0u8; packet_len];
    stream.read_exact(&mut packet)?;
    Ok(packet)
}

fn write_tcp_response_frame<S: Write>(stream: &mut S, response: &[u8]) -> io::Result<()> {
    let response_len = response.len();
    let response_prefix = [(response_len >> 8) as u8, response_len as u8];
    stream.write_all(&response_prefix)?;
    stream.write_all(response)?;
    stream.flush()
}

fn write_http_response<S: Write>(
    stream: &mut S,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        content_type,
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::{route_upstreams_for_fqdn, select_upstreams, try_take_tcp_frame};
    use config::{RoutingRuleConfig, UpstreamConfig, UpstreamProtocol};
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn round_robin_prefers_weighted_primary_without_repeating_same_upstream() {
        let upstreams = vec![
            UpstreamConfig {
                name: "doh-a".to_owned(),
                proto: UpstreamProtocol::Doh,
                addr: None,
                url: Some("https://1.1.1.1/dns-query".to_owned()),
                pool: "default".to_owned(),
                weight: 1,
            },
            UpstreamConfig {
                name: "udp-a".to_owned(),
                proto: UpstreamProtocol::Udp,
                addr: Some("1.1.1.1:53".to_owned()),
                url: None,
                pool: "default".to_owned(),
                weight: 5,
            },
            UpstreamConfig {
                name: "udp-b".to_owned(),
                proto: UpstreamProtocol::Udp,
                addr: Some("8.8.8.8:53".to_owned()),
                url: None,
                pool: "default".to_owned(),
                weight: 5,
            },
        ];

        let rr_counter = AtomicUsize::new(1);
        let ordered = select_upstreams(&upstreams, "round_robin", &rr_counter);
        let names = ordered.into_iter().map(|upstream| upstream.name).collect::<Vec<_>>();

        assert_eq!(names[0], "udp-a");
        assert_eq!(names.len(), 3);
        assert_eq!(names.iter().filter(|name| name.as_str() == "udp-a").count(), 1);
    }

    #[test]
    fn tcp_frame_parser_extracts_complete_packet_and_keeps_tail() {
        let mut buffer = vec![0x00, 0x0c];
        buffer.extend_from_slice(&[0u8; 12]);
        buffer.extend_from_slice(&[0xaa, 0xbb, 0xcc]);

        let packet = try_take_tcp_frame(&mut buffer).unwrap().unwrap();

        assert_eq!(packet.len(), 12);
        assert_eq!(buffer, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn routing_rules_prioritize_named_upstreams() {
        let upstreams = vec![
            UpstreamConfig {
                name: "cloudflare-doh".to_owned(),
                proto: UpstreamProtocol::Doh,
                addr: None,
                url: Some("https://1.1.1.1/dns-query".to_owned()),
                pool: "default".to_owned(),
                weight: 1,
            },
            UpstreamConfig {
                name: "yandex-udp".to_owned(),
                proto: UpstreamProtocol::Udp,
                addr: Some("77.88.8.8:53".to_owned()),
                url: None,
                pool: "default".to_owned(),
                weight: 1,
            },
            UpstreamConfig {
                name: "cloudflare-udp".to_owned(),
                proto: UpstreamProtocol::Udp,
                addr: Some("1.1.1.1:53".to_owned()),
                url: None,
                pool: "default".to_owned(),
                weight: 5,
            },
            UpstreamConfig {
                name: "google-udp".to_owned(),
                proto: UpstreamProtocol::Udp,
                addr: Some("8.8.8.8:53".to_owned()),
                url: None,
                pool: "default".to_owned(),
                weight: 5,
            },
        ];
        let routing_rules = vec![
            RoutingRuleConfig {
                suffix: ".ru.".to_owned(),
                upstreams: vec!["yandex-udp".to_owned()],
            },
            RoutingRuleConfig {
                suffix: ".".to_owned(),
                upstreams: vec!["cloudflare-udp".to_owned(), "google-udp".to_owned()],
            },
        ];

        let rr_counter = AtomicUsize::new(0);
        let ru = route_upstreams_for_fqdn(
            "example.ru.",
            &routing_rules,
            &upstreams,
            "round_robin",
            &rr_counter,
        );
        let ru_names = ru.into_iter().map(|upstream| upstream.name).collect::<Vec<_>>();
        assert_eq!(ru_names[0], "yandex-udp");

        let rr_counter = AtomicUsize::new(0);
        let non_ru = route_upstreams_for_fqdn(
            "example.com.",
            &routing_rules,
            &upstreams,
            "round_robin",
            &rr_counter,
        );
        let non_ru_names = non_ru
            .into_iter()
            .map(|upstream| upstream.name)
            .collect::<Vec<_>>();
        assert_eq!(non_ru_names[0], "cloudflare-udp");
        assert_eq!(non_ru_names[1], "google-udp");
    }
}
