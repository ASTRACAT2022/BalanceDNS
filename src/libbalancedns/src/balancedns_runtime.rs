use crate::cache::Cache;
use crate::config::{Config, RoutingRuleConfig, UpstreamConfig, UpstreamProtocol};
use crate::dns;
use crate::odoh::OdohServer;
use crate::plugins::{PacketAction, PluginManager};
use crate::varz::Varz;
use base64;
use base64::Engine;
use crossbeam_channel::{bounded, Sender, TrySendError};
use log::{debug, error, info, warn};
use parking_lot::{Mutex, RwLock};
use prometheus::{Encoder, TextEncoder};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection, StreamOwned};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration as StdDuration;
use std::time::Instant;
use url::Url;

const TCP_SESSION_PREFETCH_MAX: usize = 4;
const TCP_SESSION_PREFETCH_READ_TIMEOUT_MS: u64 = 5;
const TCP_SESSION_MAX_QUERIES: usize = 1000; // Max queries per TCP/DoT/DoH session
const TCP_SESSION_IDLE_TIMEOUT_MS: u64 = 30000; // 30 seconds idle timeout

// Upstream query timeouts
const UPSTREAM_QUERY_MIN_TIMEOUT_MS: u64 = 100;
const UPSTREAM_QUERY_MAX_TIMEOUT_MS: u64 = 1000;
const UPSTREAM_QUERY_MAX_DEVIATION_COEFFICIENT: f64 = 2.0;
const UPSTREAM_PROBES_DELAY_MS: u64 = 5000;
const MAX_STALE_REFRESH_THREADS: usize = 8;
const DOH_MAX_BODY_SIZE: usize = 65535;
const UDP_UPSTREAM_SOCKET_POOL_MIN: usize = 32;
const UDP_UPSTREAM_SOCKET_POOL_MAX: usize = 256;
const UDP_WORK_QUEUE_PER_WORKER: usize = 1024;
const STREAM_WORK_QUEUE_MULTIPLIER: usize = 256;
const STREAM_WORK_QUEUE_MIN: usize = 256;
const STREAM_WORK_QUEUE_MAX: usize = 8192;

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
    routing_rules: Vec<RuntimeRoutingRule>,
    upstream_selection: UpstreamSelectionState,
    plugins: PluginManager,
    rr_counter: AtomicUsize,
    udp_socket_rr_counter: AtomicUsize,
    varz: Arc<Varz>,
    http_client: Client,
    stale_refresh_inflight: Mutex<HashSet<dns::NormalizedQuestionKey>>,
    stale_refresh_active: AtomicUsize,
    tcp_connection_count: AtomicUsize,
    upstream_udp_sockets: Vec<Mutex<UdpSocket>>,
    odoh_server: OdohServer,
}

struct RuntimeRoutingRule {
    suffix: String,
    prioritized_indices: Vec<usize>,
}

struct UpstreamSelectionState {
    cumulative_weights: Vec<usize>,
    total_weight: usize,
    fallback_indices: Vec<usize>,
}

impl UpstreamSelectionState {
    fn new(upstreams: &[UpstreamConfig]) -> Self {
        let mut cumulative_weights = Vec::with_capacity(upstreams.len());
        let mut total_weight = 0usize;
        for upstream in upstreams {
            total_weight = total_weight.saturating_add(upstream.weight.max(1));
            cumulative_weights.push(total_weight);
        }

        let mut fallback_indices = (0..upstreams.len()).collect::<Vec<_>>();
        fallback_indices.sort_by(|left, right| {
            upstreams[*right]
                .weight
                .cmp(&upstreams[*left].weight)
                .then_with(|| left.cmp(right))
        });

        Self {
            cumulative_weights,
            total_weight,
            fallback_indices,
        }
    }

    #[inline]
    fn ordered_indices(&self, balancing_algorithm: &str, rr_counter: &AtomicUsize) -> Vec<usize> {
        if self.fallback_indices.is_empty() {
            return Vec::new();
        }

        let primary_index = match balancing_algorithm {
            "round_robin" if self.total_weight > 0 => {
                let slot = rr_counter.fetch_add(1, Ordering::Relaxed) % self.total_weight;
                self.cumulative_weights.partition_point(|end| *end <= slot)
            }
            _ => 0,
        };

        let mut ordered = Vec::with_capacity(self.fallback_indices.len());
        ordered.push(primary_index);
        for &index in &self.fallback_indices {
            if index != primary_index {
                ordered.push(index);
            }
        }
        ordered
    }
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

struct StaleRefreshGuard<'a> {
    runtime: &'a BalanceDnsRuntime,
    cache_key: dns::NormalizedQuestionKey,
}

impl<'a> Drop for StaleRefreshGuard<'a> {
    fn drop(&mut self) {
        self.runtime
            .stale_refresh_inflight
            .lock()
            .remove(&self.cache_key);
        self.runtime
            .stale_refresh_active
            .fetch_sub(1, Ordering::Relaxed);
    }
}

impl BalanceDnsRuntime {
    pub fn new(config: Config, varz: Arc<Varz>) -> io::Result<Arc<Self>> {
        let local_hosts = config
            .hosts_local
            .iter()
            .filter_map(|(name, ip)| ip.parse().ok().map(|ip| (name.clone(), ip)))
            .collect::<HashMap<String, IpAddr>>();
        let routing_rules = compile_routing_rules(&config.routing_rules, &config.upstreams);
        let upstream_selection = UpstreamSelectionState::new(&config.upstreams);
        let http_client = Client::builder()
            .connect_timeout(StdDuration::from_millis(
                (config.request_timeout_ms / 2).max(500),
            ))
            .pool_max_idle_per_host(16)
            .pool_idle_timeout(Some(StdDuration::from_secs(90)))
            .tcp_keepalive(Some(StdDuration::from_secs(30)))
            .timeout(StdDuration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(io::Error::other)?;

        let odoh_server = OdohServer::new();

        // Pre-create a pool of UDP sockets for upstream queries
        let socket_pool_size = thread::available_parallelism()
            .map(|parallelism| {
                (parallelism.get() * 8)
                    .clamp(UDP_UPSTREAM_SOCKET_POOL_MIN, UDP_UPSTREAM_SOCKET_POOL_MAX)
            })
            .unwrap_or(64);
        let mut upstream_udp_sockets = Vec::with_capacity(socket_pool_size);
        for _ in 0..socket_pool_size {
            match bind_upstream_udp_socket() {
                Ok(sock) => upstream_udp_sockets.push(Mutex::new(sock)),
                Err(err) => {
                    log::warn!("Failed to pre-allocate upstream UDP socket: {}", err);
                }
            }
        }
        if upstream_udp_sockets.is_empty() {
            // Fallback: at least one
            upstream_udp_sockets.push(Mutex::new(bind_upstream_udp_socket()?));
        }

        Ok(Arc::new(BalanceDnsRuntime {
            cache: Cache::new(config.clone())?,
            config: config.clone(),
            local_hosts,
            remote_hosts: RwLock::new(HashMap::new()),
            remote_blocklist: RwLock::new(HashSet::new()),
            routing_rules,
            upstream_selection,
            plugins: PluginManager::from_config(&config.plugin_libraries, &config.lua_scripts),
            rr_counter: AtomicUsize::new(0),
            udp_socket_rr_counter: AtomicUsize::new(0),
            varz,
            http_client,
            stale_refresh_inflight: Mutex::new(HashSet::new()),
            stale_refresh_active: AtomicUsize::new(0),
            tcp_connection_count: AtomicUsize::new(0),
            upstream_udp_sockets,
            odoh_server,
        }))
    }

    pub fn run(self: &Arc<Self>) -> io::Result<()> {
        self.prime_remote_data_in_memory();
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
            match thread::Builder::new()
                .name("remote_hosts_refresh".to_string())
                .spawn(move || {
                    runtime.refresh_remote_hosts_loop();
                }) {
                Ok(_) => {}
                Err(e) => error!("Failed to spawn remote hosts refresh thread: {}", e),
            }
        }
        if self.config.blocklist_remote.is_some() {
            let runtime = self.clone();
            match thread::Builder::new()
                .name("remote_blocklist_refresh".to_string())
                .spawn(move || {
                    runtime.refresh_remote_blocklist_loop();
                }) {
                Ok(_) => {}
                Err(e) => error!("Failed to spawn blocklist refresh thread: {}", e),
            }
        }
    }

    fn prime_remote_data_in_memory(&self) {
        self.refresh_remote_hosts_once();
        self.refresh_remote_blocklist_once();
    }

    fn spawn_udp_listener(
        self: &Arc<Self>,
        listen_addr: String,
    ) -> io::Result<thread::JoinHandle<()>> {
        let socket = UdpSocket::bind(&listen_addr)?;
        let sender_socket = socket.try_clone()?;
        configure_udp_listener_socket(&socket)?;
        let default_workers = thread::available_parallelism()
            .map(|parallelism| parallelism.get())
            .unwrap_or(4)
            .min(8);
        let worker_count = if self.config.udp_acceptor_threads > 1 {
            self.config.udp_acceptor_threads
        } else {
            default_workers.max(2)
        };
        let (tx, rx) = bounded::<(SocketAddr, Vec<u8>)>(worker_count * UDP_WORK_QUEUE_PER_WORKER);
        for worker_id in 0..worker_count {
            let socket = sender_socket.try_clone()?;
            let rx = rx.clone();
            let runtime = self.clone();
            thread::Builder::new()
                .name(format!("balancedns_udp_worker_{}", worker_id))
                .spawn(move || loop {
                    let (addr, packet) = match rx.recv() {
                        Ok(job) => job,
                        Err(_) => break,
                    };
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        runtime.varz.client_queries.inc();
                        runtime.varz.client_queries_udp.inc();
                        match runtime.process_query(&packet) {
                            Ok(response) => {
                                if let Err(e) = socket.send_to(&response, addr) {
                                    runtime.varz.client_queries_errors.inc();
                                    debug!("UDP send error to {}: {}", addr, e);
                                }
                            }
                            Err(err) => {
                                runtime.varz.client_queries_errors.inc();
                                debug!("UDP query failed from {}: {}", addr, err);
                            }
                        }
                    }));
                    if let Err(panic_err) = result {
                        error!("UDP worker thread panicked for {}: {:?}", addr, panic_err);
                    }
                })
                .map_err(|err| io::Error::other(format!("Unable to spawn UDP worker: {}", err)))?;
        }
        info!("UDP listener is ready on {}", listen_addr);
        thread::Builder::new()
            .name("balancedns_udp".to_string())
            .spawn({
                let runtime = self.clone();
                move || {
                    let mut buf = [0u8; 65535];
                    loop {
                        match socket.recv_from(&mut buf) {
                            Ok((len, addr)) => {
                                let packet = buf[..len].to_vec();
                                match tx.try_send((addr, packet)) {
                                    Ok(()) => {}
                                    Err(TrySendError::Full((_addr, _packet))) => {
                                        runtime.varz.client_queries_dropped.inc();
                                        debug!(
                                            "UDP worker queue is full on {}, dropping packet",
                                            listen_addr
                                        );
                                    }
                                    Err(TrySendError::Disconnected((_addr, _packet))) => {
                                        error!(
                                            "UDP worker queue unexpectedly closed on {}",
                                            listen_addr
                                        );
                                        break;
                                    }
                                }
                            }
                            Err(err) => {
                                error!("UDP listener error on {}: {}", listen_addr, err);
                            }
                        }
                    }
                }
            })
    }

    fn spawn_tcp_listener(
        self: &Arc<Self>,
        listen_addr: String,
    ) -> io::Result<thread::JoinHandle<()>> {
        let listener = TcpListener::bind(&listen_addr)?;
        info!("TCP listener is ready on {}", listen_addr);
        let max_tcp = self.config.max_tcp_clients;
        let worker_count = stream_worker_count(self.config.tcp_acceptor_threads);
        let queue_capacity = stream_queue_capacity(worker_count, max_tcp);
        let (tx, rx) = bounded::<(TcpStream, SocketAddr)>(queue_capacity);

        for worker_id in 0..worker_count {
            let runtime = self.clone();
            let rx = rx.clone();
            thread::Builder::new()
                .name(format!("balancedns_tcp_worker_{}", worker_id))
                .spawn(move || {
                    while let Ok((stream, addr)) = rx.recv() {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            if let Err(err) = runtime.handle_tcp_session(stream) {
                                debug!("TCP session closed for {}: {}", addr, err);
                            }
                        }));
                        if let Err(panic_err) = result {
                            error!("TCP session worker panicked for {}: {:?}", addr, panic_err);
                        }
                        runtime.tcp_connection_count.fetch_sub(1, Ordering::Relaxed);
                    }
                })
                .map_err(|err| io::Error::other(format!("Unable to spawn TCP worker: {}", err)))?;
        }

        thread::Builder::new()
            .name("balancedns_tcp".to_string())
            .spawn({
                let runtime = self.clone();
                move || loop {
                    match listener.accept() {
                        Ok((stream, addr)) => {
                            let current = runtime.tcp_connection_count.load(Ordering::Relaxed);
                            if current >= max_tcp {
                                warn!(
                                    "TCP connection limit reached ({}/{}), rejecting {}",
                                    current, max_tcp, addr
                                );
                                runtime.varz.client_connections_rejected.inc();
                                drop(stream);
                                continue;
                            }
                            if let Err(err) = configure_accepted_stream(&stream) {
                                runtime.varz.client_connections_rejected.inc();
                                debug!("Failed to configure TCP stream for {}: {}", addr, err);
                                drop(stream);
                                continue;
                            }
                            runtime.tcp_connection_count.fetch_add(1, Ordering::Relaxed);
                            if let Err(err) = enqueue_stream(&tx, stream, addr) {
                                runtime.tcp_connection_count.fetch_sub(1, Ordering::Relaxed);
                                runtime.varz.client_connections_rejected.inc();
                                debug!("TCP queue rejected {}: {}", addr, err);
                            }
                        }
                        Err(err) => error!("TCP accept error on {}: {}", listen_addr, err),
                    }
                }
            })
    }

    fn spawn_dot_listener(
        self: &Arc<Self>,
        listen_addr: String,
    ) -> io::Result<thread::JoinHandle<()>> {
        let listener = TcpListener::bind(&listen_addr)?;
        let tls_config = Arc::new(load_tls_server_config(
            &self.config,
            TlsApplicationProtocol::Dns,
        )?);
        info!("DoT listener is ready on {}", listen_addr);
        let max_tcp = self.config.max_tcp_clients;
        let worker_count = stream_worker_count(self.config.tcp_acceptor_threads);
        let queue_capacity = stream_queue_capacity(worker_count, max_tcp);
        let (tx, rx) = bounded::<(TcpStream, SocketAddr)>(queue_capacity);

        for worker_id in 0..worker_count {
            let runtime = self.clone();
            let rx = rx.clone();
            let tls_config = tls_config.clone();
            thread::Builder::new()
                .name(format!("balancedns_dot_worker_{}", worker_id))
                .spawn(move || {
                    while let Ok((stream, addr)) = rx.recv() {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let connection =
                                ServerConnection::new(tls_config.clone()).map_err(io::Error::other);
                            match connection {
                                Ok(connection) => {
                                    let tls_stream = StreamOwned::new(connection, stream);
                                    if let Err(err) = runtime.handle_tls_session(tls_stream) {
                                        debug!("DoT session closed for {}: {}", addr, err);
                                    }
                                }
                                Err(err) => debug!("DoT TLS error for {}: {}", addr, err),
                            }
                        }));
                        if let Err(panic_err) = result {
                            error!("DoT session worker panicked for {}: {:?}", addr, panic_err);
                        }
                        runtime.tcp_connection_count.fetch_sub(1, Ordering::Relaxed);
                    }
                })
                .map_err(|err| io::Error::other(format!("Unable to spawn DoT worker: {}", err)))?;
        }
        thread::Builder::new()
            .name("balancedns_dot".to_string())
            .spawn({
                let runtime = self.clone();
                move || loop {
                    match listener.accept() {
                        Ok((stream, addr)) => {
                            let current = runtime.tcp_connection_count.load(Ordering::Relaxed);
                            if current >= max_tcp {
                                warn!(
                                    "DoT connection limit reached ({}/{}), rejecting {}",
                                    current, max_tcp, addr
                                );
                                runtime.varz.client_connections_rejected.inc();
                                drop(stream);
                                continue;
                            }
                            if let Err(err) = configure_accepted_stream(&stream) {
                                runtime.varz.client_connections_rejected.inc();
                                debug!("Failed to configure DoT stream for {}: {}", addr, err);
                                drop(stream);
                                continue;
                            }
                            runtime.tcp_connection_count.fetch_add(1, Ordering::Relaxed);
                            if let Err(err) = enqueue_stream(&tx, stream, addr) {
                                runtime.tcp_connection_count.fetch_sub(1, Ordering::Relaxed);
                                runtime.varz.client_connections_rejected.inc();
                                debug!("DoT queue rejected {}: {}", addr, err);
                            }
                        }
                        Err(err) => error!("DoT accept error on {}: {}", listen_addr, err),
                    }
                }
            })
    }

    fn spawn_doh_listener(
        self: &Arc<Self>,
        listen_addr: String,
    ) -> io::Result<thread::JoinHandle<()>> {
        let listener = TcpListener::bind(&listen_addr)?;
        let tls_config = Arc::new(load_tls_server_config(
            &self.config,
            TlsApplicationProtocol::Http11,
        )?);
        info!("DoH listener is ready on https://{}/dns-query", listen_addr);
        let max_tcp = self.config.max_tcp_clients;
        let worker_count = stream_worker_count(self.config.tcp_acceptor_threads);
        let queue_capacity = stream_queue_capacity(worker_count, max_tcp);
        let (tx, rx) = bounded::<(TcpStream, SocketAddr)>(queue_capacity);

        for worker_id in 0..worker_count {
            let runtime = self.clone();
            let rx = rx.clone();
            let tls_config = tls_config.clone();
            thread::Builder::new()
                .name(format!("balancedns_doh_worker_{}", worker_id))
                .spawn(move || {
                    while let Ok((stream, addr)) = rx.recv() {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let connection =
                                ServerConnection::new(tls_config.clone()).map_err(io::Error::other);
                            match connection {
                                Ok(connection) => {
                                    let mut tls_stream = StreamOwned::new(connection, stream);
                                    if let Err(err) = runtime.handle_doh_session(&mut tls_stream) {
                                        debug!("DoH session closed for {}: {}", addr, err);
                                    }
                                }
                                Err(err) => debug!("DoH TLS error for {}: {}", addr, err),
                            }
                        }));
                        if let Err(panic_err) = result {
                            error!("DoH session worker panicked for {}: {:?}", addr, panic_err);
                        }
                        runtime.tcp_connection_count.fetch_sub(1, Ordering::Relaxed);
                    }
                })
                .map_err(|err| io::Error::other(format!("Unable to spawn DoH worker: {}", err)))?;
        }
        thread::Builder::new()
            .name("balancedns_doh".to_string())
            .spawn({
                let runtime = self.clone();
                move || loop {
                    match listener.accept() {
                        Ok((stream, addr)) => {
                            let current = runtime.tcp_connection_count.load(Ordering::Relaxed);
                            if current >= max_tcp {
                                warn!(
                                    "DoH connection limit reached ({}/{}), rejecting {}",
                                    current, max_tcp, addr
                                );
                                runtime.varz.client_connections_rejected.inc();
                                drop(stream);
                                continue;
                            }
                            if let Err(err) = configure_accepted_stream(&stream) {
                                runtime.varz.client_connections_rejected.inc();
                                debug!("Failed to configure DoH stream for {}: {}", addr, err);
                                drop(stream);
                                continue;
                            }
                            runtime.tcp_connection_count.fetch_add(1, Ordering::Relaxed);
                            if let Err(err) = enqueue_stream(&tx, stream, addr) {
                                runtime.tcp_connection_count.fetch_sub(1, Ordering::Relaxed);
                                runtime.varz.client_connections_rejected.inc();
                                debug!("DoH queue rejected {}: {}", addr, err);
                            }
                        }
                        Err(err) => error!("DoH accept error on {}: {}", listen_addr, err),
                    }
                }
            })
    }

    fn handle_doh_session<S: Read + Write>(self: &Arc<Self>, stream: &mut S) -> io::Result<()> {
        let request = read_http_request(stream)?;
        let path = http_target_path(&request.target)?;

        if path == "/dns-query" {
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
            self.varz.client_queries_doh.inc();
            match self.process_query(&body) {
                Ok(response) => {
                    write_http_response(stream, "200 OK", "application/dns-message", &response)
                }
                Err(err) => write_http_response(
                    stream,
                    "500 Internal Server Error",
                    "text/plain; charset=utf-8",
                    err.to_string().as_bytes(),
                ),
            }
        } else if path == "/odoh/configs" && request.method == "GET" {
            // oDoH is not implemented yet - return empty config
            write_http_response(
                stream,
                "501 Not Implemented",
                "text/plain; charset=utf-8",
                b"oDoH is not implemented yet",
            )
        } else if path == "/odoh" && request.method == "POST" {
            // oDoH is not implemented yet
            write_http_response(
                stream,
                "501 Not Implemented",
                "text/plain; charset=utf-8",
                b"oDoH is not implemented yet",
            )
        } else {
            write_http_response(
                stream,
                "404 Not Found",
                "text/plain; charset=utf-8",
                b"not found",
            )?;
            Ok(())
        }
    }

    fn spawn_metrics_listener(
        self: &Arc<Self>,
        listen_addr: String,
    ) -> io::Result<thread::JoinHandle<()>> {
        let listener = TcpListener::bind(&listen_addr)?;
        info!(
            "Metrics listener is ready on http://{}/metrics",
            listen_addr
        );
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
        let mut query_count = 0;
        let session_start = Instant::now();
        let idle_timeout = StdDuration::from_millis(TCP_SESSION_IDLE_TIMEOUT_MS);

        loop {
            // Check session limits
            if query_count >= TCP_SESSION_MAX_QUERIES {
                info!("TCP session ended due to max queries limit");
                return Ok(());
            }
            if session_start.elapsed() > idle_timeout {
                // Update timeout to idle timeout after initial prefetch
                stream.set_read_timeout(Some(idle_timeout))?;
            }

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

            query_count += 1;
            self.varz.client_queries.inc();
            self.varz.client_queries_tcp.inc();
            let response = self.process_query(&packet)?;
            write_tcp_response_frame(&mut stream, &response)?;
        }
    }

    fn handle_tls_session<S: SessionStream>(self: &Arc<Self>, mut stream: S) -> io::Result<()> {
        let mut query_count = 0;
        let session_start = Instant::now();
        let idle_timeout = StdDuration::from_millis(TCP_SESSION_IDLE_TIMEOUT_MS);
        stream.set_read_timeout(Some(idle_timeout))?;

        loop {
            // Check session limits
            if query_count >= TCP_SESSION_MAX_QUERIES {
                info!("DoT session ended due to max queries limit");
                return Ok(());
            }
            if session_start.elapsed() > idle_timeout {
                stream.set_read_timeout(Some(idle_timeout))?;
            }

            let packet = match read_tcp_query_frame(&mut stream) {
                Ok(packet) => packet,
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(err) => return Err(err),
            };
            query_count += 1;
            self.varz.client_queries.inc();
            self.varz.client_queries_dot.inc();
            let response = self.process_query(&packet)?;
            write_tcp_response_frame(&mut stream, &response)?;
        }
    }

    fn process_query(self: &Arc<Self>, packet: &[u8]) -> io::Result<Vec<u8>> {
        let _inflight_query = InflightQueryGuard::new(&self.varz);
        let packet = if self.plugins.is_empty() {
            Cow::Borrowed(packet)
        } else {
            match self.plugins.apply_pre_query(packet) {
                None => Cow::Borrowed(packet),
                Some(PacketAction::Continue(updated)) => Cow::Owned(updated),
                Some(PacketAction::Respond(response)) => {
                    return Ok(self.apply_post_response_plugins(response))
                }
            }
        };
        let normalized_question = dns::normalize(packet.as_ref(), true)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let fqdn = dns::qname_to_fqdn(&normalized_question.qname)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let fqdn = fqdn.to_ascii_lowercase();

        if self.config.deny_any && normalized_question.qtype == dns::DNS_TYPE_ANY {
            return Ok(dns::build_refused_packet(&normalized_question)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?);
        }
        if self.config.deny_dnskey && normalized_question.qtype == dns::DNS_TYPE_DNSKEY {
            return Ok(dns::build_refused_packet(&normalized_question)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?);
        }
        if let Some((ip_addr, ttl)) = self.lookup_host(&fqdn) {
            let response = dns::build_address_packet(&normalized_question, ip_addr, ttl)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            return Ok(self.apply_post_response_plugins(response));
        }
        if self.is_blocked(&fqdn) {
            return Ok(dns::build_nxdomain_packet(&normalized_question)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?);
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
                        return Ok(self.apply_post_response_plugins(cached_packet));
                    }
                } else {
                    self.varz.client_queries_cached.inc();
                    let mut cached_packet = cache_entry.packet.clone();
                    dns::set_tid(&mut cached_packet, normalized_question.tid);
                    return Ok(self.apply_post_response_plugins(cached_packet));
                }
            }
        }

        let response = self.resolve_via_upstreams(&normalized_question, &fqdn)?;
        let response = self.apply_post_response_plugins(response);
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
        Ok(response)
    }

    fn schedule_stale_refresh(
        self: &Arc<Self>,
        normalized_question: dns::NormalizedQuestion,
        cache_key: dns::NormalizedQuestionKey,
        fqdn: String,
    ) {
        // Atomically check and set inflight status with active count check
        let should_spawn = {
            let mut inflight = self.stale_refresh_inflight.lock();
            if inflight.contains(&cache_key) {
                false
            } else {
                // Check active count before allowing spawn
                let active = self.stale_refresh_active.load(Ordering::Relaxed);
                if active >= MAX_STALE_REFRESH_THREADS {
                    debug!(
                        "Stale refresh thread limit reached ({}/{}), skipping refresh",
                        active, MAX_STALE_REFRESH_THREADS
                    );
                    false
                } else {
                    // Mark as inflight and increment active count atomically
                    inflight.insert(cache_key.clone());
                    self.stale_refresh_active.fetch_add(1, Ordering::Relaxed);
                    true
                }
            }
        };

        if !should_spawn {
            return;
        }

        let runtime = self.clone();
        let cache_key_clone = cache_key.clone();
        match thread::Builder::new()
            .name("stale_refresh".to_string())
            .spawn(move || {
                let _guard = StaleRefreshGuard {
                    runtime: &runtime,
                    cache_key: cache_key.clone(),
                };
                let refresh_result = runtime
                    .resolve_via_upstreams(&normalized_question, &fqdn)
                    .and_then(|response| {
                        let processed = runtime.apply_post_response_plugins(response);
                        Ok(processed)
                    });

                if let Ok(response) = refresh_result {
                    let ttl = dns::min_ttl(
                        &response,
                        runtime.config.min_ttl,
                        runtime.config.max_ttl,
                        runtime.config.cache_ttl_seconds,
                    )
                    .unwrap_or(runtime.config.cache_ttl_seconds);
                    let _ = runtime.cache.insert(cache_key.clone(), response, ttl);
                }
            }) {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to spawn stale refresh thread: {}", e);
                // Rollback on failure
                self.stale_refresh_inflight.lock().remove(&cache_key_clone);
                self.stale_refresh_active.fetch_sub(1, Ordering::Relaxed);
            }
        }
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
        let upstream_indices = self.ordered_upstream_indices(fqdn);
        let upstream_question_fqdn = dns::qname_to_fqdn(&upstream_question.qname)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let total_timeout = StdDuration::from_millis(self.config.request_timeout_ms);
        let started_at = std::time::Instant::now();
        let mut last_err = None;
        for upstream_idx in upstream_indices {
            let upstream = &self.config.upstreams[upstream_idx];
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
                upstream,
                &query_packet,
                &upstream_question,
                &upstream_question_fqdn,
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
        upstream_question_fqdn: &str,
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
        let normalized_response_fqdn = dns::qname_to_fqdn(&normalized_response.qname)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        if normalized_response.tid != upstream_question.tid
            || normalized_response.qtype != upstream_question.qtype
            || normalized_response.qclass != upstream_question.qclass
            || normalized_response_fqdn != upstream_question_fqdn
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Upstream [{}] returned a mismatched response",
                    upstream.name
                ),
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
        let pool_idx = self.udp_socket_rr_counter.fetch_add(1, Ordering::Relaxed)
            % self.upstream_udp_sockets.len();
        let socket = self.upstream_udp_sockets[pool_idx].lock();

        // Serialize request/response per pooled socket to avoid reply mixups under concurrent load.
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;
        socket.send_to(query_packet, remote_addr)?;

        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; 65535];
        loop {
            let remaining_timeout = deadline.saturating_duration_since(Instant::now());
            socket.set_read_timeout(Some(remaining_timeout))?;
            match socket.recv_from(&mut buf) {
                Ok((len, addr)) if addr == remote_addr => return Ok(buf[..len].to_vec()),
                Ok((_len, addr)) => {
                    debug!(
                        "Ignoring UDP response from unexpected sender {} (expected {})",
                        addr, remote_addr
                    );
                    if remaining_timeout.is_zero() {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "Timed out while waiting for UDP upstream response",
                        ));
                    }
                }
                Err(err) => return Err(err),
            }
        }
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

    #[inline]
    fn ordered_upstream_indices(&self, fqdn: &str) -> Vec<usize> {
        route_upstream_indices_for_fqdn_compiled(
            fqdn,
            &self.routing_rules,
            &self.upstream_selection,
            &self.config.balancing_algorithm,
            &self.rr_counter,
        )
    }

    #[inline]
    fn lookup_host(&self, fqdn: &str) -> Option<(IpAddr, u32)> {
        if let Some(ip_addr) = self.local_hosts.get(fqdn).copied() {
            return Some((ip_addr, self.config.cache_ttl_seconds));
        }
        self.remote_hosts.read().get(fqdn).copied().map(|ip| {
            let ttl = self
                .config
                .hosts_remote
                .as_ref()
                .map_or(self.config.cache_ttl_seconds, |cfg| cfg.ttl_seconds);
            (ip, ttl)
        })
    }

    #[inline]
    fn is_blocked(&self, fqdn: &str) -> bool {
        self.remote_blocklist.read().contains(fqdn)
    }

    fn refresh_remote_hosts_loop(&self) {
        let config = match self.config.hosts_remote.clone() {
            Some(config) => config,
            None => return,
        };
        loop {
            self.refresh_remote_hosts_once();
            thread::sleep(StdDuration::from_secs(config.refresh_seconds));
        }
    }

    fn refresh_remote_blocklist_loop(&self) {
        let config = match self.config.blocklist_remote.clone() {
            Some(config) => config,
            None => return,
        };
        loop {
            self.refresh_remote_blocklist_once();
            thread::sleep(StdDuration::from_secs(config.refresh_seconds));
        }
    }

    fn refresh_remote_hosts_once(&self) {
        let Some(config) = self.config.hosts_remote.as_ref() else {
            return;
        };
        match fetch_text(&self.http_client, &config.url) {
            Ok(body) => {
                let hosts = parse_hosts_mapping(&body);
                *self.remote_hosts.write() = hosts;
                info!(
                    "Loaded {} remote host overrides",
                    self.remote_hosts.read().len()
                );
            }
            Err(err) => error!("Unable to refresh remote hosts [{}]: {}", config.url, err),
        }
    }

    fn refresh_remote_blocklist_once(&self) {
        let Some(config) = self.config.blocklist_remote.as_ref() else {
            return;
        };
        match fetch_text(&self.http_client, &config.url) {
            Ok(body) => {
                let entries = parse_blocklist(&body);
                *self.remote_blocklist.write() = entries;
                info!(
                    "Loaded {} remote blocked domains",
                    self.remote_blocklist.read().len()
                );
            }
            Err(err) => error!("Unable to refresh blocklist [{}]: {}", config.url, err),
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

    #[inline]
    fn apply_post_response_plugins(&self, response: Vec<u8>) -> Vec<u8> {
        if self.plugins.is_empty() {
            response
        } else {
            self.plugins.apply_post_response(&response)
        }
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
            // Skip localhost and null addresses (used for blocking in hosts files)
            if ip_addr.is_loopback() || ip_addr.is_unspecified() {
                continue;
            }
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
        // Skip AdBlock-style rules (contain ##, ||, $, or start with special characters)
        if line.contains("##") || line.contains("||") || line.contains('$') || line.starts_with('/')
        {
            continue;
        }
        // Skip lines with commas (likely multi-domain rules or complex filters)
        if line.contains(',') {
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
        // Only add simple domain names (no wildcards or special characters)
        let domain = tokens[0];
        if domain.starts_with('*') || domain.contains('*') {
            continue;
        }
        blocked.insert(normalize_domain(domain));
    }
    blocked
}

#[inline]
fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    }
}

#[inline]
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

fn configure_udp_listener_socket(socket: &UdpSocket) -> io::Result<()> {
    socket.set_nonblocking(false)?;
    Ok(())
}

fn configure_accepted_stream(stream: &TcpStream) -> io::Result<()> {
    let idle_timeout = Some(StdDuration::from_millis(TCP_SESSION_IDLE_TIMEOUT_MS));
    stream.set_nodelay(true)?;
    stream.set_read_timeout(idle_timeout)?;
    stream.set_write_timeout(idle_timeout)?;
    Ok(())
}

fn stream_worker_count(configured_threads: usize) -> usize {
    if configured_threads > 0 {
        configured_threads
    } else {
        thread::available_parallelism()
            .map(|parallelism| parallelism.get().max(2))
            .unwrap_or(4)
    }
}

fn stream_queue_capacity(worker_count: usize, max_tcp_clients: usize) -> usize {
    let per_worker = worker_count.saturating_mul(STREAM_WORK_QUEUE_MULTIPLIER);
    per_worker
        .clamp(STREAM_WORK_QUEUE_MIN, STREAM_WORK_QUEUE_MAX)
        .min(max_tcp_clients.max(1))
}

fn enqueue_stream(
    sender: &Sender<(TcpStream, SocketAddr)>,
    stream: TcpStream,
    addr: SocketAddr,
) -> io::Result<()> {
    match sender.try_send((stream, addr)) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full((_stream, _addr))) => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "session queue is full",
        )),
        Err(TrySendError::Disconnected((_stream, _addr))) => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "session queue is disconnected",
        )),
    }
}

fn bind_upstream_udp_socket() -> io::Result<UdpSocket> {
    UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
}

enum TlsApplicationProtocol {
    Dns,
    Http11,
    Http2,
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
    let mut raw = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];
    loop {
        let count = stream.read(&mut buf)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unexpected EOF while reading HTTP headers",
            ));
        }
        raw.extend_from_slice(&buf[..count]);
        if raw.len() > 65_536 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP headers are too large",
            ));
        }
        if raw.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    // Split header from any body bytes that were read along with the last chunk
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP request headers malformed: no header terminator found",
            )
        })?
        + 4;
    let extra_body_bytes = raw.split_off(header_end);
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
    if content_length > DOH_MAX_BODY_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Content-Length {} exceeds maximum allowed size {}",
                content_length, DOH_MAX_BODY_SIZE
            ),
        ));
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        let already_read = extra_body_bytes.len().min(content_length);
        body[..already_read].copy_from_slice(&extra_body_bytes[..already_read]);
        if already_read < content_length {
            stream.read_exact(&mut body[already_read..])?;
        }
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
        .find_map(|(key, value)| {
            if key == "dns" {
                Some(value.into_owned())
            } else {
                None
            }
        })
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

#[inline]
fn is_timeout_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

#[inline]
fn select_upstream_indices(
    upstreams: &[UpstreamConfig],
    balancing_algorithm: &str,
    rr_counter: &AtomicUsize,
) -> Vec<usize> {
    UpstreamSelectionState::new(upstreams).ordered_indices(balancing_algorithm, rr_counter)
}

fn compile_routing_rules(
    routing_rules: &[RoutingRuleConfig],
    upstreams: &[UpstreamConfig],
) -> Vec<RuntimeRoutingRule> {
    if routing_rules.is_empty() || upstreams.is_empty() {
        return Vec::new();
    }

    let upstream_indices = upstreams
        .iter()
        .enumerate()
        .map(|(index, upstream)| (upstream.name.as_str(), index))
        .collect::<HashMap<_, _>>();

    routing_rules
        .iter()
        .map(|rule| {
            let mut prioritized_indices = Vec::new();
            let mut seen = vec![false; upstreams.len()];
            for upstream_name in &rule.upstreams {
                if let Some(&index) = upstream_indices.get(upstream_name.as_str()) {
                    if !seen[index] {
                        seen[index] = true;
                        prioritized_indices.push(index);
                    }
                }
            }
            RuntimeRoutingRule {
                suffix: normalize_domain(&rule.suffix),
                prioritized_indices,
            }
        })
        .collect()
}

fn prioritize_upstream_indices(
    ordered_indices: Vec<usize>,
    prioritized_indices: &[usize],
) -> Vec<usize> {
    let mut prioritized = Vec::with_capacity(ordered_indices.len());
    let mut seen = vec![false; ordered_indices.len()];
    for &index in prioritized_indices {
        if index < seen.len() && !seen[index] {
            seen[index] = true;
            prioritized.push(index);
        }
    }
    for index in ordered_indices {
        if !seen[index] {
            seen[index] = true;
            prioritized.push(index);
        }
    }
    prioritized
}

fn route_upstream_indices_for_fqdn_compiled(
    fqdn: &str,
    routing_rules: &[RuntimeRoutingRule],
    upstream_selection: &UpstreamSelectionState,
    balancing_algorithm: &str,
    rr_counter: &AtomicUsize,
) -> Vec<usize> {
    let ordered_indices = upstream_selection.ordered_indices(balancing_algorithm, rr_counter);
    if ordered_indices.is_empty() {
        return ordered_indices;
    }

    let Some(rule) = routing_rules
        .iter()
        .find(|rule| fqdn_matches_suffix(fqdn, &rule.suffix))
    else {
        return ordered_indices;
    };

    prioritize_upstream_indices(ordered_indices, &rule.prioritized_indices)
}

fn route_upstream_indices_for_fqdn(
    fqdn: &str,
    routing_rules: &[RoutingRuleConfig],
    upstreams: &[UpstreamConfig],
    balancing_algorithm: &str,
    rr_counter: &AtomicUsize,
) -> Vec<usize> {
    let compiled_rules = compile_routing_rules(routing_rules, upstreams);
    let upstream_selection = UpstreamSelectionState::new(upstreams);
    route_upstream_indices_for_fqdn_compiled(
        fqdn,
        &compiled_rules,
        &upstream_selection,
        balancing_algorithm,
        rr_counter,
    )
}

#[inline]
fn fqdn_matches_suffix(fqdn: &str, suffix: &str) -> bool {
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
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

#[inline]
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

#[inline]
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
    use super::{route_upstream_indices_for_fqdn, select_upstream_indices, try_take_tcp_frame};
    use crate::config::{RoutingRuleConfig, UpstreamConfig, UpstreamProtocol};
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
        let ordered = select_upstream_indices(&upstreams, "round_robin", &rr_counter);
        let names = ordered
            .into_iter()
            .map(|upstream_index| upstreams[upstream_index].name.clone())
            .collect::<Vec<String>>();

        assert_eq!(names[0], "udp-a");
        assert_eq!(names.len(), 3);
        assert_eq!(
            names.iter().filter(|name| name.as_str() == "udp-a").count(),
            1
        );
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
        let ru = route_upstream_indices_for_fqdn(
            "example.ru.",
            &routing_rules,
            &upstreams,
            "round_robin",
            &rr_counter,
        );
        let ru_names = ru
            .into_iter()
            .map(|upstream_index| upstreams[upstream_index].name.clone())
            .collect::<Vec<_>>();
        assert_eq!(ru_names[0], "yandex-udp");

        let rr_counter = AtomicUsize::new(0);
        let non_ru = route_upstream_indices_for_fqdn(
            "example.com.",
            &routing_rules,
            &upstreams,
            "round_robin",
            &rr_counter,
        );
        let non_ru_names = non_ru
            .into_iter()
            .map(|upstream_index| upstreams[upstream_index].name.clone())
            .collect::<Vec<_>>();
        assert_eq!(non_ru_names[0], "cloudflare-udp");
        assert_eq!(non_ru_names[1], "google-udp");
    }
}
