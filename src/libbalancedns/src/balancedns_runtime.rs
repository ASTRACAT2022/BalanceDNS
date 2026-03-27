use base64;
use cache::Cache;
use config::{Config, UpstreamConfig, UpstreamProtocol};
use dns;
use parking_lot::{Mutex, RwLock};
use plugins::{PacketAction, PluginManager};
use prometheus::{Encoder, TextEncoder};
use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection, StreamOwned};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration as StdDuration;
use url::Url;
use varz::Varz;

pub struct BalanceDnsRuntime {
    config: Config,
    cache: Mutex<Cache>,
    local_hosts: HashMap<String, IpAddr>,
    remote_hosts: RwLock<HashMap<String, IpAddr>>,
    remote_blocklist: RwLock<HashSet<String>>,
    plugins: PluginManager,
    rr_counter: AtomicUsize,
    varz: Arc<Varz>,
}

impl BalanceDnsRuntime {
    pub fn new(config: Config, varz: Arc<Varz>) -> Arc<Self> {
        let local_hosts = config
            .hosts_local
            .iter()
            .filter_map(|(name, ip)| ip.parse().ok().map(|ip| (name.clone(), ip)))
            .collect::<HashMap<String, IpAddr>>();
        Arc::new(BalanceDnsRuntime {
            cache: Mutex::new(Cache::new(config.clone())),
            config: config.clone(),
            local_hosts,
            remote_hosts: RwLock::new(HashMap::new()),
            remote_blocklist: RwLock::new(HashSet::new()),
            plugins: PluginManager::from_paths(&config.plugin_libraries),
            rr_counter: AtomicUsize::new(0),
            varz,
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
                                runtime.varz.client_queries.inc();
                                runtime.varz.client_queries_udp.inc();
                                let response = runtime.process_query(&buf[..len]);
                                match response {
                                    Ok(response) => {
                                        let _ = socket.send_to(&response, addr);
                                    }
                                    Err(err) => {
                                        runtime.varz.client_queries_errors.inc();
                                        debug!("UDP query failed from {}: {}", addr, err);
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
        let tls_config = Arc::new(load_tls_server_config(&self.config)?);
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
                                let connection = ServerConnection::new(tls_config).map_err(io::Error::other);
                                match connection {
                                    Ok(connection) => {
                                        let tls_stream = StreamOwned::new(connection, stream);
                                        if let Err(err) = runtime.handle_tcp_session(tls_stream) {
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
        let tls_config = Arc::new(load_tls_server_config(&self.config)?);
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
                            runtime.update_cache_metrics();
                            let mut metrics = Vec::new();
                            let encoder = TextEncoder::new();
                            let status = match encoder.encode(&prometheus::gather(), &mut metrics) {
                                Ok(_) => ("200 OK", metrics),
                                Err(err) => ("500 Internal Server Error", err.to_string().into_bytes()),
                            };
                            let content_type = encoder.format_type();
                            let _ = write_http_response(&mut stream, status.0, content_type, &status.1);
                        }
                        Err(err) => error!("Metrics accept error on {}: {}", listen_addr, err),
                    }
                }
            })
    }

    fn handle_tcp_session<S: Read + Write>(&self, mut stream: S) -> io::Result<()> {
        loop {
            let mut len_buf = [0u8; 2];
            match stream.read_exact(&mut len_buf) {
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(err) => return Err(err),
            }
            self.varz.client_queries.inc();
            self.varz.client_queries_tcp.inc();
            let packet_len = ((len_buf[0] as usize) << 8) | len_buf[1] as usize;
            if packet_len < 12 || packet_len > 65535 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Suspicious DNS packet size",
                ));
            }
            let mut packet = vec![0u8; packet_len];
            stream.read_exact(&mut packet)?;
            let response = self.process_query(&packet)?;
            let response_len = response.len();
            let response_prefix = [(response_len >> 8) as u8, response_len as u8];
            stream.write_all(&response_prefix)?;
            stream.write_all(&response)?;
            stream.flush()?;
        }
    }

    fn handle_doh_session<S: Read + Write>(&self, stream: &mut S) -> io::Result<()> {
        let request = read_http_request(stream)?;
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

    fn process_query(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
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
            let cache_entry = {
                let mut cache = self.cache.lock();
                cache.get2(&normalized_question)
            };
            if let Some(cache_entry) = cache_entry {
                if cache_entry.is_expired() {
                    self.varz.client_queries_expired.inc();
                } else {
                    self.varz.client_queries_cached.inc();
                    return self.plugins.apply_post_response(&cache_entry.packet);
                }
            }
        }

        let response = self.resolve_via_upstreams(&normalized_question)?;
        let response = self.plugins.apply_post_response(&response)?;
        if self.config.cache_enabled {
            let ttl = dns::min_ttl(
                &response,
                self.config.min_ttl,
                self.config.max_ttl,
                self.config.cache_ttl_seconds,
            )
            .unwrap_or(self.config.cache_ttl_seconds);
            let mut cache = self.cache.lock();
            let _ = cache.insert(normalized_question.key(), response.clone(), ttl);
        }
        self.update_cache_metrics();
        Ok(response)
    }

    fn resolve_via_upstreams(&self, normalized_question: &dns::NormalizedQuestion) -> io::Result<Vec<u8>> {
        let (query_packet, upstream_question) = dns::build_query_packet(normalized_question, false)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let upstreams = self.ordered_upstreams();
        let mut last_err = None;
        for upstream in upstreams {
            self.varz.upstream_sent.inc();
            match self.query_upstream(
                &upstream,
                &query_packet,
                &upstream_question,
                normalized_question.tid,
            ) {
                Ok(response) => {
                    self.varz.upstream_received.inc();
                    return Ok(response);
                }
                Err(err) => {
                    self.varz.upstream_timeout.inc();
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
    ) -> io::Result<Vec<u8>> {
        let mut response = match upstream.proto {
            UpstreamProtocol::Udp => self.query_udp_upstream(upstream, query_packet)?,
            UpstreamProtocol::Doh => self.query_doh_upstream(upstream, query_packet)?,
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
            self.varz.upstream_errors.inc();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Upstream [{}] returned a mismatched response", upstream.name),
            ));
        }
        dns::set_tid(&mut response, client_tid);
        Ok(response)
    }

    fn query_udp_upstream(&self, upstream: &UpstreamConfig, query_packet: &[u8]) -> io::Result<Vec<u8>> {
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
        let timeout = StdDuration::from_millis(self.config.request_timeout_ms);
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;
        socket.send_to(query_packet, remote_addr)?;
        let mut buf = [0u8; 65535];
        let (len, _) = socket.recv_from(&mut buf)?;
        Ok(buf[..len].to_vec())
    }

    fn query_doh_upstream(&self, upstream: &UpstreamConfig, query_packet: &[u8]) -> io::Result<Vec<u8>> {
        let url = upstream
            .url
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing upstream url"))?;
        let response = ureq::post(url)
            .timeout(StdDuration::from_millis(self.config.request_timeout_ms))
            .set("accept", "application/dns-message")
            .set("content-type", "application/dns-message")
            .send_bytes(query_packet)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        let mut reader = response.into_reader();
        let mut body = Vec::new();
        reader.read_to_end(&mut body)?;
        Ok(body)
    }

    fn ordered_upstreams(&self) -> Vec<UpstreamConfig> {
        let mut weighted = Vec::new();
        for upstream in &self.config.upstreams {
            let copies = if upstream.weight == 0 { 1 } else { upstream.weight };
            for _ in 0..copies {
                weighted.push(upstream.clone());
            }
        }
        if weighted.is_empty() {
            return weighted;
        }
        let start = match self.config.balancing_algorithm.as_str() {
            "round_robin" => self.rr_counter.fetch_add(1, Ordering::Relaxed) % weighted.len(),
            _ => 0,
        };
        weighted.rotate_left(start);
        weighted
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
            match fetch_text(&config.url, self.config.request_timeout_ms) {
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
            match fetch_text(&config.url, self.config.request_timeout_ms) {
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
        let cache = self.cache.lock();
        let stats = cache.stats();
        self.varz.cache_frequent_len.set(stats.frequent_len as f64);
        self.varz.cache_recent_len.set(stats.recent_len as f64);
        self.varz.cache_test_len.set(stats.test_len as f64);
        self.varz.cache_inserted.set(stats.inserted as f64);
        self.varz.cache_evicted.set(stats.evicted as f64);
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

fn fetch_text(url: &str, timeout_ms: u64) -> io::Result<String> {
    ureq::get(url)
        .timeout(StdDuration::from_millis(timeout_ms))
        .call()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?
        .into_string()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}

fn load_tls_server_config(config: &Config) -> io::Result<ServerConfig> {
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
    ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(io::Error::other)
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
    if url.path() != "/dns-query" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unsupported DoH path",
        ));
    }
    let dns_param = url
        .query_pairs()
        .find_map(|(key, value)| if key == "dns" { Some(value.into_owned()) } else { None })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing dns parameter"))?;
    base64::decode_config(dns_param.as_bytes(), base64::URL_SAFE_NO_PAD)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid DoH dns parameter"))
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
