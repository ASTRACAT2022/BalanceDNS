#![allow(dead_code)]

use clap::{Arg, Command};
use libbalancedns::Config;
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_CONFIG_PATH: &str = "./balancedns.toml";
const DEFAULT_METRICS_ENDPOINT: &str = "http://127.0.0.1:9100/metrics";
const GRAPH_WIDTH: usize = 48;
const HISTORY_LEN: usize = 48;

fn main() {
    let cli = Command::new("astracatdnscli")
        .version("0.1.0")
        .about("BalanceDNS admin CLI")
        .subcommand(
            Command::new("status")
                .about("One-shot status snapshot")
                .arg(
                    Arg::new("config")
                        .short('c')
                        .long("config")
                        .value_name("FILE")
                        .default_value(DEFAULT_CONFIG_PATH),
                )
                .arg(
                    Arg::new("metrics")
                        .short('m')
                        .long("metrics")
                        .value_name("URL"),
                ),
        )
        .subcommand(
            Command::new("watch")
                .about("Live dashboard with graphs")
                .arg(
                    Arg::new("config")
                        .short('c')
                        .long("config")
                        .value_name("FILE")
                        .default_value(DEFAULT_CONFIG_PATH),
                )
                .arg(
                    Arg::new("metrics")
                        .short('m')
                        .long("metrics")
                        .value_name("URL"),
                )
                .arg(
                    Arg::new("interval")
                        .short('i')
                        .long("interval")
                        .value_name("SECONDS")
                        .default_value("2"),
                ),
        );

    let matches = cli.get_matches();
    match matches.subcommand() {
        Some(("status", sub)) => {
            let config_path = sub
                .get_one::<String>("config")
                .map(|s| s.as_str())
                .unwrap_or(DEFAULT_CONFIG_PATH);
            let config = read_config(config_path).ok();
            let endpoint =
                resolve_metrics_endpoint(sub.get_one::<String>("metrics"), config.as_ref());
            match fetch_metrics(&endpoint, Duration::from_secs(2)) {
                Ok(metrics) => {
                    print_status_snapshot(config.as_ref(), config_path, &endpoint, &metrics);
                }
                Err(err) => {
                    eprintln!("metrics fetch failed: {}", err);
                    std::process::exit(1);
                }
            }
        }
        Some(("watch", sub)) => {
            let config_path = sub
                .get_one::<String>("config")
                .map(|s| s.as_str())
                .unwrap_or(DEFAULT_CONFIG_PATH);
            let config = read_config(config_path).ok();
            let endpoint =
                resolve_metrics_endpoint(sub.get_one::<String>("metrics"), config.as_ref());
            let interval_secs = sub
                .get_one::<String>("interval")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(2)
                .max(1);
            watch_dashboard(
                config.as_ref(),
                config_path,
                &endpoint,
                Duration::from_secs(interval_secs),
            );
        }
        _ => {
            println!("Use one of subcommands: status, watch");
            std::process::exit(2);
        }
    }
}

fn read_config(path: &str) -> io::Result<Config> {
    Config::from_path(path).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn resolve_metrics_endpoint(cli_endpoint: Option<&String>, config: Option<&Config>) -> String {
    if let Some(value) = cli_endpoint {
        return value.clone();
    }
    if let Some(cfg) = config {
        if cfg.webservice_enabled {
            return format!("http://{}/metrics", cfg.webservice_listen_addr);
        }
    }
    DEFAULT_METRICS_ENDPOINT.to_owned()
}

fn fetch_metrics(endpoint: &str, timeout: Duration) -> io::Result<HashMap<String, f64>> {
    let (host_port, path, host_header) = parse_http_endpoint(endpoint)?;
    let mut stream = TcpStream::connect(&host_port)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: astracatdnscli/0.1\r\nConnection: close\r\n\r\n",
        path, host_header
    );
    stream.write_all(request.as_bytes())?;

    let mut raw = Vec::with_capacity(64 * 1024);
    stream.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let split_at = text.find("\r\n\r\n").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid HTTP response (no headers/body split)",
        )
    })?;
    let headers = &text[..split_at];
    if !headers.starts_with("HTTP/1.1 200") && !headers.starts_with("HTTP/1.0 200") {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Metrics endpoint returned non-200 status: {}",
                headers.lines().next().unwrap_or("unknown")
            ),
        ));
    }
    let body = &text[split_at + 4..];
    Ok(parse_prometheus_text(body))
}

fn parse_http_endpoint(endpoint: &str) -> io::Result<(String, String, String)> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Empty endpoint",
        ));
    }
    if trimmed.starts_with("https://") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTPS metrics endpoint is not supported by this CLI (use http://.../metrics)",
        ));
    }
    let without_scheme = trimmed.strip_prefix("http://").unwrap_or(trimmed);
    let (host_port, path) = match without_scheme.find('/') {
        Some(idx) => (&without_scheme[..idx], &without_scheme[idx..]),
        None => (without_scheme, "/metrics"),
    };
    if host_port.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Missing host:port",
        ));
    }
    let host_header = host_port.to_owned();
    Ok((host_port.to_owned(), path.to_owned(), host_header))
}

fn parse_prometheus_text(body: &str) -> HashMap<String, f64> {
    let mut values = HashMap::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let metric_with_labels = match parts.next() {
            Some(v) => v,
            None => continue,
        };
        let value = match parts.next().and_then(|v| v.parse::<f64>().ok()) {
            Some(v) => v,
            None => continue,
        };
        let metric_name = metric_with_labels
            .split('{')
            .next()
            .unwrap_or(metric_with_labels);
        values.insert(metric_name.to_owned(), value);
    }
    values
}

fn metric(metrics: &HashMap<String, f64>, name: &str) -> f64 {
    metrics.get(name).copied().unwrap_or(0.0)
}

fn print_status_snapshot(
    config: Option<&Config>,
    config_path: &str,
    endpoint: &str,
    metrics: &HashMap<String, f64>,
) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("astracatdnscli status");
    println!("timestamp_unix: {}", now);
    println!("metrics_endpoint: {}", endpoint);
    if let Some(cfg) = config {
        print_config_summary(cfg, config_path);
    } else {
        println!("config: not loaded ({})", config_path);
    }

    let total = metric(metrics, "balancedns_client_queries");
    let udp = metric(metrics, "balancedns_client_queries_udp");
    let tcp = metric(metrics, "balancedns_client_queries_tcp");
    let dot = metric(metrics, "balancedns_client_queries_dot");
    let doh = metric(metrics, "balancedns_client_queries_doh");
    let cached = metric(metrics, "balancedns_client_queries_cached");
    let errors = metric(metrics, "balancedns_client_queries_errors");
    let cache_hit = if total > 0.0 {
        (cached / total) * 100.0
    } else {
        0.0
    };
    let upstream_sent = metric(metrics, "balancedns_upstream_sent");
    let upstream_received = metric(metrics, "balancedns_upstream_received");
    let upstream_timeout = metric(metrics, "balancedns_upstream_timeout");
    let upstream_ok = if upstream_sent > 0.0 {
        (upstream_received / upstream_sent) * 100.0
    } else {
        0.0
    };

    println!("--- metrics ---");
    println!("queries_total: {:.0}", total);
    println!(
        "queries_by_proto: udp={:.0} tcp={:.0} dot={:.0} doh={:.0}",
        udp, tcp, dot, doh
    );
    println!("cache_hit_ratio: {:.2}%", cache_hit);
    println!("client_errors: {:.0}", errors);
    println!(
        "upstream: sent={:.0} recv={:.0} timeout={:.0} success={:.2}%",
        upstream_sent, upstream_received, upstream_timeout, upstream_ok
    );
    println!(
        "cache_sets: frequent={:.0} recent={:.0} test={:.0}",
        metric(metrics, "balancedns_cache_frequent_len"),
        metric(metrics, "balancedns_cache_recent_len"),
        metric(metrics, "balancedns_cache_test_len")
    );
    println!(
        "inflight_queries: {:.0}",
        metric(metrics, "balancedns_inflight_queries")
    );
}

fn print_config_summary(config: &Config, config_path: &str) {
    println!("--- config ---");
    println!("config_path: {}", config_path);
    println!(
        "listeners: udp={:?} tcp={:?} dot={:?} doh={:?}",
        config.udp_listen_addr,
        config.tcp_listen_addr,
        config.dot_listen_addr,
        config.doh_listen_addr
    );
    println!(
        "cache: enabled={} size={} ttl={}s stale_refresh={}",
        config.cache_enabled,
        config.cache_size,
        config.cache_ttl_seconds,
        config.stale_refresh_enabled
    );
    println!(
        "threads: udp={} tcp={} max_tcp_clients={}",
        config.udp_acceptor_threads, config.tcp_acceptor_threads, config.max_tcp_clients
    );
    println!(
        "upstreams: total={} udp={} doh={}",
        config.upstreams.len(),
        config
            .upstreams
            .iter()
            .filter(|u| matches!(&u.proto, libbalancedns::UpstreamProtocol::Udp))
            .count(),
        config
            .upstreams
            .iter()
            .filter(|u| matches!(&u.proto, libbalancedns::UpstreamProtocol::Doh))
            .count()
    );
}

struct DerivedRates {
    total_qps: f64,
    udp_qps: f64,
    tcp_qps: f64,
    dot_qps: f64,
    doh_qps: f64,
    cache_hit_pct: f64,
    upstream_success_pct: f64,
}

fn watch_dashboard(config: Option<&Config>, config_path: &str, endpoint: &str, interval: Duration) {
    let mut previous: Option<(Instant, HashMap<String, f64>)> = None;
    let mut qps_history = VecDeque::with_capacity(HISTORY_LEN);
    let mut doh_history = VecDeque::with_capacity(HISTORY_LEN);
    let mut dot_history = VecDeque::with_capacity(HISTORY_LEN);
    let mut cache_hit_history = VecDeque::with_capacity(HISTORY_LEN);

    loop {
        match fetch_metrics(endpoint, Duration::from_secs(2)) {
            Ok(metrics) => {
                let now = Instant::now();
                let rates = derive_rates(previous.as_ref(), now, &metrics);
                previous = Some((now, metrics.clone()));

                push_history(&mut qps_history, rates.total_qps);
                push_history(&mut doh_history, rates.doh_qps);
                push_history(&mut dot_history, rates.dot_qps);
                push_history(&mut cache_hit_history, rates.cache_hit_pct);

                print!("\x1B[2J\x1B[H");
                println!(
                    "astracatdnscli watch  endpoint={}  interval={}s",
                    endpoint,
                    interval.as_secs()
                );
                if let Some(cfg) = config {
                    print_config_summary(cfg, config_path);
                } else {
                    println!("config: not loaded ({})", config_path);
                }
                println!("--- live rates ---");
                println!(
                    "qps: total={:.1} udp={:.1} tcp={:.1} dot={:.1} doh={:.1}",
                    rates.total_qps, rates.udp_qps, rates.tcp_qps, rates.dot_qps, rates.doh_qps
                );
                println!(
                    "cache_hit={:.2}% upstream_success={:.2}%",
                    rates.cache_hit_pct, rates.upstream_success_pct
                );
                println!(
                    "graph_total_qps  [{}]",
                    render_ascii_graph(&qps_history, GRAPH_WIDTH)
                );
                println!(
                    "graph_doh_qps    [{}]",
                    render_ascii_graph(&doh_history, GRAPH_WIDTH)
                );
                println!(
                    "graph_dot_qps    [{}]",
                    render_ascii_graph(&dot_history, GRAPH_WIDTH)
                );
                println!(
                    "graph_cache_hit  [{}]",
                    render_ascii_graph(&cache_hit_history, GRAPH_WIDTH)
                );
                println!("Ctrl+C to exit");
            }
            Err(err) => {
                print!("\x1B[2J\x1B[H");
                println!("astracatdnscli watch");
                println!("metrics fetch failed: {}", err);
                println!("retrying in {}s...", interval.as_secs());
            }
        }
        let _ = io::stdout().flush();
        thread::sleep(interval);
    }
}

fn derive_rates(
    previous: Option<&(Instant, HashMap<String, f64>)>,
    now: Instant,
    current: &HashMap<String, f64>,
) -> DerivedRates {
    let total = metric(current, "balancedns_client_queries");
    let udp = metric(current, "balancedns_client_queries_udp");
    let tcp = metric(current, "balancedns_client_queries_tcp");
    let dot = metric(current, "balancedns_client_queries_dot");
    let doh = metric(current, "balancedns_client_queries_doh");
    let cached = metric(current, "balancedns_client_queries_cached");
    let upstream_sent = metric(current, "balancedns_upstream_sent");
    let upstream_received = metric(current, "balancedns_upstream_received");

    let mut rates = DerivedRates {
        total_qps: 0.0,
        udp_qps: 0.0,
        tcp_qps: 0.0,
        dot_qps: 0.0,
        doh_qps: 0.0,
        cache_hit_pct: if total > 0.0 {
            (cached / total) * 100.0
        } else {
            0.0
        },
        upstream_success_pct: if upstream_sent > 0.0 {
            (upstream_received / upstream_sent) * 100.0
        } else {
            0.0
        },
    };

    if let Some((prev_ts, prev)) = previous {
        let dt = now.duration_since(*prev_ts).as_secs_f64().max(0.001);
        rates.total_qps = (total - metric(prev, "balancedns_client_queries")).max(0.0) / dt;
        rates.udp_qps = (udp - metric(prev, "balancedns_client_queries_udp")).max(0.0) / dt;
        rates.tcp_qps = (tcp - metric(prev, "balancedns_client_queries_tcp")).max(0.0) / dt;
        rates.dot_qps = (dot - metric(prev, "balancedns_client_queries_dot")).max(0.0) / dt;
        rates.doh_qps = (doh - metric(prev, "balancedns_client_queries_doh")).max(0.0) / dt;
    }
    rates
}

fn push_history(history: &mut VecDeque<f64>, value: f64) {
    if history.len() >= HISTORY_LEN {
        let _ = history.pop_front();
    }
    history.push_back(value);
}

fn render_ascii_graph(history: &VecDeque<f64>, width: usize) -> String {
    let levels = [' ', '.', ':', '-', '=', '+', '*', '#', '%'];
    if history.is_empty() {
        return " ".repeat(width);
    }
    let max_value = history.iter().copied().fold(0.0_f64, f64::max).max(1.0);

    let mut out = String::with_capacity(width);
    let start = history.len().saturating_sub(width);
    for value in history.iter().skip(start) {
        let ratio = (*value / max_value).clamp(0.0, 1.0);
        let idx = (ratio * ((levels.len() - 1) as f64)).round() as usize;
        out.push(levels[idx]);
    }
    while out.len() < width {
        out.insert(0, ' ');
    }
    out
}
