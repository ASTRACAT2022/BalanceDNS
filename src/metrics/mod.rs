use std::sync::{Arc, RwLock, atomic::{AtomicI64, Ordering}};
use std::time::{Duration};
use serde::{Deserialize, Serialize};
use prometheus::{
    Registry, Gauge, Counter, GaugeVec, CounterVec,
    opts, Encoder, TextEncoder
};
use std::fs;
use hyper::{Body, Request, Response, Server, service::{make_service_fn, service_fn}};
use std::convert::Infallible;
use std::net::SocketAddr;
use log::{info, error};
use sysinfo::{System, Networks, get_current_pid};
use dashmap::DashMap;

#[derive(Debug, Clone)]
pub struct LatencyStat {
    pub total_latency: Duration,
    pub count: i64,
}

#[derive(Serialize)]
struct DomainCount {
    domain: String,
    count: i64,
}

#[derive(Serialize)]
struct DomainLatency {
    domain: String,
    avg_latency: f64,
}

#[derive(Serialize)]
struct TypeCount {
    #[serde(rename = "type")]
    query_type: String,
    count: i64,
}

#[derive(Serialize)]
struct CodeCount {
    code: String,
    count: i64,
}

#[derive(Serialize)]
pub struct DashboardMetrics {
    qps: f64,
    total_queries: i64,
    blocked_domains: i64,
    cpu_usage: f32,
    memory_usage: f64,
    goroutines: usize, // threads
    cache_hits: i64,
    cache_misses: i64,
    cache_hit_rate: f64,
    top_nx_domains: Vec<DomainCount>,
    top_latency_domains: Vec<DomainLatency>,
    top_queried_domains: Vec<DomainCount>,
    query_types: Vec<TypeCount>,
    response_codes: Vec<CodeCount>,
}

#[derive(Serialize, Deserialize, Default)]
struct HistoricalData {
    total_queries: i64,
}

pub struct Metrics {
    pub total_queries: AtomicI64,
    pub blocked_domains: AtomicI64,
    pub cache_hits: AtomicI64,
    pub cache_misses: AtomicI64,

    // Using DashMap for concurrent map access
    pub top_nx_domains: DashMap<String, i64>,
    pub top_latency_domains: DashMap<String, LatencyStat>,
    pub top_queried_domains: DashMap<String, i64>,
    pub query_types: DashMap<String, i64>,
    pub response_codes: DashMap<String, i64>,

    pub registry: Registry,

    // Prometheus metrics
    prom_qps: Gauge,
    prom_total_queries: Counter,
    #[allow(dead_code)]
    prom_cache_probation: Gauge,
    #[allow(dead_code)]
    prom_cache_protected: Gauge,
    prom_cpu_usage: Gauge,
    prom_memory_usage: Gauge,
    #[allow(dead_code)]
    prom_goroutine_count: Gauge,
    prom_network_sent: Gauge,
    prom_network_recv: Gauge,
    prom_top_nx_domains: GaugeVec,
    prom_top_latency_domains: GaugeVec,
    prom_top_queried_domains: GaugeVec,
    prom_query_types: CounterVec,
    prom_response_codes: CounterVec,
    prom_unbound_errors: Counter,
    #[allow(dead_code)]
    prom_dnssec_validation: CounterVec,
    #[allow(dead_code)]
    prom_cache_revalidations: Counter,
    prom_cache_hits: Counter,
    prom_cache_misses: Counter,
    prom_blocked_domains: Counter,
    #[allow(dead_code)]
    prom_cache_evictions: Counter,
    prom_lmdb_cache_loads: Counter,
    prom_lmdb_errors: Counter,
    #[allow(dead_code)]
    prom_prefetches: Counter,

    // Runtime stats
    qps: Arc<RwLock<f64>>,
    cpu_usage: Arc<RwLock<f32>>,
    memory_usage: Arc<RwLock<f64>>,
    threads: Arc<RwLock<usize>>,
}

impl Metrics {
    pub fn new(storage_path: &str) -> Self {
        let registry = Registry::new();

        // Define metrics
        let prom_qps = Gauge::new("dns_resolver_qps", "Queries per second").unwrap();
        let prom_total_queries = Counter::new("dns_resolver_total_queries", "Total number of DNS queries").unwrap();
        let prom_cache_probation = Gauge::new("dns_resolver_cache_probation_size", "Size of the probation segment of the cache").unwrap();
        let prom_cache_protected = Gauge::new("dns_resolver_cache_protected_size", "Size of the protected segment of the cache").unwrap();
        let prom_cpu_usage = Gauge::new("dns_resolver_cpu_usage_percent", "Current CPU usage percentage").unwrap();
        let prom_memory_usage = Gauge::new("dns_resolver_memory_usage_percent", "Current memory usage percentage").unwrap();
        let prom_goroutine_count = Gauge::new("dns_resolver_goroutine_count", "Current number of threads").unwrap(); // Mapped to threads
        let prom_network_sent = Gauge::new("dns_resolver_network_sent_bytes", "Total network bytes sent").unwrap();
        let prom_network_recv = Gauge::new("dns_resolver_network_recv_bytes", "Total network bytes received").unwrap();

        let prom_top_nx_domains = GaugeVec::new(opts!("dns_resolver_top_nx_domains", "Top domains with NXDOMAIN responses"), &["domain"]).unwrap();
        let prom_top_latency_domains = GaugeVec::new(opts!("dns_resolver_top_latency_domains_ms", "Top domains by average query latency in milliseconds"), &["domain"]).unwrap();
        let prom_top_queried_domains = GaugeVec::new(opts!("dns_resolver_top_queried_domains", "Top queried domains"), &["domain"]).unwrap();

        let prom_query_types = CounterVec::new(opts!("dns_resolver_query_types_total", "Total number of queries by type"), &["type"]).unwrap();
        let prom_response_codes = CounterVec::new(opts!("dns_resolver_response_codes_total", "Total number of responses by code"), &["code"]).unwrap();

        let prom_unbound_errors = Counter::new("dns_resolver_unbound_errors_total", "Total number of errors from the Unbound resolver").unwrap();
        let prom_dnssec_validation = CounterVec::new(opts!("dns_resolver_dnssec_validation_total", "Total number of DNSSEC validation results by type"), &["result"]).unwrap();
        let prom_cache_revalidations = Counter::new("dns_resolver_cache_revalidations_total", "Total number of cache revalidations").unwrap();
        let prom_cache_hits = Counter::new("dns_resolver_cache_hits_total", "Total number of cache hits").unwrap();
        let prom_cache_misses = Counter::new("dns_resolver_cache_misses_total", "Total number of cache misses").unwrap();
        let prom_blocked_domains = Counter::new("dns_resolver_blocked_domains_total", "Total number of blocked domains").unwrap();
        let prom_cache_evictions = Counter::new("dns_resolver_cache_evictions_total", "Total number of cache evictions").unwrap();
        let prom_lmdb_cache_loads = Counter::new("dns_resolver_lmdb_loads_total", "Total number of items loaded from LMDB").unwrap();
        let prom_lmdb_errors = Counter::new("dns_resolver_lmdb_errors_total", "Total number of LMDB errors").unwrap();
        let prom_prefetches = Counter::new("dns_resolver_prefetches_total", "Total number of cache prefetches").unwrap();

        // Register metrics
        registry.register(Box::new(prom_qps.clone())).unwrap();
        registry.register(Box::new(prom_total_queries.clone())).unwrap();
        registry.register(Box::new(prom_cache_probation.clone())).unwrap();
        registry.register(Box::new(prom_cache_protected.clone())).unwrap();
        registry.register(Box::new(prom_cpu_usage.clone())).unwrap();
        registry.register(Box::new(prom_memory_usage.clone())).unwrap();
        registry.register(Box::new(prom_goroutine_count.clone())).unwrap();
        registry.register(Box::new(prom_network_sent.clone())).unwrap();
        registry.register(Box::new(prom_network_recv.clone())).unwrap();
        registry.register(Box::new(prom_top_nx_domains.clone())).unwrap();
        registry.register(Box::new(prom_top_latency_domains.clone())).unwrap();
        registry.register(Box::new(prom_top_queried_domains.clone())).unwrap();
        registry.register(Box::new(prom_query_types.clone())).unwrap();
        registry.register(Box::new(prom_response_codes.clone())).unwrap();
        registry.register(Box::new(prom_unbound_errors.clone())).unwrap();
        registry.register(Box::new(prom_dnssec_validation.clone())).unwrap();
        registry.register(Box::new(prom_cache_revalidations.clone())).unwrap();
        registry.register(Box::new(prom_cache_hits.clone())).unwrap();
        registry.register(Box::new(prom_cache_misses.clone())).unwrap();
        registry.register(Box::new(prom_blocked_domains.clone())).unwrap();
        registry.register(Box::new(prom_cache_evictions.clone())).unwrap();
        registry.register(Box::new(prom_lmdb_cache_loads.clone())).unwrap();
        registry.register(Box::new(prom_lmdb_errors.clone())).unwrap();
        registry.register(Box::new(prom_prefetches.clone())).unwrap();

        let mut metrics = Metrics {
            total_queries: AtomicI64::new(0),
            blocked_domains: AtomicI64::new(0),
            cache_hits: AtomicI64::new(0),
            cache_misses: AtomicI64::new(0),
            top_nx_domains: DashMap::new(),
            top_latency_domains: DashMap::new(),
            top_queried_domains: DashMap::new(),
            query_types: DashMap::new(),
            response_codes: DashMap::new(),
            registry,
            prom_qps,
            prom_total_queries,
            prom_cache_probation,
            prom_cache_protected,
            prom_cpu_usage,
            prom_memory_usage,
            prom_goroutine_count,
            prom_network_sent,
            prom_network_recv,
            prom_top_nx_domains,
            prom_top_latency_domains,
            prom_top_queried_domains,
            prom_query_types,
            prom_response_codes,
            prom_unbound_errors,
            prom_dnssec_validation,
            prom_cache_revalidations,
            prom_cache_hits,
            prom_cache_misses,
            prom_blocked_domains,
            prom_cache_evictions,
            prom_lmdb_cache_loads,
            prom_lmdb_errors,
            prom_prefetches,
            qps: Arc::new(RwLock::new(0.0)),
            cpu_usage: Arc::new(RwLock::new(0.0)),
            memory_usage: Arc::new(RwLock::new(0.0)),
            threads: Arc::new(RwLock::new(0)),
        };

        if let Err(e) = metrics.load_historical_data(storage_path) {
            error!("Could not load historical metrics: {}", e);
        }

        metrics
    }

    fn load_historical_data(&mut self, path: &str) -> anyhow::Result<()> {
        if let Ok(data) = fs::read_to_string(path) {
            let hist: HistoricalData = serde_json::from_str(&data)?;
            self.total_queries.store(hist.total_queries, Ordering::Relaxed);
            self.prom_total_queries.inc_by(hist.total_queries as f64);
        }
        Ok(())
    }

    pub async fn save_historical_data(&self, path: &str) -> anyhow::Result<()> {
        let hist = HistoricalData {
            total_queries: self.total_queries.load(Ordering::Relaxed),
        };
        let data = serde_json::to_string(&hist)?;
        fs::write(path, data)?;
        Ok(())
    }

    pub fn start_collectors(self: Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            me.run_qps_calculator().await;
        });
        
        let me = self.clone();
        tokio::spawn(async move {
            me.run_system_metrics_collector().await;
        });

        let me = self.clone();
        tokio::spawn(async move {
            me.run_top_domains_processor().await;
        });
    }

    /* start_metrics_server moved to admin/mod.rs */

    pub fn get_json_metrics(&self) -> DashboardMetrics {
        let top_nx_domains = self.get_top_map(&self.top_nx_domains, |k, v| DomainCount { domain: k, count: *v });
        let top_latency_domains = self.get_top_latency();
        let top_queried_domains = self.get_top_map(&self.top_queried_domains, |k, v| DomainCount { domain: k, count: *v });
        let query_types = self.get_top_map(&self.query_types, |k, v| TypeCount { query_type: k, count: *v });
        let response_codes = self.get_top_map(&self.response_codes, |k, v| CodeCount { code: k, count: *v });

        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let cache_hit_rate = if hits + misses > 0 {
            (hits as f64 / (hits + misses) as f64) * 100.0
        } else {
            0.0
        };

        DashboardMetrics {
            qps: *self.qps.read().unwrap(),
            total_queries: self.total_queries.load(Ordering::Relaxed),
            blocked_domains: self.blocked_domains.load(Ordering::Relaxed),
            cpu_usage: *self.cpu_usage.read().unwrap(),
            memory_usage: *self.memory_usage.read().unwrap(),
            goroutines: *self.threads.read().unwrap(),
            cache_hits: hits,
            cache_misses: misses,
            cache_hit_rate,
            top_nx_domains,
            top_latency_domains,
            top_queried_domains,
            query_types,
            response_codes,
        }
    }

    fn get_top_map<T, F>(&self, map: &DashMap<String, i64>, mapper: F) -> Vec<T>
    where F: Fn(String, &i64) -> T
    {
        let mut items: Vec<(String, i64)> = map.iter().map(|r| (r.key().clone(), *r.value())).collect();
        items.sort_by(|a, b| b.1.cmp(&a.1));
        items.truncate(10);
        items.into_iter().map(|(k, v)| mapper(k, &v)).collect()
    }

    fn get_top_latency(&self) -> Vec<DomainLatency> {
        let mut items: Vec<(String, f64)> = self.top_latency_domains.iter().filter_map(|r| {
            let stat = r.value();
            if stat.count > 0 {
                let avg = stat.total_latency.as_secs_f64() * 1000.0 / stat.count as f64;
                Some((r.key().clone(), avg))
            } else {
                None
            }
        }).collect();

        items.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        items.truncate(10);
        items.into_iter().map(|(k, v)| DomainLatency { domain: k, avg_latency: v }).collect()
    }

    async fn run_qps_calculator(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let mut last_query_count = self.total_queries.load(Ordering::Relaxed);

        loop {
            interval.tick().await;
            let current_queries = self.total_queries.load(Ordering::Relaxed);
            let qps = (current_queries - last_query_count).max(0) as f64;
            last_query_count = current_queries;

            *self.qps.write().unwrap() = qps;
            self.prom_qps.set(qps);
        }
    }

    async fn run_system_metrics_collector(&self) {
        let mut sys = System::new_all();
        let mut interval = tokio::time::interval(Duration::from_secs(2));

        loop {
            interval.tick().await;
            sys.refresh_all();

            let cpu_usage = sys.global_cpu_usage();
            *self.cpu_usage.write().unwrap() = cpu_usage;
            self.prom_cpu_usage.set(cpu_usage as f64);

            let mem_usage = (sys.used_memory() as f64 / sys.total_memory() as f64) * 100.0;
            *self.memory_usage.write().unwrap() = mem_usage;
            self.prom_memory_usage.set(mem_usage);

            // Threads/Goroutines approximation
            if let Ok(_pid) = get_current_pid() {
                // Not supported everywhere, but keeping it simple
            }

            // Network
            let networks = Networks::new_with_refreshed_list();
            let mut sent = 0;
            let mut recv = 0;
            for (_interface_name, data) in &networks {
                sent += data.total_transmitted();
                recv += data.total_received();
            }
            self.prom_network_sent.set(sent as f64);
            self.prom_network_recv.set(recv as f64);
        }
    }

    async fn run_top_domains_processor(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;

            // Update Prometheus Top NX Domains
            let top_nx = self.get_top_map(&self.top_nx_domains, |k, v| (k, *v));
            for (domain, count) in top_nx {
                 self.prom_top_nx_domains.with_label_values(&[&domain]).set(count as f64);
            }

            // Top Latency
            let top_latency = self.get_top_latency();
            for item in top_latency {
                self.prom_top_latency_domains.with_label_values(&[&item.domain]).set(item.avg_latency);
            }

            // Top Queried
            let top_queried = self.get_top_map(&self.top_queried_domains, |k, v| (k, *v));
            for (domain, count) in top_queried {
                self.prom_top_queried_domains.with_label_values(&[&domain]).set(count as f64);
            }
        }
    }

    pub fn increment_queries(&self, domain: &str) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        self.prom_total_queries.inc();
        *self.top_queried_domains.entry(domain.to_string()).or_insert(0) += 1;
    }

    #[allow(dead_code)]
    pub fn increment_cache_hits(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
        self.prom_cache_hits.inc();
    }

    pub fn increment_cache_misses(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        self.prom_cache_misses.inc();
    }

    #[allow(dead_code)]
    pub fn record_nxdomain(&self, domain: &str) {
        *self.top_nx_domains.entry(domain.to_string()).or_insert(0) += 1;
    }

    pub fn record_latency(&self, domain: &str, latency: Duration) {
        let mut stat = self.top_latency_domains.entry(domain.to_string()).or_insert(LatencyStat{
            total_latency: Duration::default(),
            count: 0,
        });
        stat.total_latency += latency;
        stat.count += 1;
    }

    pub fn record_query_type(&self, qtype: &str) {
        *self.query_types.entry(qtype.to_string()).or_insert(0) += 1;
        self.prom_query_types.with_label_values(&[qtype]).inc();
    }

    pub fn record_response_code(&self, code: &str) {
        *self.response_codes.entry(code.to_string()).or_insert(0) += 1;
        self.prom_response_codes.with_label_values(&[code]).inc();
    }

    pub fn increment_blocked_domains(&self) {
        self.blocked_domains.fetch_add(1, Ordering::Relaxed);
        self.prom_blocked_domains.inc();
    }

    pub fn increment_lmdb_cache_loads(&self) {
        self.prom_lmdb_cache_loads.inc();
    }

    pub fn increment_lmdb_errors(&self) {
        self.prom_lmdb_errors.inc();
    }
}
