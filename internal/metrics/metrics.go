package metrics

import (
	"encoding/json"
	"errors"
	"log"
	"math"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

// LatencyStat holds the total latency and count for a domain.
type LatencyStat struct {
	TotalLatency time.Duration
	Count        int64
}

// JSON-friendly structs for the dashboard.
type DomainCount struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}

type DomainLatency struct {
	Domain     string  `json:"domain"`
	AvgLatency float64 `json:"avg_latency"`
}

type TypeCount struct {
	Type  string `json:"type"`
	Count int64  `json:"count"`
}

type CodeCount struct {
	Code  string `json:"code"`
	Count int64  `json:"count"`
}

type DashboardMetrics struct {
	QPS               float64         `json:"qps"`
	TotalQueries      int64           `json:"total_queries"`
	BlockedDomains    int64           `json:"blocked_domains"`
	CPUUsage          float64         `json:"cpu_usage"`
	MemoryUsage       float64         `json:"memory_usage"`
	Goroutines        int             `json:"goroutines"`
	CacheHits         int64           `json:"cache_hits"`
	CacheMisses       int64           `json:"cache_misses"`
	CacheHitRate      float64         `json:"cache_hit_rate"`
	TopNXDomains      []DomainCount   `json:"top_nx_domains"`
	TopLatencyDomains []DomainLatency `json:"top_latency_domains"`
	TopQueriedDomains []DomainCount   `json:"top_queried_domains"`
	QueryTypes        []TypeCount     `json:"query_types"`
	ResponseCodes     []CodeCount     `json:"response_codes"`
}

type counterValue struct {
	value atomic.Int64
}

type latencyValue struct {
	totalNanos atomic.Int64
	count      atomic.Int64
}

// Metrics holds collected metrics.
type Metrics struct {
	TotalQueries   atomic.Int64
	BlockedDomains atomic.Int64

	startTime time.Time

	TopNXDomains      sync.Map // map[string]*counterValue
	TopLatencyDomains sync.Map // map[string]*latencyValue
	TopQueriedDomains sync.Map // map[string]*counterValue
	QueryTypes        sync.Map // map[string]*counterValue
	ResponseCodes     sync.Map // map[string]*counterValue
	TransportRequests sync.Map // map[string]*counterValue

	qpsBits         atomic.Uint64
	cpuUsageBits    atomic.Uint64
	memoryUsageBits atomic.Uint64
	goroutines      atomic.Int64
	cacheHits       atomic.Int64
	cacheMisses     atomic.Int64
	topDomainsOn    atomic.Bool
}

var (
	instance *Metrics
	once     sync.Once

	promQPS = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_qps",
		Help: "Queries per second",
	})
	promQPSByTransport = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dns_resolver_qps_by_transport",
		Help: "Requests per second grouped by transport (udp/tcp/dot/doh/odoh)",
	}, []string{"transport"})
	promTotalQueries = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_total_queries",
		Help: "Total number of DNS queries",
	})
	promRequestsByTransportTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_resolver_requests_by_transport_total",
		Help: "Total DNS requests grouped by transport",
	}, []string{"transport"})
	promDNSRequestsInflight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_requests_inflight",
		Help: "Current number of in-flight DNS requests",
	})
	promDNSRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_resolver_requests_total",
		Help: "Total number of DNS requests by transport and outcome",
	}, []string{"transport", "outcome"})
	promSecurityDrops = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_resolver_security_drops_total",
		Help: "Total DNS requests dropped by security controls",
	}, []string{"transport", "reason"})
	promPolicyActions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_resolver_policy_actions_total",
		Help: "Total policy actions applied by built-in policy engine",
	}, []string{"action"})
	promDNSRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "dns_resolver_request_duration_seconds",
		Help:    "DNS request duration in seconds by transport and response code",
		Buckets: []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
	}, []string{"transport", "rcode"})
	promMalformedRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_resolver_malformed_requests_total",
		Help: "Total malformed/invalid DNS requests by transport",
	}, []string{"transport"})
	promCacheProbation = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_cache_probation_size",
		Help: "Size of the probation segment of the cache",
	})
	promCacheProtected = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_cache_protected_size",
		Help: "Size of the protected segment of the cache",
	})
	promCPUUsage = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_cpu_usage_percent",
		Help: "Current CPU usage percentage",
	})
	promMemoryUsage = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_memory_usage_percent",
		Help: "Current memory usage percentage",
	})
	promGoroutineCount = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_goroutine_count",
		Help: "Current number of goroutines",
	})
	promUptimeSeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_uptime_seconds",
		Help: "Process uptime in seconds",
	})
	promNetworkSent = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_network_sent_bytes",
		Help: "Total network bytes sent",
	})
	promNetworkRecv = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_network_recv_bytes",
		Help: "Total network bytes received",
	})
	promTopNXDomains = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dns_resolver_top_nx_domains",
		Help: "Top domains with NXDOMAIN responses",
	}, []string{"domain"})
	promTopLatencyDomains = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dns_resolver_top_latency_domains_ms",
		Help: "Top domains by average query latency in milliseconds",
	}, []string{"domain"})
	promTopQueriedDomains = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dns_resolver_top_queried_domains",
		Help: "Top queried domains",
	}, []string{"domain"})
	promQueryTypes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_resolver_query_types_total",
		Help: "Total number of queries by type",
	}, []string{"type"})
	promResponseCodes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_resolver_response_codes_total",
		Help: "Total number of responses by code",
	}, []string{"code"})
	promUnboundErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_unbound_errors_total",
		Help: "Total number of errors from the Unbound resolver",
	})
	promDNSSECValidation = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_resolver_dnssec_validation_total",
		Help: "Total number of DNSSEC validation results by type",
	}, []string{"result"})
	promCacheRevalidations = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_cache_revalidations_total",
		Help: "Total number of cache revalidations",
	})
	promCacheHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_cache_hits_total",
		Help: "Total number of cache hits",
	})
	promCacheMisses = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_cache_misses_total",
		Help: "Total number of cache misses",
	})
	promBlockedDomains = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_blocked_domains_total",
		Help: "Total number of blocked domains",
	})
	promCacheEvictions = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_cache_evictions_total",
		Help: "Total number of cache evictions",
	})
	promLMDBCacheLoads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_lmdb_loads_total",
		Help: "Total number of items loaded from LMDB",
	})
	promLMDBErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_lmdb_errors_total",
		Help: "Total number of LMDB errors",
	})
	promPrefetches = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_prefetches_total",
		Help: "Total number of cache prefetches",
	})
	promDroppedCacheWrites = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_dropped_cache_writes_total",
		Help: "Total number of cache writes dropped due to queue overflow",
	})
)

// HistoricalData holds metrics that are persisted.
type HistoricalData struct {
	TotalQueries int64 `json:"total_queries"`
}

// NewMetrics returns a singleton Metrics instance.
func NewMetrics(storagePath string) *Metrics {
	once.Do(func() {
		instance = &Metrics{
			startTime: time.Now(),
		}
		instance.topDomainsOn.Store(true)

		if err := instance.loadHistoricalData(storagePath); err != nil {
			log.Printf("Could not load historical metrics: %v", err)
		}

		go instance.qpsCalculator()
		go instance.systemMetricsCollector()
		go instance.topDomainsProcessor()
	})
	return instance
}

func (m *Metrics) loadHistoricalData(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var historicalData HistoricalData
	if err := json.Unmarshal(data, &historicalData); err != nil {
		return err
	}

	if historicalData.TotalQueries > 0 {
		m.TotalQueries.Store(historicalData.TotalQueries)
		promTotalQueries.Add(float64(historicalData.TotalQueries))
	}

	return nil
}

// SaveHistoricalData saves metrics to a file.
func (m *Metrics) SaveHistoricalData(path string) error {
	historicalData := HistoricalData{TotalQueries: m.TotalQueries.Load()}

	data, err := json.Marshal(historicalData)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// StartMetricsServer starts an HTTP server for Prometheus and dashboard metrics.
func (m *Metrics) StartMetricsServer(addr string) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/metrics.json", m.jsonMetricsHandler)
	mux.HandleFunc("/dashboard", m.dashboardHandler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("READY"))
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("Metrics server starting on %s", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("Metrics server failed: %v", err)
	}
}

func (m *Metrics) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "internal/dashboard/index.html")
}

func (m *Metrics) jsonMetricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(m.SnapshotDashboard()); err != nil {
		log.Printf("Error encoding metrics to JSON: %v", err)
	}
}

// SnapshotDashboard returns a point-in-time metrics snapshot safe for concurrent use.
func (m *Metrics) SnapshotDashboard() DashboardMetrics {
	topNXDomains := getTopDomainCounts(&m.TopNXDomains, 10)
	topLatencyDomains := getTopLatencyDomains(&m.TopLatencyDomains, 10)
	topQueriedDomains := getTopDomainCounts(&m.TopQueriedDomains, 10)
	queryTypes := getTypeCounts(&m.QueryTypes)
	responseCodes := getCodeCounts(&m.ResponseCodes)

	cacheHits := m.cacheHits.Load()
	cacheMisses := m.cacheMisses.Load()
	cacheHitRate := 0.0
	if cacheHits+cacheMisses > 0 {
		cacheHitRate = float64(cacheHits) / float64(cacheHits+cacheMisses) * 100
	}

	return DashboardMetrics{
		QPS:               loadFloat64(&m.qpsBits),
		TotalQueries:      m.TotalQueries.Load(),
		BlockedDomains:    m.BlockedDomains.Load(),
		CPUUsage:          loadFloat64(&m.cpuUsageBits),
		MemoryUsage:       loadFloat64(&m.memoryUsageBits),
		Goroutines:        int(m.goroutines.Load()),
		CacheHits:         cacheHits,
		CacheMisses:       cacheMisses,
		CacheHitRate:      cacheHitRate,
		TopNXDomains:      topNXDomains,
		TopLatencyDomains: topLatencyDomains,
		TopQueriedDomains: topQueriedDomains,
		QueryTypes:        queryTypes,
		ResponseCodes:     responseCodes,
	}
}

// SetTopDomainsTracking enables/disables high-cardinality per-domain stats.
func (m *Metrics) SetTopDomainsTracking(enabled bool) {
	if m == nil {
		return
	}
	m.topDomainsOn.Store(enabled)
	if !enabled {
		promTopNXDomains.Reset()
		promTopLatencyDomains.Reset()
		promTopQueriedDomains.Reset()
	}
}

// RecordDNSQuery records a valid DNS question consistently across transports.
func (m *Metrics) RecordDNSQuery(question dns.Question) {
	if m == nil {
		return
	}
	m.IncrementQueries(question.Name)
	m.RecordQueryType(qtypeToText(question.Qtype))
}

// RecordDNSResponse records a DNS response code and NXDOMAIN statistics.
func (m *Metrics) RecordDNSResponse(qName string, rcode int) {
	if m == nil {
		return
	}
	m.RecordResponseCode(rcodeToText(rcode))
	if rcode == dns.RcodeNameError {
		m.RecordNXDOMAIN(qName)
	}
}

// IncrementQueries increments the total number of queries.
func (m *Metrics) IncrementQueries(domain string) {
	m.TotalQueries.Add(1)
	promTotalQueries.Inc()
	if m.topDomainsOn.Load() {
		incrementCounterMap(&m.TopQueriedDomains, domain)
	}
}

// GetQueries returns the total number of queries.
func (m *Metrics) GetQueries() int64 {
	return m.TotalQueries.Load()
}

func (m *Metrics) qpsCalculator() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	lastQueryCount := m.TotalQueries.Load()
	lastTransportCounts := map[string]int64{}
	counter := 0
	for range ticker.C {
		currentQueries := m.TotalQueries.Load()
		qps := float64(currentQueries - lastQueryCount)
		if qps < 0 {
			qps = 0
		}
		lastQueryCount = currentQueries

		storeFloat64(&m.qpsBits, qps)
		promQPS.Set(qps)
		lastTransportCounts = m.updateTransportQPS(lastTransportCounts)

		counter++
		if counter%30 == 0 {
			log.Printf("QPS: %.2f, Total Queries: %d", qps, currentQueries)
		}
	}
}

func (m *Metrics) systemMetricsCollector() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cpuPercentages, err := cpu.Percent(0, false)
		if err == nil && len(cpuPercentages) > 0 {
			storeFloat64(&m.cpuUsageBits, cpuPercentages[0])
			promCPUUsage.Set(cpuPercentages[0])
		} else if err != nil {
			log.Printf("Error collecting CPU metrics: %v", err)
		}

		memInfo, err := mem.VirtualMemory()
		if err == nil {
			storeFloat64(&m.memoryUsageBits, memInfo.UsedPercent)
			promMemoryUsage.Set(memInfo.UsedPercent)
		} else if err != nil {
			log.Printf("Error collecting memory metrics: %v", err)
		}

		gCount := runtime.NumGoroutine()
		m.goroutines.Store(int64(gCount))
		promGoroutineCount.Set(float64(gCount))
		promUptimeSeconds.Set(time.Since(m.startTime).Seconds())

		netIO, err := net.IOCounters(false)
		if err == nil && len(netIO) > 0 {
			promNetworkSent.Set(float64(netIO[0].BytesSent))
			promNetworkRecv.Set(float64(netIO[0].BytesRecv))
		} else if err != nil {
			log.Printf("Error collecting network metrics: %v", err)
		}
	}
}

// UpdateCacheStats updates the cache statistics.
func (m *Metrics) UpdateCacheStats(probation, protected int) {
	promCacheProbation.Set(float64(probation))
	promCacheProtected.Set(float64(protected))
}

// IncrementInflightRequests increments number of in-flight requests.
func (m *Metrics) IncrementInflightRequests() {
	promDNSRequestsInflight.Inc()
}

// DecrementInflightRequests decrements number of in-flight requests.
func (m *Metrics) DecrementInflightRequests() {
	promDNSRequestsInflight.Dec()
}

// RecordRequestOutcome records request outcome and duration by transport.
func (m *Metrics) RecordRequestOutcome(transport, outcome, rcode string, duration time.Duration) {
	if transport == "" {
		transport = "unknown"
	}
	if outcome == "" {
		outcome = "unknown"
	}
	if rcode == "" {
		rcode = "UNKNOWN"
	}

	incrementCounterMap(&m.TransportRequests, transport)
	promRequestsByTransportTotal.WithLabelValues(transport).Inc()
	promDNSRequestsTotal.WithLabelValues(transport, outcome).Inc()
	promDNSRequestDuration.WithLabelValues(transport, rcode).Observe(duration.Seconds())
}

// RecordMalformedRequest increments malformed request counter.
func (m *Metrics) RecordMalformedRequest(transport string) {
	if transport == "" {
		transport = "unknown"
	}
	promMalformedRequests.WithLabelValues(transport).Inc()
}

// RecordSecurityDrop increments security drop counter by reason/transport.
func (m *Metrics) RecordSecurityDrop(reason, transport string) {
	if transport == "" {
		transport = "unknown"
	}
	if reason == "" {
		reason = "unknown"
	}
	promSecurityDrops.WithLabelValues(transport, reason).Inc()
}

// RecordPolicyAction increments policy action counter.
func (m *Metrics) RecordPolicyAction(action string) {
	if action == "" {
		action = "unknown"
	}
	promPolicyActions.WithLabelValues(action).Inc()
}

// RecordNXDOMAIN records an NXDOMAIN response for a given domain.
func (m *Metrics) RecordNXDOMAIN(domain string) {
	if m.topDomainsOn.Load() {
		incrementCounterMap(&m.TopNXDomains, domain)
	}
}

// RecordLatency records query latency for a given domain.
func (m *Metrics) RecordLatency(domain string, latency time.Duration) {
	if m.topDomainsOn.Load() {
		recordLatencyMap(&m.TopLatencyDomains, domain, latency)
	}
}

func (m *Metrics) topDomainsProcessor() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !m.topDomainsOn.Load() {
			continue
		}
		m.processTopNXDomains()
		m.processTopLatencyDomains()
		m.processTopQueriedDomains()
	}
}

func (m *Metrics) processTopNXDomains() {
	domains := getTopDomainCounts(&m.TopNXDomains, 10)
	promTopNXDomains.Reset()
	for _, d := range domains {
		promTopNXDomains.WithLabelValues(d.Domain).Set(float64(d.Count))
	}
}

func (m *Metrics) processTopLatencyDomains() {
	domains := getTopLatencyDomains(&m.TopLatencyDomains, 10)
	promTopLatencyDomains.Reset()
	for _, d := range domains {
		promTopLatencyDomains.WithLabelValues(d.Domain).Set(d.AvgLatency)
	}
}

func (m *Metrics) processTopQueriedDomains() {
	domains := getTopDomainCounts(&m.TopQueriedDomains, 10)
	promTopQueriedDomains.Reset()
	for _, d := range domains {
		promTopQueriedDomains.WithLabelValues(d.Domain).Set(float64(d.Count))
	}
}

// RecordQueryType records DNS query type.
func (m *Metrics) RecordQueryType(qtype string) {
	incrementCounterMap(&m.QueryTypes, qtype)
	promQueryTypes.WithLabelValues(qtype).Inc()
}

// RecordResponseCode records DNS response code.
func (m *Metrics) RecordResponseCode(rcode string) {
	incrementCounterMap(&m.ResponseCodes, rcode)
	promResponseCodes.WithLabelValues(rcode).Inc()
}

// IncrementUnboundErrors increments the Unbound error counter.
func (m *Metrics) IncrementUnboundErrors() {
	promUnboundErrors.Inc()
}

// RecordDNSSECValidation records DNSSEC validation result.
func (m *Metrics) RecordDNSSECValidation(result string) {
	promDNSSECValidation.WithLabelValues(result).Inc()
}

// IncrementCacheRevalidations increments cache revalidation counter.
func (m *Metrics) IncrementCacheRevalidations() {
	promCacheRevalidations.Inc()
}

// IncrementCacheHits increments cache hit counter.
func (m *Metrics) IncrementCacheHits() {
	m.cacheHits.Add(1)
	promCacheHits.Inc()
}

// IncrementCacheMisses increments cache miss counter.
func (m *Metrics) IncrementCacheMisses() {
	m.cacheMisses.Add(1)
	promCacheMisses.Inc()
}

// IncrementCacheEvictions increments cache eviction counter.
func (m *Metrics) IncrementCacheEvictions() {
	promCacheEvictions.Inc()
}

// IncrementLMDBCacheLoads increments LMDB load counter.
func (m *Metrics) IncrementLMDBCacheLoads() {
	promLMDBCacheLoads.Inc()
}

// IncrementLMDBErrors increments LMDB error counter.
func (m *Metrics) IncrementLMDBErrors() {
	promLMDBErrors.Inc()
}

// IncrementPrefetches increments prefetch counter.
func (m *Metrics) IncrementPrefetches() {
	promPrefetches.Inc()
}

// IncrementDroppedCacheWrites increments dropped cache writes counter.
func (m *Metrics) IncrementDroppedCacheWrites() {
	promDroppedCacheWrites.Inc()
}

// IncrementBlockedDomains increments blocked domains counter.
func (m *Metrics) IncrementBlockedDomains() {
	m.BlockedDomains.Add(1)
	promBlockedDomains.Inc()
}

func incrementCounterMap(store *sync.Map, key string) int64 {
	if key == "" {
		key = "unknown"
	}

	actual, _ := store.LoadOrStore(key, &counterValue{})
	counter, ok := actual.(*counterValue)
	if !ok {
		return 0
	}
	return counter.value.Add(1)
}

func recordLatencyMap(store *sync.Map, key string, latency time.Duration) {
	if key == "" {
		key = "unknown"
	}

	actual, _ := store.LoadOrStore(key, &latencyValue{})
	acc, ok := actual.(*latencyValue)
	if !ok {
		return
	}
	acc.totalNanos.Add(latency.Nanoseconds())
	acc.count.Add(1)
}

func getTopDomainCounts(store *sync.Map, limit int) []DomainCount {
	items := make([]DomainCount, 0)
	store.Range(func(key, value interface{}) bool {
		counter, ok := value.(*counterValue)
		if !ok {
			return true
		}
		count := counter.value.Load()
		if count <= 0 {
			return true
		}
		items = append(items, DomainCount{Domain: key.(string), Count: count})
		return true
	})

	sort.Slice(items, func(i, j int) bool { return items[i].Count > items[j].Count })
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func getTopLatencyDomains(store *sync.Map, limit int) []DomainLatency {
	items := make([]DomainLatency, 0)
	store.Range(func(key, value interface{}) bool {
		acc, ok := value.(*latencyValue)
		if !ok {
			return true
		}
		count := acc.count.Load()
		if count <= 0 {
			return true
		}
		totalNs := acc.totalNanos.Load()
		avgLatencyMs := float64(totalNs) / float64(count) / float64(time.Millisecond)
		items = append(items, DomainLatency{Domain: key.(string), AvgLatency: avgLatencyMs})
		return true
	})

	sort.Slice(items, func(i, j int) bool { return items[i].AvgLatency > items[j].AvgLatency })
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func getTypeCounts(store *sync.Map) []TypeCount {
	items := make([]TypeCount, 0)
	store.Range(func(key, value interface{}) bool {
		counter, ok := value.(*counterValue)
		if !ok {
			return true
		}
		count := counter.value.Load()
		if count <= 0 {
			return true
		}
		items = append(items, TypeCount{Type: key.(string), Count: count})
		return true
	})
	sort.Slice(items, func(i, j int) bool { return items[i].Count > items[j].Count })
	return items
}

func getCodeCounts(store *sync.Map) []CodeCount {
	items := make([]CodeCount, 0)
	store.Range(func(key, value interface{}) bool {
		counter, ok := value.(*counterValue)
		if !ok {
			return true
		}
		count := counter.value.Load()
		if count <= 0 {
			return true
		}
		items = append(items, CodeCount{Code: key.(string), Count: count})
		return true
	})
	sort.Slice(items, func(i, j int) bool { return items[i].Count > items[j].Count })
	return items
}

func storeFloat64(target *atomic.Uint64, v float64) {
	target.Store(math.Float64bits(v))
}

func loadFloat64(target *atomic.Uint64) float64 {
	return math.Float64frombits(target.Load())
}

func qtypeToText(qtype uint16) string {
	if text := dns.TypeToString[qtype]; text != "" {
		return text
	}
	return strconv.FormatUint(uint64(qtype), 10)
}

func rcodeToText(rcode int) string {
	if text := dns.RcodeToString[rcode]; text != "" {
		return text
	}
	return strconv.Itoa(rcode)
}

func snapshotCounterMap(store *sync.Map) map[string]int64 {
	out := make(map[string]int64)
	store.Range(func(key, value interface{}) bool {
		k, ok := key.(string)
		if !ok {
			return true
		}
		counter, ok := value.(*counterValue)
		if !ok {
			return true
		}
		out[k] = counter.value.Load()
		return true
	})
	return out
}

func (m *Metrics) updateTransportQPS(lastCounts map[string]int64) map[string]int64 {
	current := snapshotCounterMap(&m.TransportRequests)

	for transport, currentCount := range current {
		prev := lastCounts[transport]
		delta := currentCount - prev
		if delta < 0 {
			delta = 0
		}
		promQPSByTransport.WithLabelValues(transport).Set(float64(delta))
	}
	for transport := range lastCounts {
		if _, ok := current[transport]; !ok {
			promQPSByTransport.WithLabelValues(transport).Set(0)
		}
	}

	return current
}
