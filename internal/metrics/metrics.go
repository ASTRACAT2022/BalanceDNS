package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

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

// JSON-friendly structs for the dashboard
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

// Metrics holds the collected metrics.
type Metrics struct {
	sync.RWMutex
	TotalQueries      int64
	BlockedDomains    int64
	startTime         time.Time
	queryCountHistory []int64
	TopNXDomains      sync.Map // map[string]int64
	TopLatencyDomains sync.Map // map[string]LatencyStat
	TopQueriedDomains sync.Map // map[string]int64
	QueryTypes        sync.Map // map[string]int64
	ResponseCodes     sync.Map // map[string]int64
	registry          *prometheus.Registry

	// Fields for direct access by JSON handler
	QPS         float64
	CPUUsage    float64
	MemoryUsage float64
	Goroutines  int
	CacheHits   int64
	CacheMisses int64
}

var (
	instance     *Metrics
	once         sync.Once
	lastQueryCount int64 // Добавлено для отслеживания QPS

	// Prometheus metrics
	promQPS = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_resolver_qps",
		Help: "Queries per second",
	})
	promTotalQueries = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_resolver_total_queries",
		Help: "Total number of DNS queries",
	})
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
)

// HistoricalData holds metrics that are persisted.
type HistoricalData struct {
	TotalQueries int64 `json:"total_queries"`
}

// NewMetrics returns the singleton instance of Metrics.
func NewMetrics(storagePath string) *Metrics {
	once.Do(func() {
		registry := prometheus.NewRegistry()
		registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
		registry.MustRegister(prometheus.NewGoCollector())

		instance = &Metrics{
			startTime:         time.Now(),
			registry:          registry,
			queryCountHistory: make([]int64, 0, 10),
		}

		// Load historical data
		if err := instance.loadHistoricalData(storagePath); err != nil {
			log.Printf("Could not load historical metrics: %v", err)
		}

		// Save historical data on shutdown
		// This requires a signal handler in main.go to call SaveHistoricalData
		go instance.qpsCalculator()
		go instance.systemMetricsCollector()
		go instance.topDomainsProcessor()
	})
	return instance
}

// loadHistoricalData loads metrics from a file.
func (m *Metrics) loadHistoricalData(path string) error {
	m.Lock()
	defer m.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No historical data yet
		}
		return err
	}

	var historicalData HistoricalData
	if err := json.Unmarshal(data, &historicalData); err != nil {
		return err
	}

	m.TotalQueries = historicalData.TotalQueries
	promTotalQueries.Add(float64(m.TotalQueries))
	return nil
}

// SaveHistoricalData saves metrics to a file.
func (m *Metrics) SaveHistoricalData(path string) error {
	m.RLock()
	defer m.RUnlock()

	historicalData := HistoricalData{
		TotalQueries: m.TotalQueries,
	}

	data, err := json.Marshal(historicalData)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// StartMetricsServer starts an HTTP server for Prometheus metrics.
func (m *Metrics) StartMetricsServer(addr string) {
	http.Handle("/metrics", promhttp.HandlerFor(
		m.registry, // Используем собственный реестр
		promhttp.HandlerOpts{
			EnableOpenMetrics: true,
		},
	))

	http.HandleFunc("/metrics.json", m.jsonMetricsHandler)
	http.HandleFunc("/dashboard", m.dashboardHandler)

	// Добавляем эндпоинт для проверки здоровья
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Printf("Metrics server starting on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Failed to start metrics server: %v", err)
	}
}

// dashboardHandler serves the HTML dashboard page.
func (m *Metrics) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "internal/dashboard/index.html")
}

// jsonMetricsHandler serves metrics in JSON format for the dashboard.
func (m *Metrics) jsonMetricsHandler(w http.ResponseWriter, r *http.Request) {
	m.RLock()
	defer m.RUnlock()

	var topNXDomains []DomainCount
	m.TopNXDomains.Range(func(key, value interface{}) bool {
		topNXDomains = append(topNXDomains, DomainCount{Domain: key.(string), Count: value.(int64)})
		return true
	})
	sort.Slice(topNXDomains, func(i, j int) bool { return topNXDomains[i].Count > topNXDomains[j].Count })
	if len(topNXDomains) > 10 {
		topNXDomains = topNXDomains[:10]
	}

	var topLatencyDomains []DomainLatency
	m.TopLatencyDomains.Range(func(key, value interface{}) bool {
		stat := value.(LatencyStat)
		if stat.Count > 0 {
			avgLatency := stat.TotalLatency.Seconds() * 1000 / float64(stat.Count)
			topLatencyDomains = append(topLatencyDomains, DomainLatency{Domain: key.(string), AvgLatency: avgLatency})
		}
		return true
	})
	sort.Slice(topLatencyDomains, func(i, j int) bool { return topLatencyDomains[i].AvgLatency > topLatencyDomains[j].AvgLatency })
	if len(topLatencyDomains) > 10 {
		topLatencyDomains = topLatencyDomains[:10]
	}

	var topQueriedDomains []DomainCount
	m.TopQueriedDomains.Range(func(key, value interface{}) bool {
		topQueriedDomains = append(topQueriedDomains, DomainCount{Domain: key.(string), Count: value.(int64)})
		return true
	})
	sort.Slice(topQueriedDomains, func(i, j int) bool { return topQueriedDomains[i].Count > topQueriedDomains[j].Count })
	if len(topQueriedDomains) > 10 {
		topQueriedDomains = topQueriedDomains[:10]
	}

	var queryTypes []TypeCount
	m.QueryTypes.Range(func(key, value interface{}) bool {
		queryTypes = append(queryTypes, TypeCount{Type: key.(string), Count: value.(int64)})
		return true
	})
	sort.Slice(queryTypes, func(i, j int) bool { return queryTypes[i].Count > queryTypes[j].Count })

	var responseCodes []CodeCount
	m.ResponseCodes.Range(func(key, value interface{}) bool {
		responseCodes = append(responseCodes, CodeCount{Code: key.(string), Count: value.(int64)})
		return true
	})
	sort.Slice(responseCodes, func(i, j int) bool { return responseCodes[i].Count > responseCodes[j].Count })

	var cacheHitRate float64
	if m.CacheHits+m.CacheMisses > 0 {
		cacheHitRate = float64(m.CacheHits) / float64(m.CacheHits+m.CacheMisses) * 100
	}

	data := DashboardMetrics{
		QPS:                 m.QPS,
		TotalQueries:        m.TotalQueries,
		BlockedDomains:      m.BlockedDomains,
		CPUUsage:            m.CPUUsage,
		MemoryUsage:         m.MemoryUsage,
		Goroutines:          m.Goroutines,
		CacheHits:           m.CacheHits,
		CacheMisses:         m.CacheMisses,
		CacheHitRate:        cacheHitRate,
		TopNXDomains:        topNXDomains,
		TopLatencyDomains:   topLatencyDomains,
		TopQueriedDomains:   topQueriedDomains,
		QueryTypes:          queryTypes,
		ResponseCodes:       responseCodes,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding metrics to JSON: %v", err)
	}
}

// IncrementQueries increments the total number of queries.
func (m *Metrics) IncrementQueries(domain string) {
	m.Lock()
	defer m.Unlock()
	m.TotalQueries++
	promTotalQueries.Inc()
	val, _ := m.TopQueriedDomains.LoadOrStore(domain, int64(0))
	m.TopQueriedDomains.Store(domain, val.(int64)+1)
}

// GetQueries returns the total number of queries.
func (m *Metrics) GetQueries() int64 {
	m.RLock()
	defer m.RUnlock()
	return m.TotalQueries
}

// qpsCalculator calculates the QPS every second.
func (m *Metrics) qpsCalculator() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		m.Lock()
		currentQueries := m.TotalQueries
		qps := float64(currentQueries - lastQueryCount)
		lastQueryCount = currentQueries
		m.QPS = qps
		m.Unlock()
		promQPS.Set(qps)
	}
}

// systemMetricsCollector gathers system metrics periodically.
func (m *Metrics) systemMetricsCollector() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		m.Lock()
		// CPU Usage
		cpuPercentages, err := cpu.Percent(0, false)
		if err == nil && len(cpuPercentages) > 0 {
			m.CPUUsage = cpuPercentages[0]
			promCPUUsage.Set(cpuPercentages[0])
		}

		// Memory Usage
		memInfo, err := mem.VirtualMemory()
		if err == nil {
			m.MemoryUsage = memInfo.UsedPercent
			promMemoryUsage.Set(memInfo.UsedPercent)
		}

		// Goroutine Count
		m.Goroutines = runtime.NumGoroutine()
		promGoroutineCount.Set(float64(m.Goroutines))

		m.Unlock()

		// Network Stats - no need to lock for these, they are just for prometheus
		netIO, err := net.IOCounters(false)
		if err == nil && len(netIO) > 0 {
			promNetworkSent.Set(float64(netIO[0].BytesSent))
			promNetworkRecv.Set(float64(netIO[0].BytesRecv))
		}

		if err != nil {
			log.Printf("Error collecting system metrics: %v", err)
		}
	}
}

// UpdateCacheStats updates the cache statistics.
func (m *Metrics) UpdateCacheStats(probation, protected int) {
	promCacheProbation.Set(float64(probation))
	promCacheProtected.Set(float64(protected))
}

// RecordNXDOMAIN records an NXDOMAIN response for a given domain.
func (m *Metrics) RecordNXDOMAIN(domain string) {
	val, _ := m.TopNXDomains.LoadOrStore(domain, int64(0))
	m.TopNXDomains.Store(domain, val.(int64)+1)
}

// RecordLatency records the query latency for a given domain.
func (m *Metrics) RecordLatency(domain string, latency time.Duration) {
	loadAndStoreLatencyStat(&m.TopLatencyDomains, domain, latency)
}

// Вспомогательная функция для безопасного обновления LatencyStat
func loadAndStoreLatencyStat(store *sync.Map, domain string, latency time.Duration) {
	actual, loaded := store.LoadOrStore(domain, LatencyStat{TotalLatency: latency, Count: 1})
	if loaded {
		oldStat := actual.(LatencyStat)
		newStat := LatencyStat{
			TotalLatency: oldStat.TotalLatency + latency,
			Count:        oldStat.Count + 1,
		}
		store.Store(domain, newStat)
	}
}

// topDomainsProcessor periodically processes the domain maps to generate top lists.
func (m *Metrics) topDomainsProcessor() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		m.processTopNXDomains()
		m.processTopLatencyDomains()
		m.processTopQueriedDomains()
	}
}

func (m *Metrics) processTopNXDomains() {
	var domains []struct {
		Domain string
		Count  int64
	}
	m.TopNXDomains.Range(func(key, value interface{}) bool {
		domains = append(domains, struct {
			Domain string
			Count  int64
		}{key.(string), value.(int64)})
		return true
	})

	// Sort and get top 10
	sort.Slice(domains, func(i, j int) bool {
		return domains[i].Count > domains[j].Count
	})
	if len(domains) > 10 {
		domains = domains[:10]
	}

	promTopNXDomains.Reset()
	for _, d := range domains {
		promTopNXDomains.WithLabelValues(d.Domain).Set(float64(d.Count))
	}
}

func (m *Metrics) processTopLatencyDomains() {
	var domains []struct {
		Domain     string
		AvgLatency float64
	}
	m.TopLatencyDomains.Range(func(key, value interface{}) bool {
		stat := value.(LatencyStat)
		if stat.Count > 0 {
			avgLatency := stat.TotalLatency.Seconds() * 1000 / float64(stat.Count) // avg in ms
			domains = append(domains, struct {
				Domain     string
				AvgLatency float64
			}{key.(string), avgLatency})
		}
		return true
	})

	// Sort and get top 10
	sort.Slice(domains, func(i, j int) bool {
		return domains[i].AvgLatency > domains[j].AvgLatency
	})
	if len(domains) > 10 {
		domains = domains[:10]
	}

	promTopLatencyDomains.Reset()
	for _, d := range domains {
		promTopLatencyDomains.WithLabelValues(d.Domain).Set(d.AvgLatency)
	}
}

// RecordQueryType records the type of a DNS query.
func (m *Metrics) RecordQueryType(qtype string) {
	val, _ := m.QueryTypes.LoadOrStore(qtype, int64(0))
	m.QueryTypes.Store(qtype, val.(int64)+1)
	promQueryTypes.WithLabelValues(qtype).Inc()
}

// RecordResponseCode records the response code of a DNS query.
func (m *Metrics) RecordResponseCode(rcode string) {
	val, _ := m.ResponseCodes.LoadOrStore(rcode, int64(0))
	m.ResponseCodes.Store(rcode, val.(int64)+1)
	promResponseCodes.WithLabelValues(rcode).Inc()
}

// IncrementUnboundErrors increments the Unbound error counter.
func (m *Metrics) IncrementUnboundErrors() {
	promUnboundErrors.Inc()
}

// RecordDNSSECValidation records a DNSSEC validation result.
func (m *Metrics) RecordDNSSECValidation(result string) {
	promDNSSECValidation.WithLabelValues(result).Inc()
}

// IncrementCacheRevalidations increments the cache revalidation counter.
func (m *Metrics) IncrementCacheRevalidations() {
	promCacheRevalidations.Inc()
}

// IncrementCacheHits increments the cache hit counter.
func (m *Metrics) IncrementCacheHits() {
	m.Lock()
	m.CacheHits++
	m.Unlock()
	promCacheHits.Inc()
}

// IncrementCacheMisses increments the cache miss counter.
func (m *Metrics) IncrementCacheMisses() {
	m.Lock()
	m.CacheMisses++
	m.Unlock()
	promCacheMisses.Inc()
}

// IncrementCacheEvictions increments the cache eviction counter.
func (m *Metrics) IncrementCacheEvictions() {
	promCacheEvictions.Inc()
}

// IncrementLMDBCacheLoads increments the LMDB cache load counter.
func (m *Metrics) IncrementLMDBCacheLoads() {
	promLMDBCacheLoads.Inc()
}

// IncrementLMDBErrors increments the LMDB error counter.
func (m *Metrics) IncrementLMDBErrors() {
	promLMDBErrors.Inc()
}

// IncrementPrefetches increments the prefetch counter.
func (m *Metrics) IncrementPrefetches() {
	promPrefetches.Inc()
}

// IncrementBlockedDomains increments the blocked domains counter.
func (m *Metrics) IncrementBlockedDomains() {
	m.Lock()
	m.BlockedDomains++
	m.Unlock()
	promBlockedDomains.Inc()
}

func (m *Metrics) processTopQueriedDomains() {
	var domains []struct {
		Domain string
		Count  int64
	}
	m.TopQueriedDomains.Range(func(key, value interface{}) bool {
		domains = append(domains, struct {
			Domain string
			Count  int64
		}{key.(string), value.(int64)})
		return true
	})

	// Sort and get top 10
	sort.Slice(domains, func(i, j int) bool {
		return domains[i].Count > domains[j].Count
	})
	if len(domains) > 10 {
		domains = domains[:10]
	}

	promTopQueriedDomains.Reset()
	for _, d := range domains {
		promTopQueriedDomains.WithLabelValues(d.Domain).Set(float64(d.Count))
	}
}