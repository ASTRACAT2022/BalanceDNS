package threat

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics exposes Prometheus metrics for the Threat Intelligence subsystem.
// Label cardinality is strictly bounded (per-feed and per-reason labels only),
// matching the BalanceDNS convention of never using domain/client/random values
// as labels.
type Metrics struct {
	UpdatesTotal   *prometheus.CounterVec
	UpdateDuration prometheus.Histogram
	FeedFetches    *prometheus.CounterVec
	FeedFailures   *prometheus.CounterVec
	FeedIOCs       *prometheus.GaugeVec
	LookupsTotal   *prometheus.CounterVec
	BlockedQueries *prometheus.CounterVec
	ObservedQueries *prometheus.CounterVec
}

// NewMetrics constructs and registers all threat metrics on the given
// registerer. It is safe to call with the shared BalanceDNS registry.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		UpdatesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "balancedns_threat_updates_total",
			Help: "Number of threat feed update cycles by result",
		}, []string{"result"}),
		UpdateDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "balancedns_threat_update_duration_seconds",
			Help:    "Duration of a threat feed update cycle",
			Buckets: []float64{.01, .05, .1, .5, 1, 2, 5, 10, 30, 60},
		}),
		FeedFetches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "balancedns_threat_feed_fetches_total",
			Help: "Number of feed fetches by feed and result",
		}, []string{"feed", "result"}),
		FeedFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "balancedns_threat_feed_failures_total",
			Help: "Number of feed failures by feed",
		}, []string{"feed"}),
		FeedIOCs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "balancedns_threat_feed_iocs",
			Help: "Domains contributed by each feed",
		}, []string{"feed"}),
		LookupsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "balancedns_threat_lookups_total",
			Help: "Threat lookups by outcome",
		}, []string{"result"}),
		BlockedQueries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "balancedns_threat_blocked_total",
			Help: "Queries blocked by threat intelligence by reason",
		}, []string{"reason"}),
		ObservedQueries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "balancedns_threat_observed_total",
			Help: "Queries matched but observe-only by reason",
		}, []string{"reason"}),
	}
	reg.MustRegister(
		m.UpdatesTotal,
		m.UpdateDuration,
		m.FeedFetches,
		m.FeedFailures,
		m.FeedIOCs,
		m.LookupsTotal,
		m.BlockedQueries,
		m.ObservedQueries,
	)
	return m
}

// ObserveUpdate records an update cycle result and duration.
func (m *Metrics) ObserveUpdate(success bool, d time.Duration) {
	if m == nil {
		return
	}
	result := "failed"
	if success {
		result = "succeeded"
	}
	m.UpdatesTotal.WithLabelValues(result).Inc()
	m.UpdateDuration.Observe(d.Seconds())
}

// ObserveFeedFetch records a per-feed fetch result.
func (m *Metrics) ObserveFeedFetch(feed string, ok bool) {
	if m == nil {
		return
	}
	result := "failed"
	if ok {
		result = "ok"
	}
	m.FeedFetches.WithLabelValues(feed, result).Inc()
	if !ok {
		m.FeedFailures.WithLabelValues(feed).Inc()
	}
}

// SetFeedIOC counts records the number of domains a feed contributed.
func (m *Metrics) SetFeedIOC(feed string, n int) {
	if m == nil {
		return
	}
	m.FeedIOCs.WithLabelValues(feed).Set(float64(n))
}

// ObserveLookup records a lookup outcome (miss|allowlist|matched).
func (m *Metrics) ObserveLookup(result string) {
	if m == nil {
		return
	}
	m.LookupsTotal.WithLabelValues(result).Inc()
}

// ObserveBlocked records a blocked decision by reason.
func (m *Metrics) ObserveBlocked(reason string) {
	if m == nil {
		return
	}
	m.BlockedQueries.WithLabelValues(reason).Inc()
}

// ObserveObserved records an observe-only decision by reason.
func (m *Metrics) ObserveObserved(reason string) {
	if m == nil {
		return
	}
	m.ObservedQueries.WithLabelValues(reason).Inc()
}
