package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Provider struct {
	registry              *prometheus.Registry
	QueriesTotal          prometheus.Counter
	CacheHitsTotal        prometheus.Counter
	UpstreamLatency       *prometheus.HistogramVec
	PluginExecutionErrors prometheus.Counter
	ComponentUp           *prometheus.GaugeVec
	ComponentRestarts     *prometheus.CounterVec
}

func New() *Provider {
	registry := prometheus.NewRegistry()

	p := &Provider{
		registry: registry,
		QueriesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "balancedns_queries_total",
			Help: "Total DNS queries received",
		}),
		CacheHitsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "balancedns_cache_hits_total",
			Help: "Total DNS cache hits",
		}),
		UpstreamLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "balancedns_upstream_latency_seconds",
			Help:    "Upstream DNS response latency",
			Buckets: []float64{0.001, 0.003, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1},
		}, []string{"upstream"}),
		PluginExecutionErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "balancedns_plugin_execution_errors",
			Help: "Total Lua plugin execution errors",
		}),
		ComponentUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "balancedns_component_up",
			Help: "Component running state (1=up, 0=down)",
		}, []string{"component"}),
		ComponentRestarts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "balancedns_component_restarts_total",
			Help: "Total component restarts by supervisor",
		}, []string{"component"}),
	}

	registry.MustRegister(
		p.QueriesTotal,
		p.CacheHitsTotal,
		p.UpstreamLatency,
		p.PluginExecutionErrors,
		p.ComponentUp,
		p.ComponentRestarts,
	)

	return p
}

func (p *Provider) Handler() http.Handler {
	return promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{})
}

func (p *Provider) IncQueries() {
	p.QueriesTotal.Inc()
}

func (p *Provider) IncCacheHits() {
	p.CacheHitsTotal.Inc()
}

func (p *Provider) IncPluginErrors() {
	p.PluginExecutionErrors.Inc()
}

func (p *Provider) ObserveUpstreamLatency(upstream string, d time.Duration) {
	p.UpstreamLatency.WithLabelValues(upstream).Observe(d.Seconds())
}

func (p *Provider) SetComponentUp(component string, up bool) {
	if up {
		p.ComponentUp.WithLabelValues(component).Set(1)
		return
	}
	p.ComponentUp.WithLabelValues(component).Set(0)
}

func (p *Provider) IncComponentRestart(component string) {
	p.ComponentRestarts.WithLabelValues(component).Inc()
}
