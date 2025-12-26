use std::sync::Arc;
use crate::metrics::Metrics;
use crate::plugins::PluginManager;
use tokio::task;

pub struct AdminServer {
    addr: String,
    metrics: Arc<Metrics>,
    pm: Arc<PluginManager>, // Kept for future admin actions (e.g. reload plugins)
}

impl AdminServer {
    pub fn new(addr: &str, metrics: Arc<Metrics>, pm: Arc<PluginManager>) -> Self {
        AdminServer {
            addr: addr.to_string(),
            metrics,
            pm,
        }
    }

    pub async fn start(self) -> anyhow::Result<()> {
        let metrics = self.metrics.clone();
        let addr = self.addr.clone();

        // We reuse the metrics server implementation which already serves /metrics, /metrics.json, /dashboard
        // In the Go code, AdminServer wraps the http server.
        // In our Rust metrics implementation, we have `start_metrics_server`.
        // So we can just delegate to that for now, as it covers the requirements.

        // Note: The metrics implementation takes `self` by Arc, so we need to be careful.
        // `Metrics::start_metrics_server` is an async method on `Arc<Metrics>`.

        log::info!("Starting admin/metrics server on {}", addr);
        metrics.start_metrics_server(&addr).await
    }
}
