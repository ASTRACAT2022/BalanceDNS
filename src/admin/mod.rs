use std::sync::Arc;
use crate::metrics::Metrics;
use crate::plugins::PluginManager;
use crate::config::AdminConfig;
use hyper::{Body, Request, Response, Server, service::{make_service_fn, service_fn}};
use std::convert::Infallible;
use std::net::SocketAddr;
use log::{info, error, warn};
use prometheus::{Encoder, TextEncoder};

pub struct AdminServer {
    addr: String,
    metrics: Arc<Metrics>,
    pm: Arc<PluginManager>,
    config: AdminConfig,
}

impl AdminServer {
    pub fn new(addr: &str, metrics: Arc<Metrics>, pm: Arc<PluginManager>, config: AdminConfig) -> Self {
        AdminServer {
            addr: addr.to_string(),
            metrics,
            pm,
            config,
        }
    }

    pub async fn start(self) -> anyhow::Result<()> {
        let addr_str = self.addr.clone();
        let addr: SocketAddr = addr_str.parse()?;

        // Helper for basic auth
        use base64::Engine;
        let auth_header_val = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", self.config.username, self.config.password)));
        let auth_header_val_arc = Arc::new(auth_header_val);

        let srv = Arc::new(self);

        let make_svc = make_service_fn(move |_conn| {
            let srv = srv.clone();
            let auth = auth_header_val_arc.clone();
            
            async move {
                Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                    let srv = srv.clone();
                    let auth = auth.clone();
                    async move {
                        // Check Auth
                        if !check_auth(&req, &auth) {
                             return Ok::<_, Infallible>(Response::builder()
                                .status(401)
                                .header("WWW-Authenticate", "Basic realm=\"Astracat DNS Admin\"")
                                .body(Body::from("Unauthorized"))
                                .unwrap());
                        }

                        match (req.method(), req.uri().path()) {
                            (&hyper::Method::GET, "/metrics") => {
                                let encoder = TextEncoder::new();
                                let mut buffer = Vec::new();
                                let metric_families = srv.metrics.registry.gather();
                                encoder.encode(&metric_families, &mut buffer).unwrap();
                                Ok::<_, Infallible>(Response::new(Body::from(buffer)))
                            },
                            (&hyper::Method::GET, "/metrics.json") => {
                                let json_metrics = srv.metrics.get_json_metrics();
                                let json = serde_json::to_string(&json_metrics).unwrap_or_default();
                                Ok::<_, Infallible>(Response::builder()
                                    .header("Content-Type", "application/json")
                                    .header("Access-Control-Allow-Origin", "*")
                                    .body(Body::from(json))
                                    .unwrap())
                            },
                             (&hyper::Method::GET, "/dashboard") | (&hyper::Method::GET, "/") => {
                                const DASHBOARD_HTML: &str = include_str!("dashboard.html");
                                Ok::<_, Infallible>(Response::builder()
                                    .header("Content-Type", "text/html")
                                    .body(Body::from(DASHBOARD_HTML))
                                    .unwrap())
                            },
                            (&hyper::Method::POST, "/api/reload") => {
                                // Reload lists
                                info!("Reloading filter lists via Admin API");
                                srv.pm.reload_lists().await;
                                Ok::<_, Infallible>(Response::new(Body::from("Lists reloaded")))
                            },
                            (&hyper::Method::GET, "/health") => {
                                Ok::<_, Infallible>(Response::new(Body::from("OK")))
                            },
                            _ => Ok::<_, Infallible>(Response::builder()
                                .status(404)
                                .body(Body::from("Not Found"))
                                .unwrap()),
                        }
                    }
                }))
            }
        });

        info!("Admin server listening on {}", addr);
        let server = Server::bind(&addr).serve(make_svc);
        server.await?;
        Ok(())
    }
}

fn check_auth(req: &Request<Body>, expected: &str) -> bool {
    // If auth is disabled or default?
    // User asked for setup via config.
    if let Some(val) = req.headers().get("Authorization") {
        if let Ok(v) = val.to_str() {
            return v == expected;
        }
    }
    false
}
