use std::sync::Arc;
use crate::metrics::Metrics;
use crate::plugins::PluginManager;
use crate::config::AdminConfig;
use crate::resolver::Resolver;
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
    resolver: Arc<Box<dyn Resolver>>,
}

impl AdminServer {
    pub fn new(addr: &str, metrics: Arc<Metrics>, pm: Arc<PluginManager>, config: AdminConfig, resolver: Arc<Box<dyn Resolver>>) -> Self {
        AdminServer {
            addr: addr.to_string(),
            metrics,
            pm,
            config,
            resolver,
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
                        let path = req.uri().path().to_string();
                        let query = req.uri().query().unwrap_or("");
                        
                        // Public endpoint - no auth required
                        if path == "/api/resolve" {
                            return handle_resolve(srv.clone(), query).await;
                        }
                        
                        // Check Auth for protected endpoints
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

async fn handle_resolve(srv: Arc<AdminServer>, query: &str) -> Result<Response<Body>, Infallible> {
    // Parse query parameters: name=domain&type=A
    let mut name = "";
    let mut qtype = "A";
    
    for param in query.split('&') {
        let parts: Vec<&str> = param.split('=').collect();
        if parts.len() == 2 {
            match parts[0] {
                "name" => name = parts[1],
                "type" => qtype = parts[1],
                _ => {}
            }
        }
    }
    
    if name.is_empty() {
        return Ok(Response::builder()
            .status(400)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"error":"Missing 'name' parameter"}"#))
            .unwrap());
    }
    
    // Convert type string to u16
    let qtype_num = match qtype {
        "A" => 1,
        "AAAA" => 28,
        "CNAME" => 5,
        "MX" => 15,
        "TXT" => 16,
        "NS" => 2,
        _ => 1, // default to A
    };
    
    // Perform resolution
    match srv.resolver.resolve(name, qtype_num).await {
        Ok(msg) => {
            // Extract IP addresses from answers
            let mut ips = Vec::new();
            for answer in msg.answers() {
                if let Some(rdata) = answer.data() {
                    ips.push(
rdata.to_string());
                }
            }
            
            let json = serde_json::json!({
                "name": name,
                "type": qtype,
                "answers": ips,
                "status": msg.response_code().to_string()
            });
            
            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .header("Access-Control-Allow-Origin", "*")
                .body(Body::from(json.to_string()))
                .unwrap())
        }
        Err(e) => {
            Ok(Response::builder()
                .status(500)
                .header("Content-Type", "application/json")
                .body(Body::from(format!(r#"{{"error":"{}"}}"#, e)))
                .unwrap())
        }
    }
}
