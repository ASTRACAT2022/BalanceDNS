use std::sync::Arc;
use tokio::signal;
use log::{info, error};

mod config;
mod metrics;
mod cache;
mod resolver;
mod plugins;
mod admin;
mod server;
mod protection;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    info!("Booting up ASTRACAT Resolver (Rust Port)...");

    // Load configuration
    // Load configuration
    let config_paths = vec![
        "/etc/astracat-dns/config.yaml",
        "config.yaml",
        "/usr/local/etc/astracat-dns/config.yaml",
    ];

    let mut cfg = config::Config::default();
    let mut config_loaded = false;

    for path in config_paths {
        match config::Config::load(path) {
            Ok(c) => {
                info!("Loaded configuration from {}", path);
                cfg = c;
                config_loaded = true;
                break;
            }
            Err(e) => {
                log::warn!("Failed to load configuration from {}: {}", path, e);
            }
        }
    }

    if !config_loaded {
        error!("Could not load configuration from any standard location. Using defaults.");
    }

    // Initialize metrics
    let metrics = Arc::new(metrics::Metrics::new(&cfg.metrics_storage_path));

    // Initialize cache
    let cache = Arc::new(cache::Cache::new(
        cfg.cache.size,
        &cfg.cache.lmdb_path,
        metrics.clone(),
    )?);

    // Initialize plugin manager
    let mut pm = plugins::PluginManager::new();

    // Register Hosts plugin
    if cfg.hosts.enabled {
        let hosts_plugin = plugins::HostsPlugin::new(&cfg.hosts.path);
        pm.register(Box::new(hosts_plugin));
    }

    // Register AdBlock plugin
    if cfg.adblock.enabled {
        let adblock_plugin = plugins::AdBlockPlugin::new(cfg.adblock.blocklist_urls.clone());
        pm.register(Box::new(adblock_plugin));
    }

    let pm = Arc::new(pm);

    // Create resolver
    let res = resolver::create_resolver(&cfg.resolver.resolver_type, &cfg, cache.clone(), metrics.clone()).await?;
    let res = Arc::new(res);

    // Start metrics collectors
    metrics.clone().start_collectors();

    // Start admin server
    if !cfg.admin_addr.is_empty() {
         let admin_server = admin::AdminServer::new(&cfg.admin_addr, metrics.clone(), pm.clone(), cfg.admin.clone(), res.clone());
         tokio::spawn(async move {
             if let Err(e) = admin_server.start().await {
                 error!("Admin server error: {}", e);
             }
         });
    }

    // Initialize Protection
    let protection = Arc::new(protection::Protection::new(
        cfg.rate_limit.enabled,
        cfg.rate_limit.qps,
        cfg.rate_limit.burst,
    ));

    // Create and start DNS server
    let server = server::Server::new(cfg.clone(), metrics.clone(), res.clone(), pm.clone(), protection);

    // We don't want to lose the server task
    tokio::spawn(async move {
        if let Err(e) = server.listen_and_serve().await {
             error!("DNS server error: {}", e);
        }
    });

    // Graceful shutdown
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("Shutting down...");
            if let Err(e) = metrics.save_historical_data(&cfg.metrics_storage_path).await {
                error!("Failed to save metrics: {}", e);
            }
        },
        Err(err) => {
            error!("Unable to listen for shutdown signal: {}", err);
        },
    }

    Ok(())
}
