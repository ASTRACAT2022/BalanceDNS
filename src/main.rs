use std::sync::{Arc, RwLock};
use tokio::signal;
use log::{info, error};

mod config;
mod metrics;
mod cache;
mod resolver;
mod plugins;
mod admin;
mod server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    info!("Booting up ASTRACAT Resolver (Rust Port)...");

    // Load configuration
    let cfg = match config::Config::load("config.yaml") {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config.yaml: {}, using defaults", e);
            config::Config::default()
        }
    };

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

    // Start admin server
    if !cfg.admin_addr.is_empty() {
         let admin_server = admin::AdminServer::new(&cfg.admin_addr, metrics.clone(), pm.clone());
         tokio::spawn(async move {
             if let Err(e) = admin_server.start().await {
                 error!("Admin server error: {}", e);
             }
         });
    }

    // Create and start DNS server
    let server = server::Server::new(cfg.clone(), metrics.clone(), res.clone(), pm.clone());

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
