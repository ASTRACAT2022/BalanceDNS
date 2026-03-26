use std::{path::PathBuf, sync::Arc, time::Duration};

use tokio::signal;
use tracing::Level;

use crate::{
    config::AppConfig,
    blocklist_remote::BlocklistRemote,
    hosts_remote::HostsRemote,
    incoming::{DohServer, DotServer},
    metrics_http::MetricsServer,
    proxy::{TcpProxy, UdpProxy},
    tls,
    upstream::{Balancer, UpstreamSet},
};

pub async fn run() -> anyhow::Result<()> {
    init_tracing();
    tls::ensure_rustls_crypto_provider();

    let config_path = parse_config_path();
    let config = AppConfig::load(&config_path)?;

    let upstreams = Arc::new(UpstreamSet::new(config.upstreams.clone())?);
    let balancer = Arc::new(Balancer::new(config.balancing.algorithm));

    let hosts = match config.hosts_remote.clone() {
        Some(cfg) => {
            let hr = Arc::new(HostsRemote::new(cfg)?);
            let bg = hr.clone();
            tokio::spawn(async move {
                bg.start().await;
            });
            Some(hr)
        }
        None => None,
    };

    let blocklist = match config.blocklist_remote.clone() {
        Some(cfg) => {
            let bl = Arc::new(BlocklistRemote::new(cfg)?);
            let bg = bl.clone();
            tokio::spawn(async move {
                bg.start().await;
            });
            Some(bl)
        }
        None => None,
    };

    let udp_proxy = UdpProxy::new(
        config.server.udp_listen,
        upstreams.clone(),
        balancer.clone(),
        config.security.clone(),
        hosts.clone(),
        blocklist.clone(),
    )
    .await?;

    let tcp_proxy = TcpProxy::new(
        config.server.tcp_listen,
        upstreams.clone(),
        balancer.clone(),
        config.security.clone(),
        hosts.clone(),
        blocklist.clone(),
    )
    .await?;

    let metrics = MetricsServer::new(config.metrics.listen);

    let dot = DotServer::new(
        config.server.dot_listen,
        config.tls.clone(),
        upstreams.clone(),
        balancer.clone(),
        config.security.clone(),
        hosts.clone(),
        blocklist.clone(),
    )
    .await?;
    let doh = DohServer::new(
        config.server.doh_listen,
        config.tls.clone(),
        upstreams.clone(),
        balancer.clone(),
        config.security.clone(),
        hosts.clone(),
        blocklist.clone(),
    )
    .await?;

    tracing::info!(
        udp_listen = %config.server.udp_listen,
        tcp_listen = %config.server.tcp_listen,
        dot_listen = %config.server.dot_listen,
        doh_listen = %config.server.doh_listen,
        metrics_listen = %config.metrics.listen,
        "balanceDNSt started"
    );

    tokio::spawn(async move {
        if let Err(err) = udp_proxy.run().await {
            tracing::error!(error = %err, "udp proxy stopped");
        }
    });

    tokio::spawn(async move {
        if let Err(err) = tcp_proxy.run().await {
            tracing::error!(error = %err, "tcp proxy stopped");
        }
    });

    tokio::spawn(async move {
        if let Err(err) = metrics.run().await {
            tracing::error!(error = %err, "metrics server stopped");
        }
    });

    tokio::spawn(async move {
        if let Err(err) = dot.run().await {
            tracing::error!(error = %err, "dot server stopped");
        }
    });

    tokio::spawn(async move {
        if let Err(err) = doh.run().await {
            tracing::error!(error = %err, "doh server stopped");
        }
    });

    tokio::select! {
        _ = signal::ctrl_c() => {
            tracing::info!("shutdown: ctrl-c");
        }
        _ = upstreams.healthcheck_loop(Duration::from_secs(2)) => {
            tracing::warn!("healthcheck loop terminated");
        }
    }

    Ok(())
}

fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_max_level(Level::INFO)
        .json()
        .init();
}

fn parse_config_path() -> PathBuf {
    let mut args = std::env::args().skip(1);
    match args.next() {
        Some(flag) if flag == "--config" => args
            .next()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("config/config.toml")),
        Some(path) => PathBuf::from(path),
        None => PathBuf::from("config/config.toml"),
    }
}
