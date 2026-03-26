use std::{net::SocketAddr, time::Duration};

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time,
};

pub struct MetricsServer {
    listen: SocketAddr,
    handle: PrometheusHandle,
}

impl MetricsServer {
    pub fn new(listen: SocketAddr) -> Self {
        let builder = PrometheusBuilder::new();
        let handle = builder
            .install_recorder()
            .expect("prometheus recorder already installed");

        Self { listen, handle }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.listen).await?;
        loop {
            let (stream, peer) = listener.accept().await?;
            let handle = self.handle.clone();
            tokio::spawn(async move {
                if let Err(err) = serve_conn(stream, handle).await {
                    tracing::debug!(peer = %peer, error = %err, "metrics connection failed");
                }
            });
        }
    }
}

async fn serve_conn(mut stream: TcpStream, handle: PrometheusHandle) -> anyhow::Result<()> {
    let mut buf = [0u8; 8192];
    let n = time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
    if n == 0 {
        return Ok(());
    }

    let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
    let first_line = req.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    if method == "GET" && path == "/metrics" {
        let body = handle.render();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    stream
        .write_all(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await?;
    Ok(())
}

