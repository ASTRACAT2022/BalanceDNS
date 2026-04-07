use reqwest::blocking::Client;
use std::fs;
use std::io;
use std::path::Path;
use std::process;
use std::time::Duration as StdDuration;

#[derive(Clone, Copy, Debug)]
pub enum RemoteRefreshKind {
    Hosts,
    Blocklist,
}

impl RemoteRefreshKind {
    pub fn as_arg(self) -> &'static str {
        match self {
            RemoteRefreshKind::Hosts => "hosts",
            RemoteRefreshKind::Blocklist => "blocklist",
        }
    }

    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "hosts" => Ok(RemoteRefreshKind::Hosts),
            "blocklist" => Ok(RemoteRefreshKind::Blocklist),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsupported remote refresh kind: {}", value),
            )),
        }
    }
}

pub fn run_remote_refresh_helper(
    kind: RemoteRefreshKind,
    url: &str,
    output_path: &str,
    timeout_ms: u64,
) -> io::Result<()> {
    let client = Client::builder()
        .timeout(StdDuration::from_millis(timeout_ms.max(1)))
        .build()
        .map_err(|err| io::Error::other(err.to_string()))?;
    let body = fetch_text(&client, url)?;
    write_snapshot_atomic(output_path, &body)?;
    info!(
        "Remote {:?} helper wrote {} bytes to {}",
        kind,
        body.len(),
        output_path
    );
    Ok(())
}

pub fn fetch_text(client: &Client, url: &str) -> io::Result<String> {
    client
        .get(url)
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|err| io::Error::other(err.to_string()))?
        .text()
        .map_err(|err| io::Error::other(err.to_string()))
}

fn write_snapshot_atomic(output_path: &str, body: &str) -> io::Result<()> {
    let output_path = Path::new(output_path);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp_name = format!(
        ".{}.{}.tmp",
        output_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("balancedns-remote"),
        process::id()
    );
    let temp_path = output_path.with_file_name(temp_name);
    fs::write(&temp_path, body.as_bytes())?;
    fs::rename(&temp_path, output_path)?;
    Ok(())
}
