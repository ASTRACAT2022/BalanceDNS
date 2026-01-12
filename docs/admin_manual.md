# AstracatDNS Administrator Manual

## Admin Panel
AstracatDNS comes with a built-in web-based Admin Panel for real-time monitoring and configuration.

**Default URL**: `http://localhost:8080` (or the configured IP:Port)

### Dashboard
The dashboard provides a real-time overview of the system's health and performance:
- **QPS (Queries Per Second)**: Current load on the resolver.
- **Cache Hit Rate**: Efficiency of the caching mechanism.
- **System Resources**: CPU and Memory usage visualization.
- **Charts**: Traffic analysis over time.
- **Top Tables**: Most blocked domains, high latency domains, and query types.

### Plugin Management

#### AdBlock Manager
- **Status**: View active blocklists.
- **Add Blocklist**: Enter a URL to a standard hosts format blocklist (e.g., from StevenBlack/hosts) to subscribe to it.
- **Remove**: Unsubscribe from a blocklist.
- **Update**: Manually trigger a parallel update of all blocklists.

#### Hosts Editor
- **Direct Edit**: Edit the local `hosts` file content directly from the browser.
- **Reload**: Apply changes immediately without restarting the server.
- **Syntax**: Standard hosts format: `IP_ADDRESS HOSTNAME [ALIASES...]`
  ```
  127.0.0.1 localhost
  192.168.1.10 my-server.local
  ```

## Troubleshooting

### High Memory Usage
- Check the **Cache Misses** on the dashboard. If high, the cache might be filling up with unique queries.
- The cache uses a **Lazy Loading** strategy with LMDB. It only loads frequent items into RAM. Verify disk I/O if performance drops.

### Blocklists Not Updating
- Check the **System Logs** (stdout/stderr) for HTTP errors.
- Ensure the server has internet access.
- The update process uses a 10-second timeout per list to prevent hanging.

### "Address already in use" Error
- Ensure no other DNS resolver (like `systemd-resolved` or `dnsmasq`) is running on port 53.
- Use `sudo lsof -i :53` to identify conflicting processes.

### ODoH Verification
- The server exposes ODoH configs at `https://<your-domain>/odohconfigs`.
- You can verify this using `curl -v https://<your-domain>/odohconfigs`.
- Ensure your TLS certificates are valid and trusted by the client.

## Security Best Practices
1. **Change Default Password**: Immediately change the admin password via the Admin Panel ("Quick Actions" -> "Admin").
2. **Firewall**: Restrict access to the Admin Panel port (8080) to trusted IP addresses only.
3. **HTTPS**: The current version runs on HTTP. For remote access, use a reverse proxy (like Nginx or Caddy) with TLS termination.
