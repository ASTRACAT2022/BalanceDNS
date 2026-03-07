# Optimized ASTRACAT DNS Resolver

This is a high-performance recursive DNS resolver built with Go, optimized for production use with maximum speed, minimal resource consumption, and stable operation under high loads.

## Key Optimizations

### Performance Improvements
- **Selectable Resolver Backend**: Choose built-in Go recursor or `miekg/unbound` (`resolver_type`)
- **Memory Optimization**: Implemented request/response object pooling to reduce GC pressure
- **Connection Reuse**: Optimized UDP/TCP connection handling with proper reuse
- **Sharded Cache**: Improved cache with better concurrency and reduced lock contention
- **Background Operations**: Asynchronous cache writes and revalidations

### Caching Strategy
- **SLRU Cache**: Segmented LRU cache with probation and protected segments
- **Stale-While-Revalidate**: Serving stale content while revalidating in background
- **Persistent Cache**: LMDB-backed persistent storage for cache data
- **Cache Prefetching**: Proactive caching of related records

### Resilience Features
- **Rate Limiting**: Per-IP token bucket rate limiting
- **Circuit Breakers**: Prevents cascading failures
- **Retry Logic**: Intelligent retry mechanisms with exponential backoff
- **Error Handling**: Comprehensive error handling and recovery

### Monitoring & Metrics
- **Prometheus Integration**: Full metrics export for monitoring
- **Performance Metrics**: QPS, latency, cache hit rates, etc.
- **Health Checks**: Built-in health check endpoint
- **Dashboard**: JSON metrics endpoint for dashboards

## Configuration

The resolver can be configured via the config package. Key settings:
- Listen address: `0.0.0.0:5053` (DNS), `0.0.0.0:9090` (metrics)
- Cache size: 10,000 entries
- Worker pool: 50 concurrent workers
- Rate limiting: 100 requests/second per IP (burst 200)

## Deployment

### Docker
```bash
# Build the image
docker build -t astracat-dns-resolver .

# Run with default settings
docker run -d -p 53:53/udp -p 53:53/tcp -p 9090:9090/tcp --name dns-resolver astracat-dns-resolver
```

### Direct Execution
```bash
# Build
go build -o dns-resolver

# Run
./dns-resolver
```

## Production Recommendations

1. **Resource Allocation**:
   - CPU: 2-4 cores recommended for high loads
   - Memory: 512MB-2GB depending on cache size
   - Disk: SSD recommended for cache persistence

2. **Monitoring**:
   - Monitor metrics at `http://localhost:9090/metrics`
   - Check dashboard at `http://localhost:9090/dashboard`
   - Health check at `http://localhost:9090/health`

3. **Security**:
   - Use rate limiting to prevent abuse
   - Run in isolated network environment
   - Consider using iptables for additional protection

## Performance Tuning

For high-load environments:
- Increase `MaxWorkers` in config
- Adjust cache sizes based on available memory
- Tune rate limiting parameters
- Enable `reuse_port: true` and `reuse_addr: true` (Linux)
- Set `metrics_top_domains_enabled: false` to reduce per-request metrics overhead under extreme QPS
- Monitor with the included performance testing tool

Example high-load snippet:

```yaml
resolver_workers: 0
max_global_inflight: 65536
max_qps_per_ip: 0
max_concurrent_per_ip: 0
reuse_port: true
reuse_addr: true
metrics_top_domains_enabled: false
recursor_cache_entries: 1000000
cache_ram_size: 512
```

## Safe Update Command (Keep Current Prod Config)

If `auto_install.sh` was used, run:

```bash
sudo astracat-deploy
```

The deploy helper now:
- backs up current `config.yaml` and binary;
- restores existing production config after code sync;
- rolls back binary/config automatically if restart fails.

## Testing

Run the performance test:
```bash
go run performance_test.go
```

This will test concurrent query handling, latency, and cache efficiency.
