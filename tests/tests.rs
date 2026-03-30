extern crate libbalancedns;

#[cfg(test)]
mod test {
    use libbalancedns::{Config, UpstreamProtocol};

    #[test]
    fn parse_balancedns_config() {
        let cfg = r#"
[server]
udp_listen = "0.0.0.0:5353"
tcp_listen = "0.0.0.0:5353"
dot_listen = "0.0.0.0:8853"
doh_listen = "0.0.0.0:8443"

[tls]
cert_pem = "tls/server.crt"
key_pem = "tls/server.key"

[balancing]
algorithm = "round_robin"

[security]
deny_any = true
deny_dnskey = true
request_timeout_ms = 3000

[cache]
enabled = true
max_size = 20000
ttl_seconds = 600
stale_refresh_enabled = true
stale_ttl_seconds = 30

[metrics]
listen = "127.0.0.1:9100"

[hosts_local]
"example.com." = "1.2.3.4"

[hosts_remote]
url = " https://example.com/hosts "
refresh_seconds = 300
ttl_seconds = 60

[blocklist_remote]
url = " https://example.com/blocklist "
refresh_seconds = 300

[plugins]
libraries = ["plugins/libsample.dylib"]

[[upstreams]]
name = "cloudflare-doh"
proto = "doh"
url = " https://1.1.1.1/dns-query "
pool = "default"
weight = 5

[[upstreams]]
name = "cloudflare-udp"
proto = "udp"
addr = "1.1.1.1:53"
pool = "default"
weight = 1

[[routing_rules]]
suffix = ".ru."
upstreams = ["cloudflare-udp"]
"#;

        let config = Config::from_string(cfg).unwrap();
        assert_eq!(config.udp_listen_addr.as_deref(), Some("0.0.0.0:5353"));
        assert_eq!(config.tcp_listen_addr.as_deref(), Some("0.0.0.0:5353"));
        assert_eq!(config.dot_listen_addr.as_deref(), Some("0.0.0.0:8853"));
        assert_eq!(config.doh_listen_addr.as_deref(), Some("0.0.0.0:8443"));
        assert_eq!(config.tls_cert_pem.as_deref(), Some("tls/server.crt"));
        assert_eq!(config.tls_key_pem.as_deref(), Some("tls/server.key"));
        assert_eq!(config.balancing_algorithm, "round_robin");
        assert!(config.deny_any);
        assert!(config.deny_dnskey);
        assert!(config.cache_enabled);
        assert_eq!(config.cache_size, 20_000);
        assert_eq!(config.cache_ttl_seconds, 600);
        assert!(config.stale_refresh_enabled);
        assert_eq!(config.stale_ttl_seconds, 30);
        assert_eq!(config.webservice_listen_addr, "127.0.0.1:9100");
        assert_eq!(config.hosts_local.get("example.com.").unwrap(), "1.2.3.4");
        assert_eq!(
            config.hosts_remote.as_ref().unwrap().url,
            "https://example.com/hosts"
        );
        assert_eq!(
            config.blocklist_remote.as_ref().unwrap().url,
            "https://example.com/blocklist"
        );
        assert_eq!(config.plugin_libraries.len(), 1);
        assert_eq!(config.upstreams.len(), 2);
        assert_eq!(config.upstreams[0].proto, UpstreamProtocol::Doh);
        assert_eq!(
            config.upstreams[0].url.as_deref(),
            Some("https://1.1.1.1/dns-query")
        );
        assert_eq!(config.upstreams[1].proto, UpstreamProtocol::Udp);
        assert_eq!(config.upstreams[1].addr.as_deref(), Some("1.1.1.1:53"));
        assert_eq!(config.routing_rules.len(), 1);
        assert_eq!(config.routing_rules[0].suffix, ".ru.");
        assert_eq!(config.routing_rules[0].upstreams, vec!["cloudflare-udp"]);
    }

    #[test]
    fn parse_legacy_config() {
        let cfg = r#"
[upstream]
type = "resolver"
servers = ["127.0.0.1:53"]
strategy = "fallback"
max_failure_duration = 2500

[network]
listen = "127.0.0.1:5353"
udp_ports = 1

[cache]
max_items = 100
min_ttl = 60
max_ttl = 300

[global]
threads_udp = 1
threads_tcp = 1
"#;

        let config = Config::from_string(cfg).unwrap();
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.upstreams[0].proto, UpstreamProtocol::Udp);
        assert_eq!(config.upstreams[0].addr.as_deref(), Some("127.0.0.1:53"));
        assert_eq!(config.listen_addr, "127.0.0.1:5353");
        assert_eq!(config.cache_size, 100);
        assert_eq!(config.max_ttl, 300);
    }

    #[test]
    fn balancedns_timeout_defaults_to_1500ms() {
        let cfg = r#"
[server]
udp_listen = "127.0.0.1:5353"

[[upstreams]]
name = "cloudflare-udp"
proto = "udp"
addr = "1.1.1.1:53"
pool = "default"
weight = 1
"#;

        let config = Config::from_string(cfg).unwrap();
        assert_eq!(config.request_timeout_ms, 1500);
        assert!(!config.stale_refresh_enabled);
        assert_eq!(config.stale_ttl_seconds, 30);
    }
}
