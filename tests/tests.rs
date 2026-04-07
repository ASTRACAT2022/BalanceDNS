extern crate libbalancedns;

#[cfg(test)]
mod test {
    use libbalancedns::{dns, Config, UpstreamProtocol};
    use std::io::Write;
    use tempfile::Builder;

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

[lua]
scripts = [" lua/query_logger.lua "]

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

[global]
threads_udp = 6
threads_tcp = 4
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
        assert_eq!(config.lua_scripts, vec!["lua/query_logger.lua"]);
        assert_eq!(config.lua_components.len(), 1);
        assert_eq!(config.lua_components[0].path, "lua/query_logger.lua");
        assert_eq!(config.lua_sandbox.max_packet_bytes, 4096);
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
        assert_eq!(config.udp_acceptor_threads, 6);
        assert_eq!(config.tcp_acceptor_threads, 4);
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

    #[test]
    fn balancedns_rejects_unknown_routing_upstream() {
        let cfg = r#"
[server]
udp_listen = "127.0.0.1:5353"

[[upstreams]]
name = "cloudflare-udp"
proto = "udp"
addr = "1.1.1.1:53"
pool = "default"
weight = 1

[[routing_rules]]
suffix = ".ru."
upstreams = ["missing-upstream"]
"#;

        let err = Config::from_string(cfg).unwrap_err();
        assert!(err
            .to_string()
            .contains("references unknown upstream [missing-upstream]"));
    }

    #[test]
    fn balancedns_rejects_zero_refresh_interval() {
        let cfg = r#"
[server]
udp_listen = "127.0.0.1:5353"

[hosts_remote]
url = "https://example.com/hosts"
refresh_seconds = 0
ttl_seconds = 60

[[upstreams]]
name = "cloudflare-udp"
proto = "udp"
addr = "1.1.1.1:53"
pool = "default"
weight = 1
"#;

        let err = Config::from_string(cfg).unwrap_err();
        assert!(err
            .to_string()
            .contains("hosts_remote.refresh_seconds must be greater than 0"));
    }

    #[test]
    fn parse_structured_lua_config() {
        let cfg = r#"
[server]
udp_listen = "127.0.0.1:5353"

[lua]
scripts = ["lua/default.lua"]

[lua.settings]
mode = "observe"
sample_rate = 5

[lua.sandbox]
max_packet_bytes = 2048
disable_after_failures = 3
init_instruction_limit = 123456
hook_instruction_limit = 654321

[[lua.components]]
path = "lua/filter.lua"
enabled = true

[lua.components.settings]
mode = "block"
reply_code = 3
tags = ["ads", "telemetry"]

[[lua.components]]
path = "lua/off.lua"
enabled = false

[[upstreams]]
name = "cloudflare-udp"
proto = "udp"
addr = "1.1.1.1:53"
pool = "default"
weight = 1
"#;

        let config = Config::from_string(cfg).unwrap();
        assert_eq!(
            config.lua_scripts,
            vec!["lua/default.lua", "lua/filter.lua"]
        );
        assert_eq!(config.lua_components.len(), 3);
        assert_eq!(config.lua_sandbox.max_packet_bytes, 2048);
        assert_eq!(config.lua_sandbox.disable_after_failures, 3);
        assert_eq!(config.lua_sandbox.init_instruction_limit, 123456);
        assert_eq!(config.lua_sandbox.hook_instruction_limit, 654321);

        let default_component = config
            .lua_components
            .iter()
            .find(|component| component.path == "lua/default.lua")
            .unwrap();
        let default_settings = default_component.settings.as_table().unwrap();
        assert_eq!(
            default_settings
                .get("mode")
                .and_then(|value| value.as_str()),
            Some("observe")
        );
        assert_eq!(
            default_settings
                .get("sample_rate")
                .and_then(|value| value.as_integer()),
            Some(5)
        );

        let filter_component = config
            .lua_components
            .iter()
            .find(|component| component.path == "lua/filter.lua")
            .unwrap();
        let filter_settings = filter_component.settings.as_table().unwrap();
        assert_eq!(
            filter_settings.get("mode").and_then(|value| value.as_str()),
            Some("block")
        );
        assert_eq!(
            filter_settings
                .get("reply_code")
                .and_then(|value| value.as_integer()),
            Some(3)
        );
        assert_eq!(
            filter_settings
                .get("tags")
                .and_then(|value| value.as_array())
                .map(|items| items.len()),
            Some(2)
        );

        let disabled_component = config
            .lua_components
            .iter()
            .find(|component| component.path == "lua/off.lua")
            .unwrap();
        assert!(!disabled_component.enabled);
    }

    #[test]
    fn parse_balancedns_lua_config() {
        let cfg = r#"
local edge_ip = "0.0.0.0"

return {
    server = {
        udp_listen = edge_ip .. ":5353",
        tcp_listen = edge_ip .. ":5353",
        dot_listen = edge_ip .. ":8853",
        doh_listen = edge_ip .. ":8443",
    },
    tls = {
        cert_pem = "tls/server.crt",
        key_pem = "tls/server.key",
    },
    balancing = {
        algorithm = "round_robin",
    },
    security = {
        deny_any = true,
        deny_dnskey = true,
        request_timeout_ms = 3000,
    },
    cache = {
        enabled = true,
        max_size = 20000,
        ttl_seconds = 600,
        stale_refresh_enabled = true,
        stale_ttl_seconds = 30,
    },
    metrics = {
        listen = "127.0.0.1:9100",
    },
    hosts_local = {
        ["example.com."] = "1.2.3.4",
    },
    plugins = {
        libraries = { "plugins/libsample.dylib" },
    },
    lua = {
        settings = {
            mode = "observe",
            sample_rate = 10,
        },
        sandbox = {
            max_packet_bytes = 2048,
            disable_after_failures = 4,
            init_instruction_limit = 111111,
            hook_instruction_limit = 222222,
        },
        components = {
            {
                path = "lua/default.lua",
                enabled = true,
            },
            {
                path = "lua/filter.lua",
                enabled = true,
                settings = {
                    mode = "block",
                    reply_code = 3,
                    tags = { "ads", "telemetry" },
                },
            },
        },
    },
    upstreams = {
        {
            name = "cloudflare-doh",
            proto = "doh",
            url = "https://1.1.1.1/dns-query",
            pool = "default",
            weight = 5,
        },
        {
            name = "cloudflare-udp",
            proto = "udp",
            addr = "1.1.1.1:53",
            pool = "default",
            weight = 1,
        },
    },
    routing_rules = {
        {
            suffix = ".ru.",
            upstreams = { "cloudflare-udp" },
        },
    },
    global = {
        threads_udp = 6,
        threads_tcp = 4,
    },
}
"#;

        let config = match Config::from_lua_string(cfg) {
            Ok(config) => config,
            Err(err)
                if err.kind() == std::io::ErrorKind::NotFound
                    && err.to_string().contains("Lua shared library") =>
            {
                eprintln!("Skipping Lua config test: {}", err);
                return;
            }
            Err(err) => panic!("Lua config parse failed: {}", err),
        };

        assert_eq!(config.udp_listen_addr.as_deref(), Some("0.0.0.0:5353"));
        assert_eq!(config.dot_listen_addr.as_deref(), Some("0.0.0.0:8853"));
        assert_eq!(
            config.lua_scripts,
            vec!["lua/default.lua", "lua/filter.lua"]
        );
        assert_eq!(config.lua_sandbox.max_packet_bytes, 2048);
        assert_eq!(config.lua_sandbox.disable_after_failures, 4);
        assert_eq!(config.lua_sandbox.init_instruction_limit, 111111);
        assert_eq!(config.lua_sandbox.hook_instruction_limit, 222222);
        assert_eq!(config.hosts_local.get("example.com.").unwrap(), "1.2.3.4");
        assert_eq!(config.upstreams[0].proto, UpstreamProtocol::Doh);
        assert_eq!(config.upstreams[1].proto, UpstreamProtocol::Udp);
        assert_eq!(config.routing_rules[0].suffix, ".ru.");

        let filter_component = config
            .lua_components
            .iter()
            .find(|component| component.path == "lua/filter.lua")
            .unwrap();
        let settings = filter_component.settings.as_table().unwrap();
        assert_eq!(
            settings.get("mode").and_then(|value| value.as_str()),
            Some("block")
        );
        assert_eq!(
            settings
                .get("reply_code")
                .and_then(|value| value.as_integer()),
            Some(3)
        );
    }

    #[test]
    fn from_path_detects_lua_config_extension() {
        let cfg = r#"
return {
    server = {
        udp_listen = "0.0.0.0:5353",
    },
    tls = {
        cert_pem = "tls/server.crt",
        key_pem = "tls/server.key",
    },
    upstreams = {
        {
            name = "cloudflare-udp",
            proto = "udp",
            addr = "1.1.1.1:53",
            pool = "default",
            weight = 1,
        },
    },
}
"#;

        let mut file = Builder::new().suffix(".lua").tempfile().unwrap();
        write!(file, "{}", cfg).unwrap();

        let config = match Config::from_path(file.path()) {
            Ok(config) => config,
            Err(err)
                if err.kind() == std::io::ErrorKind::NotFound
                    && err.to_string().contains("Lua shared library") =>
            {
                eprintln!("Skipping Lua config path test: {}", err);
                return;
            }
            Err(err) => panic!("Lua config path parse failed: {}", err),
        };

        assert_eq!(config.udp_listen_addr.as_deref(), Some("0.0.0.0:5353"));
        assert_eq!(config.upstreams.len(), 1);
    }

    #[test]
    fn parse_balancedns_lua_config_accepts_empty_arrays() {
        let cfg = r#"
return {
    server = {
        udp_listen = "0.0.0.0:5353",
    },
    tls = {
        cert_pem = "tls/server.crt",
        key_pem = "tls/server.key",
    },
    plugins = {
        libraries = {},
    },
    lua = {
        scripts = {},
        components = {},
    },
    upstreams = {
        {
            name = "cloudflare-udp",
            proto = "udp",
            addr = "1.1.1.1:53",
            pool = "default",
            weight = 1,
        },
    },
}
"#;

        let config = match Config::from_lua_string(cfg) {
            Ok(config) => config,
            Err(err)
                if err.kind() == std::io::ErrorKind::NotFound
                    && err.to_string().contains("Lua shared library") =>
            {
                eprintln!("Skipping Lua empty-array test: {}", err);
                return;
            }
            Err(err) => panic!("Lua config parse failed: {}", err),
        };

        assert!(config.plugin_libraries.is_empty());
        assert!(config.lua_scripts.is_empty());
        assert!(config.lua_components.is_empty());
        assert_eq!(config.upstreams.len(), 1);
    }

    #[test]
    fn balancedns_requires_tls_files_for_dot_or_doh() {
        let cfg = r#"
[server]
dot_listen = "127.0.0.1:8853"

[[upstreams]]
name = "cloudflare-udp"
proto = "udp"
addr = "1.1.1.1:53"
pool = "default"
weight = 1
"#;

        let err = Config::from_string(cfg).unwrap_err();
        assert!(err.to_string().contains("tls.cert_pem is required"));
    }

    #[test]
    fn dns_helpers_reject_malformed_question_without_panicking() {
        let packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let question_result = std::panic::catch_unwind(|| dns::question(&packet));
        let min_ttl_result = std::panic::catch_unwind(|| dns::min_ttl(&packet, 0, 60, 30));
        let set_ttl_result = std::panic::catch_unwind(|| {
            let mut packet = packet.clone();
            dns::set_ttl(&mut packet, 30)
        });

        assert!(question_result.is_ok());
        assert!(min_ttl_result.is_ok());
        assert!(set_ttl_result.is_ok());
        assert!(question_result.unwrap().is_err());
        assert!(min_ttl_result.unwrap().is_err());
        assert!(set_ttl_result.unwrap().is_err());
    }
}
