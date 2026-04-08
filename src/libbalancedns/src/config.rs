use crate::lua_config::load_lua_config_value;
use coarsetime::Duration;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::{Error, ErrorKind, Read};
use std::net::SocketAddr;
use std::path::Path;
use toml::{self, Value};
use url::Url;

type TomlTable = toml::value::Table;

#[derive(Clone, Copy, Debug)]
pub enum LoadBalancingMode {
    Fallback,
    Uniform,
    P2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolverMode {
    Forward,
    Recursive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpstreamProtocol {
    Udp,
    Doh,
}

#[derive(Clone, Debug)]
pub struct UpstreamConfig {
    pub name: String,
    pub proto: UpstreamProtocol,
    pub addr: Option<String>,
    pub url: Option<String>,
    pub pool: String,
    pub weight: usize,
}

#[derive(Clone, Debug)]
pub struct RemoteHostsConfig {
    pub url: String,
    pub refresh_seconds: u64,
    pub ttl_seconds: u32,
}

#[derive(Clone, Debug)]
pub struct RemoteBlocklistConfig {
    pub url: String,
    pub refresh_seconds: u64,
}

#[derive(Clone, Debug)]
pub struct RoutingRuleConfig {
    pub suffix: String,
    pub upstreams: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct LuaSandboxConfig {
    pub max_packet_bytes: usize,
    pub disable_after_failures: usize,
    pub init_instruction_limit: u32,
    pub hook_instruction_limit: u32,
}

#[derive(Clone, Debug)]
pub struct LuaComponentConfig {
    pub path: String,
    pub enabled: bool,
    pub settings: Value,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub decrement_ttl: bool,
    pub upstream_servers: Vec<String>,
    pub upstreams: Vec<UpstreamConfig>,
    pub lbmode: LoadBalancingMode,
    pub balancing_algorithm: String,
    pub resolver_mode: ResolverMode,
    pub upstream_max_failure_duration: Duration,
    pub cache_enabled: bool,
    pub cache_size: usize,
    pub cache_ttl_seconds: u32,
    pub stale_refresh_enabled: bool,
    pub stale_ttl_seconds: u32,
    pub udp_ports: u16,
    pub listen_addr: String,
    pub udp_listen_addr: Option<String>,
    pub tcp_listen_addr: Option<String>,
    pub dot_listen_addr: Option<String>,
    pub doh_listen_addr: Option<String>,
    pub tls_cert_pem: Option<String>,
    pub tls_key_pem: Option<String>,
    pub webservice_enabled: bool,
    pub webservice_listen_addr: String,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub deny_any: bool,
    pub deny_dnskey: bool,
    pub request_timeout_ms: u64,
    pub user: Option<String>,
    pub group: Option<String>,
    pub chroot_dir: Option<String>,
    pub udp_acceptor_threads: usize,
    pub tcp_acceptor_threads: usize,
    pub dnstap_enabled: bool,
    pub dnstap_backlog: usize,
    pub dnstap_socket_path: Option<String>,
    pub dnstap_identity: Option<String>,
    pub dnstap_version: Option<String>,
    pub max_tcp_clients: usize,
    pub max_dot_clients: usize,
    pub max_doh_clients: usize,
    pub max_waiting_clients: usize,
    pub max_active_queries: usize,
    pub max_clients_waiting_for_query: usize,
    pub hosts_local: HashMap<String, String>,
    pub hosts_remote: Option<RemoteHostsConfig>,
    pub blocklist_remote: Option<RemoteBlocklistConfig>,
    pub plugin_libraries: Vec<String>,
    pub lua_scripts: Vec<String>,
    pub lua_components: Vec<LuaComponentConfig>,
    pub lua_sandbox: LuaSandboxConfig,
    pub routing_rules: Vec<RoutingRuleConfig>,
}

impl Config {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Config, Error> {
        let path = path.as_ref();
        let mut fd = File::open(path)?;
        let mut lua = String::new();
        fd.read_to_string(&mut lua)?;
        Self::from_lua_string(&lua)
    }

    pub fn from_lua_string(lua: &str) -> Result<Config, Error> {
        let mut lua_config = load_lua_config_value(lua, "config.lua")?;
        normalize_lua_empty_arrays(&mut lua_config);
        Self::parse(lua_config)
    }

    fn parse(toml_config: Value) -> Result<Config, Error> {
        let config =
            if toml_config.get("server").is_some() || toml_config.get("upstreams").is_some() {
                Self::parse_balancedns(toml_config)?
            } else {
                Self::parse_legacy(toml_config)?
            };
        Self::validate(config)
    }

    fn validate(config: Config) -> Result<Config, Error> {
        if config.cache_size == 0 {
            return Err(invalid_data("cache size must be greater than 0"));
        }
        if config.request_timeout_ms == 0 {
            return Err(invalid_data("request timeout must be greater than 0"));
        }
        if config.max_ttl < config.min_ttl {
            return Err(invalid_data(
                "cache.max_ttl must be greater than or equal to cache.min_ttl",
            ));
        }
        if config.max_tcp_clients == 0 {
            return Err(invalid_data(
                "global.max_tcp_clients must be greater than 0",
            ));
        }
        if config.max_dot_clients == 0 {
            return Err(invalid_data(
                "global.max_dot_clients must be greater than 0",
            ));
        }
        if config.max_doh_clients == 0 {
            return Err(invalid_data(
                "global.max_doh_clients must be greater than 0",
            ));
        }
        if config.max_waiting_clients == 0 {
            return Err(invalid_data(
                "global.max_waiting_clients must be greater than 0",
            ));
        }
        if config.max_active_queries == 0 {
            return Err(invalid_data(
                "global.max_active_queries must be greater than 0",
            ));
        }
        if config.max_clients_waiting_for_query == 0 {
            return Err(invalid_data(
                "global.max_clients_waiting_for_query must be greater than 0",
            ));
        }
        if config.udp_acceptor_threads == 0 || config.tcp_acceptor_threads == 0 {
            return Err(invalid_data(
                "listener thread counts must be greater than 0",
            ));
        }
        if config.lua_sandbox.max_packet_bytes == 0 {
            return Err(invalid_data(
                "lua.sandbox.max_packet_bytes must be greater than 0",
            ));
        }
        if config.lua_sandbox.disable_after_failures == 0 {
            return Err(invalid_data(
                "lua.sandbox.disable_after_failures must be greater than 0",
            ));
        }
        if config.lua_sandbox.init_instruction_limit == 0 {
            return Err(invalid_data(
                "lua.sandbox.init_instruction_limit must be greater than 0",
            ));
        }
        if config.lua_sandbox.hook_instruction_limit == 0 {
            return Err(invalid_data(
                "lua.sandbox.hook_instruction_limit must be greater than 0",
            ));
        }
        if let Some(hosts_remote) = &config.hosts_remote {
            if hosts_remote.refresh_seconds == 0 {
                return Err(invalid_data(
                    "hosts_remote.refresh_seconds must be greater than 0",
                ));
            }
        }
        if let Some(blocklist_remote) = &config.blocklist_remote {
            if blocklist_remote.refresh_seconds == 0 {
                return Err(invalid_data(
                    "blocklist_remote.refresh_seconds must be greater than 0",
                ));
            }
        }

        let mut upstream_names = HashSet::with_capacity(config.upstreams.len());
        for upstream in &config.upstreams {
            if !upstream_names.insert(upstream.name.as_str()) {
                return Err(invalid_data(format!(
                    "Duplicate upstream name [{}] is not allowed",
                    upstream.name
                )));
            }
            match upstream.proto {
                UpstreamProtocol::Udp => {
                    let addr = upstream.addr.as_deref().ok_or_else(|| {
                        invalid_data(format!(
                            "Upstream [{}] is missing addr for proto=udp",
                            upstream.name
                        ))
                    })?;
                    addr.parse::<SocketAddr>().map_err(|_| {
                        invalid_data(format!(
                            "Upstream [{}] has an invalid UDP address [{}]",
                            upstream.name, addr
                        ))
                    })?;
                }
                UpstreamProtocol::Doh => {
                    let url = upstream.url.as_deref().ok_or_else(|| {
                        invalid_data(format!(
                            "Upstream [{}] is missing url for proto=doh",
                            upstream.name
                        ))
                    })?;
                    let parsed = Url::parse(url).map_err(|_| {
                        invalid_data(format!(
                            "Upstream [{}] has an invalid DoH URL [{}]",
                            upstream.name, url
                        ))
                    })?;
                    if parsed.scheme() != "https" && parsed.scheme() != "http" {
                        return Err(invalid_data(format!(
                            "Upstream [{}] must use http or https",
                            upstream.name
                        )));
                    }
                }
            }
        }

        for rule in &config.routing_rules {
            if rule.upstreams.is_empty() {
                return Err(invalid_data(format!(
                    "Routing rule [{}] must reference at least one upstream",
                    rule.suffix
                )));
            }
            for upstream_name in &rule.upstreams {
                if !upstream_names.contains(upstream_name.as_str()) {
                    return Err(invalid_data(format!(
                        "Routing rule [{}] references unknown upstream [{}]",
                        rule.suffix, upstream_name
                    )));
                }
            }
        }

        let tls_is_required = config.dot_listen_addr.is_some() || config.doh_listen_addr.is_some();
        if tls_is_required && config.tls_cert_pem.is_none() {
            return Err(invalid_data(
                "tls.cert_pem is required when DoT or DoH is enabled",
            ));
        }
        if tls_is_required && config.tls_key_pem.is_none() {
            return Err(invalid_data(
                "tls.key_pem is required when DoT or DoH is enabled",
            ));
        }

        Ok(config)
    }

    fn parse_balancedns(toml_config: Value) -> Result<Config, Error> {
        let config_server = get_table(&toml_config, "server");
        let config_tls = get_table(&toml_config, "tls");
        let config_balancing = get_table(&toml_config, "balancing");
        let config_resolver = get_table(&toml_config, "resolver");
        let config_security = get_table(&toml_config, "security");
        let config_cache = get_table(&toml_config, "cache");
        let config_metrics = get_table(&toml_config, "metrics");
        let config_hosts_remote = get_table(&toml_config, "hosts_remote");
        let config_blocklist_remote = get_table(&toml_config, "blocklist_remote");
        let config_plugins = get_table(&toml_config, "plugins");
        let config_lua = get_table(&toml_config, "lua");
        let config_global = get_table(&toml_config, "global");

        let udp_listen_addr = get_string(config_server, "udp_listen");
        let tcp_listen_addr = get_string(config_server, "tcp_listen");
        let dot_listen_addr = get_string(config_server, "dot_listen");
        let doh_listen_addr = get_string(config_server, "doh_listen");

        let tls_cert_pem = get_string(config_tls, "cert_pem");
        let tls_key_pem = get_string(config_tls, "key_pem");

        let balancing_algorithm =
            get_string(config_balancing, "algorithm").unwrap_or_else(|| "round_robin".to_owned());
        let lbmode = parse_balancedns_lbmode(&balancing_algorithm);
        let resolver_mode = parse_resolver_mode(
            get_string(config_resolver, "mode")
                .unwrap_or_else(|| "forward".to_owned())
                .as_str(),
        )?;

        let deny_any = get_bool(config_security, "deny_any", false, "security.deny_any")?;
        let deny_dnskey = get_bool(
            config_security,
            "deny_dnskey",
            false,
            "security.deny_dnskey",
        )?;
        let request_timeout_ms = get_u64(
            config_security,
            "request_timeout_ms",
            1500,
            "security.request_timeout_ms",
        )?;

        let cache_enabled = get_bool(config_cache, "enabled", true, "cache.enabled")?;
        let cache_size = get_usize(config_cache, "max_size", 20_000, "cache.max_size")?;
        let cache_ttl_seconds = get_u32(config_cache, "ttl_seconds", 600, "cache.ttl_seconds")?;
        let min_ttl = get_u32(config_cache, "min_ttl", 0, "cache.min_ttl")?;
        let max_ttl = get_u32(config_cache, "max_ttl", 86_400, "cache.max_ttl")?;
        let decrement_ttl = get_bool(config_cache, "decrement_ttl", true, "cache.decrement_ttl")?;
        let stale_refresh_enabled = get_bool(
            config_cache,
            "stale_refresh_enabled",
            false,
            "cache.stale_refresh_enabled",
        )?;
        let stale_ttl_seconds = get_u32(
            config_cache,
            "stale_ttl_seconds",
            30,
            "cache.stale_ttl_seconds",
        )?;

        let webservice_listen_addr =
            get_string(config_metrics, "listen").unwrap_or_else(|| "127.0.0.1:9100".to_owned());
        let webservice_enabled = config_metrics
            .and_then(|table| table.get("listen"))
            .is_some();

        let hosts_local = get_table(&toml_config, "hosts_local")
            .map(|table| {
                table
                    .iter()
                    .filter_map(|(name, value)| {
                        value
                            .as_str()
                            .map(|ip| (normalize_fqdn(name), clean_string(ip)))
                    })
                    .collect::<HashMap<String, String>>()
            })
            .unwrap_or_default();

        let hosts_remote = parse_remote_hosts_config(config_hosts_remote)?;
        let blocklist_remote = parse_remote_blocklist_config(config_blocklist_remote)?;
        let plugin_libraries = get_string_array(config_plugins, "libraries", "plugins.libraries")?;
        let (lua_scripts, lua_components, lua_sandbox) = parse_lua_config(config_lua)?;
        let routing_rules = parse_routing_rules(&toml_config)?;

        let user = get_string(config_global, "user");
        let group = get_string(config_global, "group");
        let chroot_dir = get_string(config_global, "chroot_dir");
        let max_tcp_clients = get_usize(
            config_global,
            "max_tcp_clients",
            250,
            "global.max_tcp_clients",
        )?;
        let max_dot_clients = get_usize(
            config_global,
            "max_dot_clients",
            max_tcp_clients,
            "global.max_dot_clients",
        )?;
        let max_doh_clients = get_usize(
            config_global,
            "max_doh_clients",
            max_tcp_clients,
            "global.max_doh_clients",
        )?;
        let max_waiting_clients = get_usize(
            config_global,
            "max_waiting_clients",
            1_000_000,
            "global.max_waiting_clients",
        )?;
        let max_active_queries = get_usize(
            config_global,
            "max_active_queries",
            100_000,
            "global.max_active_queries",
        )?;
        let max_clients_waiting_for_query = get_usize(
            config_global,
            "max_clients_waiting_for_query",
            1_000,
            "global.max_clients_waiting_for_query",
        )?;
        let udp_acceptor_threads =
            get_usize(config_global, "threads_udp", 1, "global.threads_udp")?.max(1);
        let tcp_acceptor_threads =
            get_usize(config_global, "threads_tcp", 1, "global.threads_tcp")?.max(1);

        let upstream_entries = toml_config
            .get("upstreams")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid_data("[[upstreams]] is required"))?;
        let mut upstreams = Vec::with_capacity(upstream_entries.len());
        let mut upstream_servers = Vec::new();
        for (idx, upstream_value) in upstream_entries.iter().enumerate() {
            let upstream = upstream_value
                .as_table()
                .ok_or_else(|| invalid_data("Invalid [[upstreams]] entry"))?;
            let name = get_string(Some(upstream), "name")
                .unwrap_or_else(|| format!("upstream-{}", idx + 1));
            let proto_str = get_string(Some(upstream), "proto").unwrap_or_else(|| "udp".to_owned());
            let pool = get_string(Some(upstream), "pool").unwrap_or_else(|| "default".to_owned());
            let weight = get_usize(Some(upstream), "weight", 1, "upstreams.weight")?.max(1);
            let (proto, addr, url) = match proto_str.as_str() {
                "udp" => {
                    let addr = get_required_string(
                        upstream,
                        "addr",
                        "upstreams.addr is required for proto=udp",
                    )?;
                    upstream_servers.push(addr.clone());
                    (UpstreamProtocol::Udp, Some(addr), None)
                }
                "doh" => {
                    let url = get_required_string(
                        upstream,
                        "url",
                        "upstreams.url is required for proto=doh",
                    )?;
                    (UpstreamProtocol::Doh, None, Some(url))
                }
                _ => {
                    return Err(invalid_data(
                        "upstreams.proto must be either 'udp' or 'doh'",
                    ))
                }
            };
            upstreams.push(UpstreamConfig {
                name,
                proto,
                addr,
                url,
                pool,
                weight,
            });
        }

        let listen_addr = udp_listen_addr
            .clone()
            .or_else(|| tcp_listen_addr.clone())
            .or_else(|| dot_listen_addr.clone())
            .unwrap_or_else(|| "0.0.0.0:5353".to_owned());

        Ok(Config {
            decrement_ttl,
            upstream_servers,
            upstreams,
            lbmode,
            balancing_algorithm,
            resolver_mode,
            upstream_max_failure_duration: Duration::from_millis(request_timeout_ms),
            cache_enabled,
            cache_size,
            cache_ttl_seconds,
            stale_refresh_enabled,
            stale_ttl_seconds,
            udp_ports: 1,
            listen_addr,
            udp_listen_addr,
            tcp_listen_addr,
            dot_listen_addr,
            doh_listen_addr,
            tls_cert_pem,
            tls_key_pem,
            webservice_enabled,
            webservice_listen_addr,
            min_ttl,
            max_ttl,
            deny_any,
            deny_dnskey,
            request_timeout_ms,
            user,
            group,
            chroot_dir,
            udp_acceptor_threads,
            tcp_acceptor_threads,
            dnstap_enabled: false,
            dnstap_backlog: 4096,
            dnstap_socket_path: None,
            dnstap_identity: None,
            dnstap_version: Some("BalanceDNS".to_owned()),
            max_tcp_clients,
            max_dot_clients,
            max_doh_clients,
            max_waiting_clients,
            max_active_queries,
            max_clients_waiting_for_query,
            hosts_local,
            hosts_remote,
            blocklist_remote,
            plugin_libraries,
            lua_scripts,
            lua_components,
            lua_sandbox,
            routing_rules,
        })
    }

    fn parse_legacy(toml_config: Value) -> Result<Config, Error> {
        let config_upstream = get_table(&toml_config, "upstream");
        let decrement_ttl_str =
            get_string(config_upstream, "type").unwrap_or_else(|| "authoritative".to_owned());
        let decrement_ttl = match decrement_ttl_str.as_str() {
            "authoritative" => false,
            "resolver" => true,
            _ => {
                return Err(invalid_data(
                    "Invalid value for the type of upstream servers. Must be 'authoritative' or 'resolver'",
                ))
            }
        };

        let upstream_servers =
            get_required_string_array(config_upstream, "servers", "upstream.servers is required")?;

        let balancing_algorithm =
            get_string(config_upstream, "strategy").unwrap_or_else(|| "uniform".to_owned());
        let lbmode = parse_legacy_lbmode(&balancing_algorithm)?;

        let request_timeout_ms = get_u64(
            config_upstream,
            "max_failure_duration",
            1500,
            "upstream.max_failure_duration",
        )?;

        let config_cache = get_table(&toml_config, "cache");
        let cache_size = get_usize(config_cache, "max_items", 250_000, "cache.max_items")?;
        let min_ttl = get_u32(config_cache, "min_ttl", 60, "cache.min_ttl")?;
        let max_ttl = get_u32(config_cache, "max_ttl", 86_400, "cache.max_ttl")?;

        let config_network = get_table(&toml_config, "network");
        let udp_ports = get_u16(config_network, "udp_ports", 8, "network.udp_ports")?;
        let listen_addr =
            get_string(config_network, "listen").unwrap_or_else(|| "0.0.0.0:53".to_owned());

        let config_webservice = get_table(&toml_config, "webservice");
        let webservice_enabled =
            get_bool(config_webservice, "enabled", false, "webservice.enabled")?;
        let webservice_listen_addr =
            get_string(config_webservice, "listen").unwrap_or_else(|| "0.0.0.0:9090".to_owned());

        let config_global = get_table(&toml_config, "global");
        let user = get_string(config_global, "user");
        let group = get_string(config_global, "group");
        let chroot_dir = get_string(config_global, "chroot_dir");
        let udp_acceptor_threads =
            get_usize(config_global, "threads_udp", 1, "global.threads_udp")?;
        let tcp_acceptor_threads =
            get_usize(config_global, "threads_tcp", 1, "global.threads_tcp")?;
        let max_tcp_clients = get_usize(
            config_global,
            "max_tcp_clients",
            250,
            "global.max_tcp_clients",
        )?;
        let max_waiting_clients = get_usize(
            config_global,
            "max_waiting_clients",
            1_000_000,
            "global.max_waiting_clients",
        )?;
        let max_active_queries = get_usize(
            config_global,
            "max_active_queries",
            100_000,
            "global.max_active_queries",
        )?;
        let max_clients_waiting_for_query = get_usize(
            config_global,
            "max_clients_waiting_for_query",
            1_000,
            "global.max_clients_waiting_for_query",
        )?;

        let config_dnstap = get_table(&toml_config, "dnstap");
        let dnstap_enabled = get_bool(config_dnstap, "enabled", false, "dnstap.enabled")?;
        let dnstap_backlog = get_usize(config_dnstap, "backlog", 4096, "dnstap.backlog")?;
        let dnstap_socket_path = get_string(config_dnstap, "socket_path");
        let dnstap_identity = get_string(config_dnstap, "identity");
        let dnstap_version = get_string(config_dnstap, "version");

        let upstreams = upstream_servers
            .iter()
            .enumerate()
            .map(|(idx, addr)| UpstreamConfig {
                name: format!("legacy-udp-{}", idx + 1),
                proto: UpstreamProtocol::Udp,
                addr: Some(addr.clone()),
                url: None,
                pool: "default".to_owned(),
                weight: 1,
            })
            .collect();

        Ok(Config {
            decrement_ttl,
            upstream_servers,
            upstreams,
            lbmode,
            balancing_algorithm,
            resolver_mode: ResolverMode::Forward,
            upstream_max_failure_duration: Duration::from_millis(request_timeout_ms),
            cache_enabled: true,
            cache_size,
            cache_ttl_seconds: max_ttl,
            stale_refresh_enabled: false,
            stale_ttl_seconds: 30,
            udp_ports,
            listen_addr: listen_addr.clone(),
            udp_listen_addr: Some(listen_addr.clone()),
            tcp_listen_addr: Some(listen_addr),
            dot_listen_addr: None,
            doh_listen_addr: None,
            tls_cert_pem: None,
            tls_key_pem: None,
            webservice_enabled,
            webservice_listen_addr,
            min_ttl,
            max_ttl,
            deny_any: false,
            deny_dnskey: false,
            request_timeout_ms,
            user,
            group,
            chroot_dir,
            udp_acceptor_threads,
            tcp_acceptor_threads,
            dnstap_enabled,
            dnstap_backlog,
            dnstap_socket_path,
            dnstap_identity,
            dnstap_version,
            max_tcp_clients,
            max_dot_clients: max_tcp_clients,
            max_doh_clients: max_tcp_clients,
            max_waiting_clients,
            max_active_queries,
            max_clients_waiting_for_query,
            hosts_local: HashMap::new(),
            hosts_remote: None,
            blocklist_remote: None,
            plugin_libraries: Vec::new(),
            lua_scripts: Vec::new(),
            lua_components: Vec::new(),
            lua_sandbox: default_lua_sandbox_config(),
            routing_rules: Vec::new(),
        })
    }
}

fn parse_balancedns_lbmode(algorithm: &str) -> LoadBalancingMode {
    match algorithm {
        "uniform" | "consistent_hash" => LoadBalancingMode::Uniform,
        "minload" | "power_of_two" | "fastest" => LoadBalancingMode::P2,
        "round_robin" | "fallback" => LoadBalancingMode::Fallback,
        other => {
            eprintln!(
                "WARNING: Unknown balancing algorithm '{}', using 'round_robin' (fallback mode)",
                other
            );
            LoadBalancingMode::Fallback
        }
    }
}

fn parse_resolver_mode(value: &str) -> Result<ResolverMode, Error> {
    match value {
        "forward" => Ok(ResolverMode::Forward),
        "recursive" => Ok(ResolverMode::Recursive),
        _ => Err(invalid_data(
            "resolver.mode must be either 'forward' or 'recursive'",
        )),
    }
}

fn parse_legacy_lbmode(value: &str) -> Result<LoadBalancingMode, Error> {
    match value {
        "uniform" => Ok(LoadBalancingMode::Uniform),
        "fallback" => Ok(LoadBalancingMode::Fallback),
        "minload" => Ok(LoadBalancingMode::P2),
        _ => Err(invalid_data(
            "Invalid value for the load balancing/failover strategy",
        )),
    }
}

fn parse_remote_hosts_config(
    table: Option<&TomlTable>,
) -> Result<Option<RemoteHostsConfig>, Error> {
    let Some(table) = table else {
        return Ok(None);
    };
    let Some(url) = get_string(Some(table), "url") else {
        return Ok(None);
    };
    Ok(Some(RemoteHostsConfig {
        url,
        refresh_seconds: get_u64(
            Some(table),
            "refresh_seconds",
            300,
            "hosts_remote.refresh_seconds",
        )?,
        ttl_seconds: get_u32(Some(table), "ttl_seconds", 60, "hosts_remote.ttl_seconds")?,
    }))
}

fn parse_remote_blocklist_config(
    table: Option<&TomlTable>,
) -> Result<Option<RemoteBlocklistConfig>, Error> {
    let Some(table) = table else {
        return Ok(None);
    };
    let Some(url) = get_string(Some(table), "url") else {
        return Ok(None);
    };
    Ok(Some(RemoteBlocklistConfig {
        url,
        refresh_seconds: get_u64(
            Some(table),
            "refresh_seconds",
            300,
            "blocklist_remote.refresh_seconds",
        )?,
    }))
}

fn parse_routing_rules(toml_config: &Value) -> Result<Vec<RoutingRuleConfig>, Error> {
    let Some(rules) = toml_config.get("routing_rules").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };

    let mut parsed = Vec::with_capacity(rules.len());
    for rule in rules {
        let table = rule
            .as_table()
            .ok_or_else(|| invalid_data("Invalid [[routing_rules]] entry"))?;
        let suffix = get_required_string(table, "suffix", "routing_rules.suffix must be a string")?;
        let upstreams = get_required_string_array(
            Some(table),
            "upstreams",
            "routing_rules.upstreams must be an array",
        )?;
        parsed.push(RoutingRuleConfig {
            suffix: normalize_fqdn(&suffix),
            upstreams,
        });
    }
    Ok(parsed)
}

fn parse_lua_config(
    table: Option<&TomlTable>,
) -> Result<(Vec<String>, Vec<LuaComponentConfig>, LuaSandboxConfig), Error> {
    let Some(table) = table else {
        return Ok((Vec::new(), Vec::new(), default_lua_sandbox_config()));
    };

    let default_settings = match table.get("settings") {
        Some(Value::Table(settings)) => Value::Table(settings.clone()),
        Some(_) => return Err(invalid_data("lua.settings must be a table")),
        None => Value::Table(TomlTable::new()),
    };

    let sandbox = match table.get("sandbox") {
        Some(Value::Table(sandbox)) => parse_lua_sandbox_config(Some(sandbox))?,
        Some(_) => return Err(invalid_data("lua.sandbox must be a table")),
        None => default_lua_sandbox_config(),
    };

    let script_paths = get_string_array(Some(table), "scripts", "lua.scripts")?;
    let mut components = Vec::new();
    for path in &script_paths {
        upsert_lua_component(
            &mut components,
            LuaComponentConfig {
                path: path.clone(),
                enabled: true,
                settings: default_settings.clone(),
            },
        );
    }

    if let Some(component_values) = table.get("components") {
        let component_values = component_values
            .as_array()
            .ok_or_else(|| invalid_data("lua.components must be an array of tables"))?;
        for component_value in component_values {
            let component_table = component_value
                .as_table()
                .ok_or_else(|| invalid_data("Each lua.components entry must be a table"))?;
            let path = get_required_string(
                component_table,
                "path",
                "lua.components.path must be a string",
            )?;
            let enabled = get_bool(
                Some(component_table),
                "enabled",
                true,
                "lua.components.enabled",
            )?;
            let component_settings = match component_table.get("settings") {
                Some(Value::Table(settings)) => Value::Table(settings.clone()),
                Some(_) => return Err(invalid_data("lua.components.settings must be a table")),
                None => Value::Table(TomlTable::new()),
            };
            let mut merged_settings = default_settings.clone();
            merge_toml_value(&mut merged_settings, &component_settings);
            upsert_lua_component(
                &mut components,
                LuaComponentConfig {
                    path,
                    enabled,
                    settings: merged_settings,
                },
            );
        }
    }

    let lua_scripts = components
        .iter()
        .filter(|component| component.enabled)
        .map(|component| component.path.clone())
        .collect::<Vec<_>>();

    Ok((lua_scripts, components, sandbox))
}

fn parse_lua_sandbox_config(table: Option<&TomlTable>) -> Result<LuaSandboxConfig, Error> {
    let defaults = default_lua_sandbox_config();
    Ok(LuaSandboxConfig {
        max_packet_bytes: get_usize(
            table,
            "max_packet_bytes",
            defaults.max_packet_bytes,
            "lua.sandbox.max_packet_bytes",
        )?,
        disable_after_failures: get_usize(
            table,
            "disable_after_failures",
            defaults.disable_after_failures,
            "lua.sandbox.disable_after_failures",
        )?,
        init_instruction_limit: get_u32(
            table,
            "init_instruction_limit",
            defaults.init_instruction_limit,
            "lua.sandbox.init_instruction_limit",
        )?,
        hook_instruction_limit: get_u32(
            table,
            "hook_instruction_limit",
            defaults.hook_instruction_limit,
            "lua.sandbox.hook_instruction_limit",
        )?,
    })
}

fn default_lua_sandbox_config() -> LuaSandboxConfig {
    LuaSandboxConfig {
        max_packet_bytes: 4096,
        disable_after_failures: 8,
        init_instruction_limit: 500_000,
        hook_instruction_limit: 100_000,
    }
}

fn upsert_lua_component(components: &mut Vec<LuaComponentConfig>, component: LuaComponentConfig) {
    if let Some(existing) = components
        .iter_mut()
        .find(|existing| existing.path == component.path)
    {
        *existing = component;
    } else {
        components.push(component);
    }
}

fn merge_toml_value(base: &mut Value, overlay: &Value) {
    match (base, overlay) {
        (Value::Table(base_table), Value::Table(overlay_table)) => {
            for (key, overlay_value) in overlay_table {
                match base_table.get_mut(key) {
                    Some(base_value) => merge_toml_value(base_value, overlay_value),
                    None => {
                        base_table.insert(key.clone(), overlay_value.clone());
                    }
                }
            }
        }
        (base_value, overlay_value) => {
            *base_value = overlay_value.clone();
        }
    }
}

fn normalize_lua_empty_arrays(value: &mut Value) {
    coerce_empty_table_to_array_at(value, &["plugins", "libraries"]);
    coerce_empty_table_to_array_at(value, &["lua", "scripts"]);
    coerce_empty_table_to_array_at(value, &["lua", "components"]);
    coerce_empty_table_to_array_at(value, &["upstreams"]);
    coerce_empty_table_to_array_at(value, &["routing_rules"]);
}

fn coerce_empty_table_to_array_at(value: &mut Value, path: &[&str]) {
    if path.is_empty() {
        return;
    }
    let mut current = value;
    for segment in path {
        let Some(table) = current.as_table_mut() else {
            return;
        };
        let Some(next) = table.get_mut(*segment) else {
            return;
        };
        current = next;
    }
    if matches!(current, Value::Table(table) if table.is_empty()) {
        *current = Value::Array(Vec::new());
    }
}

fn get_table<'a>(value: &'a Value, key: &str) -> Option<&'a TomlTable> {
    value.get(key)?.as_table()
}

fn get_string(table: Option<&TomlTable>, key: &str) -> Option<String> {
    table?.get(key)?.as_str().map(clean_string)
}

fn get_required_string(table: &TomlTable, key: &str, context: &str) -> Result<String, Error> {
    table
        .get(key)
        .and_then(Value::as_str)
        .map(clean_string)
        .ok_or_else(|| invalid_data(context))
}

fn get_bool(
    table: Option<&TomlTable>,
    key: &str,
    default: bool,
    context: &str,
) -> Result<bool, Error> {
    match table.and_then(|table| table.get(key)) {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| invalid_data(format!("{} must be a boolean", context))),
        None => Ok(default),
    }
}

fn get_u64(
    table: Option<&TomlTable>,
    key: &str,
    default: u64,
    context: &str,
) -> Result<u64, Error> {
    match table.and_then(|table| table.get(key)) {
        Some(value) => parse_integer(value, context).map(|value| value as u64),
        None => Ok(default),
    }
}

fn get_u32(
    table: Option<&TomlTable>,
    key: &str,
    default: u32,
    context: &str,
) -> Result<u32, Error> {
    match table.and_then(|table| table.get(key)) {
        Some(value) => parse_integer(value, context).map(|value| value as u32),
        None => Ok(default),
    }
}

fn get_u16(
    table: Option<&TomlTable>,
    key: &str,
    default: u16,
    context: &str,
) -> Result<u16, Error> {
    match table.and_then(|table| table.get(key)) {
        Some(value) => parse_integer(value, context).map(|value| value as u16),
        None => Ok(default),
    }
}

fn get_usize(
    table: Option<&TomlTable>,
    key: &str,
    default: usize,
    context: &str,
) -> Result<usize, Error> {
    match table.and_then(|table| table.get(key)) {
        Some(value) => parse_integer(value, context).map(|value| value as usize),
        None => Ok(default),
    }
}

fn parse_integer(value: &Value, context: &str) -> Result<u64, Error> {
    match value.as_integer() {
        Some(number) if number >= 0 => Ok(number as u64),
        Some(_) => Err(invalid_data(format!(
            "{} must be a non-negative integer",
            context
        ))),
        None => Err(invalid_data(format!("{} must be an integer", context))),
    }
}

fn get_string_array(
    table: Option<&TomlTable>,
    key: &str,
    context: &str,
) -> Result<Vec<String>, Error> {
    let Some(value) = table.and_then(|table| table.get(key)) else {
        return Ok(Vec::new());
    };
    parse_string_array(value, context)
}

fn get_required_string_array(
    table: Option<&TomlTable>,
    key: &str,
    missing_context: &str,
) -> Result<Vec<String>, Error> {
    let Some(value) = table.and_then(|table| table.get(key)) else {
        return Err(invalid_data(missing_context));
    };
    parse_string_array(value, missing_context)
}

fn parse_string_array(value: &Value, context: &str) -> Result<Vec<String>, Error> {
    let array = value
        .as_array()
        .ok_or_else(|| invalid_data(format!("{} must be an array", context)))?;
    array
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(clean_string)
                .ok_or_else(|| invalid_data(format!("{} entries must be strings", context)))
        })
        .collect()
}

fn invalid_data(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidData, message.into())
}

fn clean_string(value: &str) -> String {
    value.trim().trim_matches('`').trim().to_owned()
}

fn normalize_fqdn(name: &str) -> String {
    let cleaned = clean_string(name);
    if cleaned == "." {
        return cleaned;
    }
    let mut normalized = cleaned.to_ascii_lowercase();
    if !normalized.ends_with('.') {
        normalized.push('.');
    }
    normalized
}
