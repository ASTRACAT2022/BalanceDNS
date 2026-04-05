use coarsetime::Duration;
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::path::Path;
use toml;

#[derive(Clone, Copy, Debug)]
pub enum LoadBalancingMode {
    Fallback,
    Uniform,
    P2,
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
pub struct Config {
    pub decrement_ttl: bool,
    pub upstream_servers: Vec<String>,
    pub upstreams: Vec<UpstreamConfig>,
    pub lbmode: LoadBalancingMode,
    pub balancing_algorithm: String,
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
    pub max_waiting_clients: usize,
    pub max_active_queries: usize,
    pub max_clients_waiting_for_query: usize,
    pub hosts_local: HashMap<String, String>,
    pub hosts_remote: Option<RemoteHostsConfig>,
    pub blocklist_remote: Option<RemoteBlocklistConfig>,
    pub plugin_libraries: Vec<String>,
    pub routing_rules: Vec<RoutingRuleConfig>,
}

impl Config {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Config, Error> {
        let mut fd = File::open(path)?;
        let mut toml = String::new();
        fd.read_to_string(&mut toml)?;
        Self::from_string(&toml)
    }

    pub fn from_string(toml: &str) -> Result<Config, Error> {
        let toml_config: toml::Value = toml::from_str(toml).map_err(|err| {
            Error::new(
                ErrorKind::InvalidData,
                format!("Syntax error - config file is not valid TOML: {}", err),
            )
        })?;
        Self::parse(toml_config)
    }

    fn parse(toml_config: toml::Value) -> Result<Config, Error> {
        if toml_config.get("server").is_some() || toml_config.get("upstreams").is_some() {
            return Self::parse_balancedns(toml_config);
        }
        Self::parse_legacy(toml_config)
    }

    fn parse_balancedns(toml_config: toml::Value) -> Result<Config, Error> {
        let config_server = toml_config.get("server");
        let config_tls = toml_config.get("tls");
        let config_balancing = toml_config.get("balancing");
        let config_security = toml_config.get("security");
        let config_cache = toml_config.get("cache");
        let config_metrics = toml_config.get("metrics");
        let config_hosts_remote = toml_config.get("hosts_remote");
        let config_blocklist_remote = toml_config.get("blocklist_remote");
        let config_plugins = toml_config.get("plugins");
        let config_routing_rules = toml_config.get("routing_rules");
        let config_global = toml_config.get("global");

        let udp_listen_addr = config_server
            .and_then(|x| x.get("udp_listen"))
            .and_then(|x| x.as_str())
            .map(clean_string);
        let tcp_listen_addr = config_server
            .and_then(|x| x.get("tcp_listen"))
            .and_then(|x| x.as_str())
            .map(clean_string);
        let dot_listen_addr = config_server
            .and_then(|x| x.get("dot_listen"))
            .and_then(|x| x.as_str())
            .map(clean_string);
        let doh_listen_addr = config_server
            .and_then(|x| x.get("doh_listen"))
            .and_then(|x| x.as_str())
            .map(clean_string);

        let tls_cert_pem = config_tls
            .and_then(|x| x.get("cert_pem"))
            .and_then(|x| x.as_str())
            .map(clean_string);
        let tls_key_pem = config_tls
            .and_then(|x| x.get("key_pem"))
            .and_then(|x| x.as_str())
            .map(clean_string);

        let balancing_algorithm = config_balancing
            .and_then(|x| x.get("algorithm"))
            .and_then(|x| x.as_str())
            .map(clean_string)
            .unwrap_or_else(|| "round_robin".to_owned());
        let lbmode = match balancing_algorithm.as_str() {
            "uniform" | "consistent_hash" => LoadBalancingMode::Uniform,
            "minload" | "power_of_two" | "fastest" => LoadBalancingMode::P2,
            "round_robin" | "fallback" => LoadBalancingMode::Fallback,
            other => {
                eprintln!("WARNING: Unknown balancing algorithm '{}', using 'round_robin' (fallback mode)", other);
                LoadBalancingMode::Fallback
            }
        };

        let deny_any = config_security
            .and_then(|x| x.get("deny_any"))
            .map_or(false, |x| {
                x.as_bool().expect("security.deny_any must be a boolean")
            });
        let deny_dnskey = config_security
            .and_then(|x| x.get("deny_dnskey"))
            .map_or(false, |x| {
                x.as_bool().expect("security.deny_dnskey must be a boolean")
            });
        let request_timeout_ms = config_security
            .and_then(|x| x.get("request_timeout_ms"))
            .map_or(1500, |x| {
                x.as_integer()
                    .expect("security.request_timeout_ms must be an integer")
            }) as u64;

        let cache_enabled = config_cache
            .and_then(|x| x.get("enabled"))
            .map_or(true, |x| {
                x.as_bool().expect("cache.enabled must be a boolean")
            });
        let cache_size = config_cache
            .and_then(|x| x.get("max_size"))
            .map_or(20_000, |x| {
                x.as_integer().expect("cache.max_size must be an integer")
            }) as usize;
        let cache_ttl_seconds = config_cache
            .and_then(|x| x.get("ttl_seconds"))
            .map_or(600, |x| {
                x.as_integer()
                    .expect("cache.ttl_seconds must be an integer")
            }) as u32;
        let min_ttl = config_cache
            .and_then(|x| x.get("min_ttl"))
            .map_or(0, |x| {
                x.as_integer().expect("cache.min_ttl must be an integer")
            }) as u32;
        let max_ttl = config_cache
            .and_then(|x| x.get("max_ttl"))
            .map_or(86_400, |x| {
                x.as_integer().expect("cache.max_ttl must be an integer")
            }) as u32;
        let decrement_ttl = config_cache
            .and_then(|x| x.get("decrement_ttl"))
            .map_or(true, |x| {
                x.as_bool().expect("cache.decrement_ttl must be a boolean")
            });
        let stale_refresh_enabled = config_cache
            .and_then(|x| x.get("stale_refresh_enabled"))
            .map_or(false, |x| {
                x.as_bool()
                    .expect("cache.stale_refresh_enabled must be a boolean")
            });
        let stale_ttl_seconds = config_cache
            .and_then(|x| x.get("stale_ttl_seconds"))
            .map_or(30, |x| {
                x.as_integer()
                    .expect("cache.stale_ttl_seconds must be an integer")
            }) as u32;

        let webservice_listen_addr = config_metrics
            .and_then(|x| x.get("listen"))
            .and_then(|x| x.as_str())
            .map(clean_string)
            .unwrap_or_else(|| "127.0.0.1:9100".to_owned());
        let webservice_enabled = config_metrics
            .and_then(|x| x.get("listen"))
            .is_some();

        let hosts_local = toml_config
            .get("hosts_local")
            .and_then(|x| x.as_table())
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
            .unwrap_or_else(HashMap::new);

        let hosts_remote = config_hosts_remote.and_then(|x| {
            let url = x.get("url").and_then(|v| v.as_str()).map(clean_string)?;
            Some(RemoteHostsConfig {
                url,
                refresh_seconds: x
                    .get("refresh_seconds")
                    .map_or(300, |v| {
                        v.as_integer()
                            .expect("hosts_remote.refresh_seconds must be an integer")
                    }) as u64,
                ttl_seconds: x
                    .get("ttl_seconds")
                    .map_or(60, |v| {
                        v.as_integer()
                            .expect("hosts_remote.ttl_seconds must be an integer")
                    }) as u32,
            })
        });

        let blocklist_remote = config_blocklist_remote.and_then(|x| {
            let url = x.get("url").and_then(|v| v.as_str()).map(clean_string)?;
            Some(RemoteBlocklistConfig {
                url,
                refresh_seconds: x
                    .get("refresh_seconds")
                    .map_or(300, |v| {
                        v.as_integer()
                            .expect("blocklist_remote.refresh_seconds must be an integer")
                    }) as u64,
            })
        });

        let plugin_libraries = config_plugins
            .and_then(|x| x.get("libraries"))
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .map(|x| {
                        clean_string(
                            x.as_str()
                                .expect("plugins.libraries entries must be strings"),
                        )
                    })
                    .collect::<Vec<String>>()
            })
            .unwrap_or_else(Vec::new);

        let routing_rules = config_routing_rules
            .and_then(|x| x.as_array())
            .map(|rules| {
                rules
                    .iter()
                    .map(|rule| {
                        let table = rule.as_table().expect("Invalid [[routing_rules]] entry");
                        let suffix = table
                            .get("suffix")
                            .and_then(|x| x.as_str())
                            .map(clean_string)
                            .expect("routing_rules.suffix must be a string");
                        let upstreams = table
                            .get("upstreams")
                            .and_then(|x| x.as_array())
                            .expect("routing_rules.upstreams must be an array")
                            .iter()
                            .map(|x| {
                                clean_string(
                                    x.as_str()
                                        .expect("routing_rules.upstreams entries must be strings"),
                                )
                            })
                            .collect::<Vec<String>>();
                        RoutingRuleConfig { suffix, upstreams }
                    })
                    .collect::<Vec<RoutingRuleConfig>>()
            })
            .unwrap_or_else(Vec::new);

        let user = config_global
            .and_then(|x| x.get("user"))
            .and_then(|x| x.as_str())
            .map(clean_string);
        let group = config_global
            .and_then(|x| x.get("group"))
            .and_then(|x| x.as_str())
            .map(clean_string);
        let chroot_dir = config_global
            .and_then(|x| x.get("chroot_dir"))
            .and_then(|x| x.as_str())
            .map(clean_string);

        let max_tcp_clients = config_global
            .and_then(|x| x.get("max_tcp_clients"))
            .map_or(250, |x| {
                x.as_integer()
                    .expect("global.max_tcp_clients must be an integer")
            }) as usize;
        let max_waiting_clients = config_global
            .and_then(|x| x.get("max_waiting_clients"))
            .map_or(1_000_000, |x| {
                x.as_integer()
                    .expect("global.max_waiting_clients must be an integer")
            }) as usize;
        let max_active_queries = config_global
            .and_then(|x| x.get("max_active_queries"))
            .map_or(100_000, |x| {
                x.as_integer()
                    .expect("global.max_active_queries must be an integer")
            }) as usize;
        let max_clients_waiting_for_query = config_global
            .and_then(|x| x.get("max_clients_waiting_for_query"))
            .map_or(1_000, |x| {
                x.as_integer()
                    .expect("global.max_clients_waiting_for_query must be an integer")
            }) as usize;

        let upstreams_value = toml_config
            .get("upstreams")
            .and_then(|x| x.as_array())
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "[[upstreams]] is required"))?;
        let mut upstreams = Vec::with_capacity(upstreams_value.len());
        let mut upstream_servers = Vec::new();
        for (idx, upstream_value) in upstreams_value.iter().enumerate() {
            let upstream = upstream_value
                .as_table()
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Invalid [[upstreams]] entry"))?;
            let name = upstream
                .get("name")
                .and_then(|x| x.as_str())
                .map(clean_string)
                .unwrap_or_else(|| format!("upstream-{}", idx + 1));
            let proto = upstream
                .get("proto")
                .and_then(|x| x.as_str())
                .map(clean_string)
                .unwrap_or_else(|| "udp".to_owned());
            let pool = upstream
                .get("pool")
                .and_then(|x| x.as_str())
                .map(clean_string)
                .unwrap_or_else(|| "default".to_owned());
            let weight = upstream
                .get("weight")
                .map_or(1, |x| {
                    x.as_integer()
                        .expect("upstreams.weight must be an integer")
                }) as usize;
            let (proto, addr, url) = match proto.as_str() {
                "udp" => {
                    let addr = upstream
                        .get("addr")
                        .and_then(|x| x.as_str())
                        .map(clean_string)
                        .ok_or_else(|| {
                            Error::new(
                                ErrorKind::InvalidData,
                                "upstreams.addr is required for proto=udp",
                            )
                        })?;
                    upstream_servers.push(addr.clone());
                    (UpstreamProtocol::Udp, Some(addr), None)
                }
                "doh" => {
                    let url = upstream
                        .get("url")
                        .and_then(|x| x.as_str())
                        .map(clean_string)
                        .ok_or_else(|| {
                            Error::new(
                                ErrorKind::InvalidData,
                                "upstreams.url is required for proto=doh",
                            )
                        })?;
                    (UpstreamProtocol::Doh, None, Some(url))
                }
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
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
                weight: if weight == 0 { 1 } else { weight },
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
            udp_acceptor_threads: 1,
            tcp_acceptor_threads: 1,
            dnstap_enabled: false,
            dnstap_backlog: 4096,
            dnstap_socket_path: None,
            dnstap_identity: None,
            dnstap_version: Some("BalanceDNS".to_owned()),
            max_tcp_clients,
            max_waiting_clients,
            max_active_queries,
            max_clients_waiting_for_query,
            hosts_local,
            hosts_remote,
            blocklist_remote,
            plugin_libraries,
            routing_rules,
        })
    }

    fn parse_legacy(toml_config: toml::Value) -> Result<Config, Error> {
        let config_upstream = toml_config.get("upstream");
        let decrement_ttl_str = config_upstream
            .and_then(|x| x.get("type"))
            .map_or("authoritative", |x| {
                x.as_str().expect("upstream.type must be a string")
            });
        let decrement_ttl = match decrement_ttl_str {
            "authoritative" => false,
            "resolver" => true,
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Invalid value for the type of upstream servers. Must be 'authoritative' or 'resolver'",
                ))
            }
        };

        let upstream_servers: Vec<String> = config_upstream
            .and_then(|x| x.get("servers"))
            .expect("upstream.servers is required")
            .as_array()
            .expect("Invalid list of upstream servers")
            .iter()
            .map(|x| {
                clean_string(
                    x.as_str()
                        .expect("upstream servers must be strings"),
                )
            })
            .collect();

        let lbmode_str = config_upstream
            .and_then(|x| x.get("strategy"))
            .map_or("uniform", |x| {
                x.as_str().expect("upstream.strategy must be a string")
            });
        let lbmode = match lbmode_str {
            "uniform" => LoadBalancingMode::Uniform,
            "fallback" => LoadBalancingMode::Fallback,
            "minload" => LoadBalancingMode::P2,
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Invalid value for the load balancing/failover strategy",
                ))
            }
        };

        let request_timeout_ms = config_upstream
            .and_then(|x| x.get("max_failure_duration"))
            .map_or(1500, |x| {
                x.as_integer()
                    .expect("upstream.max_failure_duration must be an integer")
            }) as u64;

        let config_cache = toml_config.get("cache");
        let cache_size = config_cache
            .and_then(|x| x.get("max_items"))
            .map_or(250_000, |x| {
                x.as_integer().expect("cache.max_items must be an integer")
            }) as usize;
        let min_ttl = config_cache.and_then(|x| x.get("min_ttl")).map_or(60, |x| {
            x.as_integer().expect("cache.min_ttl must be an integer")
        }) as u32;
        let max_ttl = config_cache
            .and_then(|x| x.get("max_ttl"))
            .map_or(86_400, |x| {
                x.as_integer().expect("cache.max_ttl must be an integer")
            }) as u32;

        let config_network = toml_config.get("network");
        let udp_ports = config_network
            .and_then(|x| x.get("udp_ports"))
            .map_or(8, |x| {
                x.as_integer()
                    .expect("network.udp_ports must be an integer")
            }) as u16;
        let listen_addr = config_network
            .and_then(|x| x.get("listen"))
            .map_or("0.0.0.0:53", |x| {
                x.as_str().expect("network.listen must be a string")
            })
            .to_owned();

        let config_webservice = toml_config.get("webservice");
        let webservice_enabled = config_webservice
            .and_then(|x| x.get("enabled"))
            .map_or(false, |x| {
                x.as_bool().expect("webservice.enabled must be a boolean")
            });
        let webservice_listen_addr = config_webservice
            .and_then(|x| x.get("listen"))
            .map_or("0.0.0.0:9090", |x| {
                x.as_str().expect("webservice.listen must be a string")
            })
            .to_owned();

        let config_global = toml_config.get("global");
        let user = config_global
            .and_then(|x| x.get("user"))
            .and_then(|x| x.as_str())
            .map(str::to_owned);
        let group = config_global
            .and_then(|x| x.get("group"))
            .and_then(|x| x.as_str())
            .map(str::to_owned);
        let chroot_dir = config_global
            .and_then(|x| x.get("chroot_dir"))
            .and_then(|x| x.as_str())
            .map(str::to_owned);
        let udp_acceptor_threads = config_global
            .and_then(|x| x.get("threads_udp"))
            .map_or(1, |x| {
                x.as_integer()
                    .expect("global.threads_udp must be an integer")
            }) as usize;
        let tcp_acceptor_threads = config_global
            .and_then(|x| x.get("threads_tcp"))
            .map_or(1, |x| {
                x.as_integer()
                    .expect("global.threads_tcp must be an integer")
            }) as usize;
        let max_tcp_clients = config_global
            .and_then(|x| x.get("max_tcp_clients"))
            .map_or(250, |x| {
                x.as_integer()
                    .expect("global.max_tcp_clients must be an integer")
            }) as usize;
        let max_waiting_clients = config_global
            .and_then(|x| x.get("max_waiting_clients"))
            .map_or(1_000_000, |x| {
                x.as_integer()
                    .expect("global.max_waiting_clients must be an integer")
            }) as usize;
        let max_active_queries = config_global
            .and_then(|x| x.get("max_active_queries"))
            .map_or(100_000, |x| {
                x.as_integer()
                    .expect("global.max_active_queries must be an integer")
            }) as usize;
        let max_clients_waiting_for_query = config_global
            .and_then(|x| x.get("max_clients_waiting_for_query"))
            .map_or(1_000, |x| {
                x.as_integer()
                    .expect("global.max_clients_waiting_for_query must be an integer")
            }) as usize;

        let config_dnstap = toml_config.get("dnstap");
        let dnstap_enabled = config_dnstap
            .and_then(|x| x.get("enabled"))
            .map_or(false, |x| {
                x.as_bool().expect("dnstap.enabled must be a boolean")
            });
        let dnstap_backlog = config_dnstap
            .and_then(|x| x.get("backlog"))
            .map_or(4096, |x| {
                x.as_integer().expect("dnstap.backlog must be an integer")
            }) as usize;
        let dnstap_socket_path = config_dnstap
            .and_then(|x| x.get("socket_path"))
            .and_then(|x| x.as_str())
            .map(str::to_owned);
        let dnstap_identity = config_dnstap
            .and_then(|x| x.get("identity"))
            .and_then(|x| x.as_str())
            .map(str::to_owned);
        let dnstap_version = config_dnstap
            .and_then(|x| x.get("version"))
            .and_then(|x| x.as_str())
            .map(str::to_owned);

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
            balancing_algorithm: lbmode_str.to_owned(),
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
            max_waiting_clients,
            max_active_queries,
            max_clients_waiting_for_query,
            hosts_local: HashMap::new(),
            hosts_remote: None,
            blocklist_remote: None,
            plugin_libraries: Vec::new(),
            routing_rules: Vec::new(),
        })
    }
}

fn clean_string(value: &str) -> String {
    value.trim().trim_matches('`').trim().to_owned()
}

fn normalize_fqdn(name: &str) -> String {
    let mut normalized = clean_string(name).to_ascii_lowercase();
    if !normalized.ends_with('.') {
        normalized.push('.');
    }
    normalized
}
