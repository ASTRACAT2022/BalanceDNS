//! Import all the required crates, instanciate the main components and start
//! the service.
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(
    feature = "clippy",
    allow(identity_op, ptr_arg, collapsible_if, let_and_return)
)]
#![allow(dead_code, unused_imports, unused_variables)]

extern crate base64;
extern crate byteorder;
extern crate clockpro_cache;
#[macro_use]
extern crate bpf;
extern crate bytes;
extern crate coarsetime;
extern crate dnstap;
extern crate env_logger;
#[macro_use]
extern crate futures;
extern crate jumphash;
#[macro_use]
extern crate lazy_static;
extern crate libloading;
#[macro_use]
extern crate log;
extern crate net2;
extern crate nix;
extern crate parking_lot;
extern crate privdrop;
extern crate rand;
extern crate rustls;
extern crate rustls_pemfile;
extern crate siphasher;
extern crate slab;
extern crate socket_priority;
extern crate tokio_core;
#[macro_use]
extern crate tokio_io;
extern crate tokio_timer;
extern crate toml;
extern crate ureq;
extern crate url;

#[cfg(feature = "webservice")]
extern crate hyper;

#[macro_use]
extern crate prometheus;

mod balancedns_runtime;
mod cache;
mod client_queries_handler;
mod client_query;
mod config;
pub mod dns;
mod ext_response;
mod log_dnstap;
mod net_helpers;
mod pending_query;
mod plugins;
mod resolver;
use std::io;
mod tcp_acceptor;
mod tcp_arbitrator;
mod udp_acceptor;
mod udp_stream;
mod upstream_probe;
mod upstream_server;
mod varz;

#[cfg(feature = "webservice")]
mod webservice;

use balancedns_runtime::BalanceDnsRuntime;
use cache::Cache;
pub use config::{
    Config, RemoteBlocklistConfig, RemoteHostsConfig, UpstreamConfig, UpstreamProtocol,
};
use privdrop::PrivDrop;
use std::net;
use std::sync::Arc;
use tcp_arbitrator::TcpArbitrator;
use varz::*;

const CLOCK_RESOLUTION: u64 = 100;
const DNS_MAX_SIZE: usize = 65535;
const DNS_MAX_TCP_SIZE: usize = 65535;
const DNS_MAX_UDP_SIZE: usize = 4096;
const DNS_QUERY_MAX_SIZE: usize = 283;
const DNS_QUERY_MIN_SIZE: usize = 17;
const DNS_UDP_NOEDNS0_MAX_SIZE: usize = 512;
const HEALTH_CHECK_MS: u64 = 10 * 1000;
const MAX_EVENTS_PER_BATCH: usize = 1024;
const MAX_TCP_CLIENTS: usize = 1_000;
const MAX_TCP_HASH_DISTANCE: usize = 10;
const MAX_TCP_IDLE_MS: u64 = 10 * 1000;
const FAILURE_TTL: u32 = 30;
const TCP_BACKLOG: usize = 1024;
const UDP_BUFFER_SIZE: usize = 16 * 1024 * 1024;
const UPSTREAM_TOTAL_TIMEOUT_MS: u64 = 5 * 1000;
const UPSTREAM_QUERY_MIN_TIMEOUT_MS: u64 = 1000;
const UPSTREAM_QUERY_MAX_TIMEOUT_MS: u64 = UPSTREAM_TOTAL_TIMEOUT_MS * 3 / 4;
const UPSTREAM_QUERY_MAX_DEVIATION_COEFFICIENT: f64 = 4.0;
const UPSTREAM_PROBES_DELAY_MS: u64 = 1000;

#[cfg(feature = "webservice")]
const WEBSERVICE_THREADS: usize = 1;

pub struct BalanceDNSContext {
    pub config: Config,
    pub listen_addr: String,
    pub udp_socket: net::UdpSocket,
    pub tcp_listener: net::TcpListener,
    pub cache: Cache,
    pub varz: Arc<Varz>,
    pub tcp_arbitrator: TcpArbitrator,
    pub dnstap_sender: Option<log_dnstap::Sender>,
}

pub struct BalanceDNS;

impl BalanceDNS {
    fn privileges_drop(config: &Config) {
        let mut pd = PrivDrop::default();
        if let Some(ref user) = config.user {
            pd = pd.user(user).expect("User not found");
        }
        if let Some(ref group) = config.group {
            pd = pd.group(group).expect("Group not found");
        }
        if let Some(ref chroot_dir) = config.chroot_dir {
            pd = pd.chroot(chroot_dir);
        }
        pd.apply().expect("Unable to drop privileges");
    }

    pub fn new(config: Config) -> BalanceDNS {
        let ct = coarsetime::Updater::new(CLOCK_RESOLUTION)
            .start()
            .expect("Unable to spawn the internal timer");
        let varz = Arc::new(Varz::new());
        Self::privileges_drop(&config);
        let runtime = BalanceDnsRuntime::new(config, varz);
        runtime.run().expect("Unable to start BalanceDNS");
        ct.stop().unwrap();
        BalanceDNS
    }
}
