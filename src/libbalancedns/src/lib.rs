//! Import all the required crates, instanciate the main components and start
//! the service.
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(
    feature = "clippy",
    allow(identity_op, ptr_arg, collapsible_if, let_and_return)
)]
#![allow(dead_code, unused_imports, unused_variables)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate prometheus;

mod balancedns_runtime;
mod cache;
mod config;
pub mod dns;
mod odoh;
mod plugins;
mod varz;

use balancedns_runtime::BalanceDnsRuntime;
pub use config::{
    Config, RemoteBlocklistConfig, RemoteHostsConfig, UpstreamConfig, UpstreamProtocol,
};
use privdrop::PrivDrop;
use std::sync::Arc;
use varz::*;

const CLOCK_RESOLUTION: u64 = 100;
const DNS_QUERY_MIN_SIZE: usize = 17;
const DNS_UDP_NOEDNS0_MAX_SIZE: usize = 512;

pub struct BalanceDNS;

impl BalanceDNS {
    fn privileges_drop(config: &Config) {
        let is_root = nix::unistd::geteuid() == 0;
        if !is_root {
            if config.user.is_some() || config.group.is_some() || config.chroot_dir.is_some() {
                warn!(
                    "Skipping internal privilege drop because the process is already running as an unprivileged user"
                );
            }
            return;
        }
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
