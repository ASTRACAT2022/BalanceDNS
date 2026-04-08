//! Import all the required crates, instanciate the main components and start
//! the service.
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(
    feature = "clippy",
    allow(identity_op, ptr_arg, collapsible_if, let_and_return)
)]
#![allow(dead_code)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate prometheus;

mod balancedns_runtime;
mod cache;
mod conductor;
mod config;
pub mod dns;
mod lua_config;
mod lua_plugin;
mod odoh;
mod plugins;
mod remote_refresh;
mod sandbox;
mod server;
mod varz;
mod worker;

use balancedns_runtime::BalanceDnsRuntime;
pub use config::{
    Config, LuaComponentConfig, LuaSandboxConfig, RemoteBlocklistConfig, RemoteHostsConfig,
    UpstreamConfig, UpstreamProtocol,
};
use privdrop::PrivDrop;
pub use remote_refresh::{run_remote_refresh_helper, RemoteRefreshKind};
use std::io;
use std::sync::Arc;
use varz::*;

const CLOCK_RESOLUTION: u64 = 100;
const DNS_QUERY_MIN_SIZE: usize = 17;
const DNS_UDP_NOEDNS0_MAX_SIZE: usize = 512;

pub struct BalanceDNS;

impl BalanceDNS {
    fn privileges_drop(config: &Config) -> io::Result<()> {
        let is_root = nix::unistd::geteuid() == 0;
        if !is_root {
            if config.user.is_some() || config.group.is_some() || config.chroot_dir.is_some() {
                warn!(
                    "Skipping internal privilege drop because the process is already running as an unprivileged user"
                );
            }
            return Ok(());
        }
        let mut pd = PrivDrop::default();
        if let Some(ref user) = config.user {
            pd = pd
                .user(user)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        }
        if let Some(ref group) = config.group {
            pd = pd
                .group(group)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        }
        if let Some(ref chroot_dir) = config.chroot_dir {
            pd = pd.chroot(chroot_dir);
        }
        pd.apply().map_err(io::Error::other)
    }

    pub fn new(config: Config) -> io::Result<BalanceDNS> {
        let ct = coarsetime::Updater::new(CLOCK_RESOLUTION)
            .start()
            .map_err(io::Error::other)?;
        let varz = Arc::new(Varz::new());
        Self::privileges_drop(&config)?;
        let runtime = BalanceDnsRuntime::new(config, varz)?;
        let run_result = runtime.run();
        let stop_result = ct.stop().map_err(io::Error::other);
        run_result?;
        stop_result?;
        Ok(BalanceDNS)
    }
}
