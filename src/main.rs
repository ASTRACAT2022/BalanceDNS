//! Import all the required crates, instanciate the main components and start
//! the service.
#![allow(dead_code, unused_imports, unused_variables)]

#[macro_use]
extern crate log;

use clap::{Command, Arg};
use libbalancedns::{BalanceDNS, Config};

fn main() {
    env_logger::init();

    let matches = Command::new("BalanceDNS")
        .version("0.3.0")
        .author("Frank Denis")
        .about("A balancing DNS proxy with UDP, TCP, DoT and DoH support")
        .arg(
            Arg::new("config_file")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Path to the BalanceDNS TOML config file")
                .num_args(1)
                .required(true),
        )
        .get_matches();

    let config_file = match matches.get_one::<String>("config_file") {
        None => {
            error!("A path to the configuration file is required");
            return;
        }
        Some(config_file) => config_file,
    };
    let config = match Config::from_path(config_file) {
        Err(err) => {
            error!(
                "The configuration couldn't be loaded -- [{}]: [{}]",
                config_file, err
            );
            return;
        }
        Ok(config) => config,
    };
    BalanceDNS::new(config);
}
