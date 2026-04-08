//! Import all the required crates, instanciate the main components and start
//! the service.

#[macro_use]
extern crate log;

use clap::{Arg, Command};
use libbalancedns::{run_remote_refresh_helper, BalanceDNS, Config, RemoteRefreshKind};
use std::process::ExitCode;

fn main() -> ExitCode {
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
                .help("Path to the BalanceDNS Lua config file")
                .num_args(1)
                .required(false),
        )
        .subcommand(
            Command::new("refresh-remote-state")
                .hide(true)
                .arg(
                    Arg::new("kind")
                        .long("kind")
                        .value_name("KIND")
                        .num_args(1)
                        .required(true),
                )
                .arg(
                    Arg::new("url")
                        .long("url")
                        .value_name("URL")
                        .num_args(1)
                        .required(true),
                )
                .arg(
                    Arg::new("output")
                        .long("output")
                        .value_name("FILE")
                        .num_args(1)
                        .required(true),
                )
                .arg(
                    Arg::new("timeout_ms")
                        .long("timeout-ms")
                        .value_name("MILLISECONDS")
                        .num_args(1),
                ),
        )
        .get_matches();

    if let Some(("refresh-remote-state", helper)) = matches.subcommand() {
        let kind = match helper.get_one::<String>("kind") {
            Some(kind) => match RemoteRefreshKind::parse(kind) {
                Ok(kind) => kind,
                Err(err) => {
                    error!("{}", err);
                    return ExitCode::FAILURE;
                }
            },
            None => {
                error!("A remote refresh kind is required");
                return ExitCode::FAILURE;
            }
        };
        let url = match helper.get_one::<String>("url") {
            Some(url) => url,
            None => {
                error!("A remote refresh URL is required");
                return ExitCode::FAILURE;
            }
        };
        let output = match helper.get_one::<String>("output") {
            Some(output) => output,
            None => {
                error!("A remote refresh output path is required");
                return ExitCode::FAILURE;
            }
        };
        let timeout_ms = helper
            .get_one::<String>("timeout_ms")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(1000);
        return match run_remote_refresh_helper(kind, url, output, timeout_ms) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                error!("Remote refresh helper failed: {}", err);
                ExitCode::FAILURE
            }
        };
    }

    let config_file = match matches.get_one::<String>("config_file") {
        None => {
            error!("A path to the configuration file is required");
            return ExitCode::FAILURE;
        }
        Some(config_file) => config_file,
    };
    let config = match Config::from_path(config_file) {
        Err(err) => {
            error!(
                "The configuration couldn't be loaded -- [{}]: [{}]",
                config_file, err
            );
            return ExitCode::FAILURE;
        }
        Ok(config) => config,
    };
    match BalanceDNS::new(config) {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            error!("Unable to start BalanceDNS: {}", err);
            ExitCode::FAILURE
        }
    }
}
