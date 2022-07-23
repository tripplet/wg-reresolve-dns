mod wireguard_config;

use std::{process::Command, thread::sleep, time::Duration};

use clap::Parser;
use log::LevelFilter;
use simple_logger::SimpleLogger;

use crate::wireguard_config::{get_peers, Endpoint};

// The main config
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// The wireguard interface to use
    #[clap()]
    wireguard_interface: String,

    /// Interval to check/update the endoints, with units 'ms', 's', 'm', 'h', e.g. 5m30s
    #[clap(long, env, default_value("5m"), parse(try_from_str = humantime::parse_duration))]
    interval: Duration,

    /// Enable verbose output
    #[clap(short, long)]
    verbose: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Args::parse(); // Parse arguments

    // Initialize logger
    SimpleLogger::new().init().unwrap();
    if cfg.verbose {
        log::set_max_level(LevelFilter::Debug);
    } else {
        log::set_max_level(LevelFilter::Warn);
    }

    log::debug!("Config: {:?}", cfg);
    run_loop(&cfg)
}

fn run_loop(cfg: &Args) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        log::info!("Checking endpoints");

        // Re-read the wireguard config because it might have been changed while sleeping
        // + filter out peers to have only the ones with a hostname defined
        let peers = get_peers(&format!("/etc/wireguard/{}.conf", cfg.wireguard_interface))?
            .into_iter()
            .filter(|peer| matches!(peer.endpoint, Endpoint::Hostname { .. }));

        // Update all peers
        for peer in peers {
            let result = Command::new("/usr/bin/wg")
                .arg("set")
                .arg(&cfg.wireguard_interface)
                .arg("peer")
                .arg(&peer.public_key)
                .arg("endpoint")
                .arg(format!("{}", peer.endpoint))
                .output()?;

            log::info!("Update of {pub_key}: {result:?}", pub_key = &peer.public_key);
        }

        sleep(cfg.interval);
    }
}
