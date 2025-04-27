mod wireguard_api;
mod wireguard_config;

use std::{error::Error, thread::sleep, time::Duration};

//use anyhow::{Context, Result};
use clap::Parser;
use log::LevelFilter;
use simple_logger::SimpleLogger;

use wireguard_api::{Client, UpdateError};

// The main config
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// The wireguard interfaces to use
    #[clap()]
    wireguard_interfaces: Vec<String>,

    /// Directory of wireguard configs
    #[clap(long, env, default_value("/etc/wireguard/"))]
    directory: String,

    /// Interval to check/update the endoints, with units 'ms', 's', 'm', 'h', e.g. 5m30s
    #[clap(long, env, default_value("5m"), value_parser = humantime::parse_duration)]
    interval: Duration,

    /// Enable verbose output
    #[clap(short, long, env)]
    verbose: bool,
}

fn main() {
    let cfg = Args::parse(); // Parse arguments

    // Initialize logger
    SimpleLogger::new().init().unwrap();
    if cfg.verbose {
        log::set_max_level(LevelFilter::Debug);
    } else {
        log::set_max_level(LevelFilter::Warn);
    }

    log::debug!("Config: {cfg:?}");

    // Run the endless loop
    let error = run_loop(&cfg);
    log::error!("{}", error.unwrap_err());
}

fn run_loop(cfg: &Args) -> Result<(), Box<dyn Error>> {
    let mut wg = Client::connect()?;

    let interface_list: Vec<_> = cfg
        .wireguard_interfaces
        .iter()
        .map(|iface| (iface, format!("{}{iface}.conf", cfg.directory)))
        .collect();

    loop {
        log::info!("Checking endpoints");

        for (interface, file) in &interface_list {
            let res = wg.update_endpoints(interface, file);

            match res {
                Err(
                    UpdateError::ConfigFileError(..)
                    | UpdateError::ErrorSettingDevice(..)
                    | UpdateError::InvalidPublicKey(..),
                ) => {
                    // Exit loop/program in case of critical errors
                    return Err(Box::new(res.unwrap_err()));
                }
                Err(e) => {
                    // Log all other errors as warnings
                    log::warn!("{e}");
                }
                Ok(()) => {}
            }
        }

        sleep(cfg.interval);
    }
}
