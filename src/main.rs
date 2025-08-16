mod networkd;
mod wireguard_api;
mod wireguard_config;

use std::{error::Error, process::ExitCode, thread::sleep, time::Duration};

//use anyhow::{Context, Result};
use clap::Parser;
use log::LevelFilter;
use simple_logger::SimpleLogger;

use wireguard_api::{Client, UpdateError};

// The main config
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// The wireguard interfaces to use if endswith with -netdev then it is a networkd config file
    #[clap()]
    wireguard_interfaces: Vec<String>,

    /// Directory of wireguard configs
    #[clap(long, env, default_value("/etc/wireguard/"))]
    wireguard_directory: String,

    /// Directory of wireguard configs
    #[clap(long, env, default_value("/etc/systemd/network/"))]
    networkd_directory: String,

    /// Interval to check/update the endoints, with units 'ms', 's', 'm', 'h', e.g. 5m30s
    #[clap(long, env, default_value("5m"), value_parser = humantime::parse_duration)]
    interval: Duration,

    /// Enable verbose output
    #[clap(short, long, env)]
    verbose: bool,
}

fn main() -> ExitCode {
    let mut cfg = Args::parse(); // Parse arguments

    // Initialize logger
    SimpleLogger::new().init().unwrap();
    if cfg.verbose {
        log::set_max_level(LevelFilter::Debug);
    } else {
        log::set_max_level(LevelFilter::Warn);
    }

    log::debug!("Config: {cfg:?}");

    if cfg.wireguard_interfaces.is_empty()
        && let Ok(mut route_socket) = wireguard_uapi::RouteSocket::connect()
        && let Ok(wg_interfaces) = route_socket.list_device_names()
    {
        log::info!("No wireguard interfaces specified, using all available interfaces: {wg_interfaces:?}");
        cfg.wireguard_interfaces = wg_interfaces;
    }

    if cfg.wireguard_interfaces.is_empty() {
        log::error!("No wireguard interfaces specified, exiting.");
        return ExitCode::FAILURE;
    }

    // Run the endless loop
    let error = run_loop(&cfg);
    log::error!("{}", error.unwrap_err());
    ExitCode::FAILURE
}

fn run_loop(cfg: &Args) -> Result<(), Box<dyn Error>> {
    let mut wg = Client::connect()?;

    // If any networkd devices are used, build a map of networkd devices to wireguard devices
    let networkd_devices = if cfg.wireguard_interfaces.iter().any(|iface| iface.ends_with("-netdev")) {
        Some(networkd::get_networkd_devices(&cfg.networkd_directory))
    } else {
        None
    };

    let interface_list: Vec<_> = cfg
        .wireguard_interfaces
        .iter()
        .filter_map(|iface| {
            if let Some(iface) = iface.strip_suffix("-netdev") {
                // Find the corresponding networkd file
                let Some(device_config_file) = networkd_devices.as_ref().and_then(|dev_map| dev_map.get(iface)) else {
                    log::error!("Unable to find device config file for networkd {iface}");
                    return None;
                };

                Some((iface, device_config_file.clone()))
            } else {
                Some((iface, format!("{}{iface}.conf", cfg.wireguard_directory)))
            }
        })
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
