use std::{error::Error, fmt, fmt::Display, net::SocketAddr, net::ToSocketAddrs, str::FromStr};

use super::Args;

use base64::{engine::general_purpose, Engine as _};
use ini::Ini;
use wireguard_uapi::linux::set::{Device, Peer, WgPeerF};
use wireguard_uapi::{DeviceInterface, WgSocket};

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct CfgPeer {
    pub public_key: String,
    pub endpoint: Endpoint,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum Endpoint {
    Hostname { host: String, port: u16 },
    SocketAddr(SocketAddr),
}

#[derive(Debug)]
pub enum UpdateError {
    ConfigFileError(String),
    MissingWireguardInterface(String),
    InvalidPublicKey(String),
    ErrorSettingDevice(String),
}

impl Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for UpdateError {}

/// Get all peers from a wireguard config file which have a endpoint defined.
pub fn get_cfg_peers(config_filepath: &str) -> Result<Vec<CfgPeer>, Box<dyn Error>> {
    let conf = Ini::load_from_file(config_filepath)?;

    conf.iter()
        // Filter for all peers which have a endpoint defined.
        .filter(|(sec, prop)| sec.unwrap_or("") == "Peer" && prop.get("Endpoint").is_some())
        // Map to a Peer struct.
        .map(|(_, prop)| {
            Ok(CfgPeer {
                public_key: prop.get("PublicKey").ok_or("Missing PublicKey")?.to_string(),
                endpoint: prop.get("Endpoint").unwrap().parse()?,
            })
        })
        .collect()
}

pub fn update_endpoints(wg: &mut WgSocket, cfg: &Args) -> Result<(), UpdateError> {
    // Try get the device
    // This is done for every check as the device might me unavailable
    // if the wireguard interface is down temporarily
    let device = match wg.get_device(DeviceInterface::from_name(&cfg.wireguard_interface)) {
        Err(err) => {
            return Err(UpdateError::MissingWireguardInterface(format!(
                "Unable to get wireguard interface {}: {err}",
                &cfg.wireguard_interface
            )));
        }
        Ok(dev) => dev,
    };

    // Re-read the wireguard config because it might have been changed while sleeping
    // + filter out peers to have only the ones with a hostname defined
    let peers = get_cfg_peers(&format!("{}{}.conf", cfg.directory, cfg.wireguard_interface))
        .map_err(|e| UpdateError::ConfigFileError(format!("Unable to read config file: {e}")))?
        .into_iter()
        .filter(|peer| matches!(peer.endpoint, Endpoint::Hostname { .. }));

    let mut peer_updates: Vec<([u8; 32], std::net::SocketAddr)> = vec![];

    // Collect data to update peers
    for peer in peers {
        let raw_public_key = peer.get_raw_public_key()?;

        // Find matching peer in active interface
        if let Some(active_peer) = device.peers.iter().find(|&p| p.public_key == raw_public_key) {
            // Resolve the endpoint address
            match peer.endpoint.resolve() {
                Err(err) => {
                    log::warn!("Unable to resolve endpoint '{}': {err}", &peer.endpoint);
                    continue;
                }
                Ok(new_endpoint) => {
                    // Check if the endpoint address has changed
                    if active_peer.endpoint.unwrap() == new_endpoint {
                        log::info!("Endpoint for peer {} not changed", &peer.public_key);
                        continue;
                    }

                    peer_updates.push((raw_public_key, new_endpoint));
                }
            }
        } else {
            log::warn!("Peer {} not found in active interface", &peer.public_key);
        }
    }

    if peer_updates.is_empty() {
        return Ok(());
    }

    // Build the update struct for updating the endpoints
    let mut device_update = Device::from_ifname(&cfg.wireguard_interface);

    for peer in peer_updates.iter() {
        let mut peer_update = Peer::from_public_key(&peer.0);
        peer_update.flags.push(WgPeerF::UpdateOnly);
        peer_update.endpoint = Some(&peer.1);

        device_update.peers.push(peer_update);
    }

    // Update the peer endpoints
    wg.set_device(device_update)
        .map_err(|e| UpdateError::ErrorSettingDevice(format!("{e:#}")))?;
    Ok(())
}

impl CfgPeer {
    /// Get the publiy key as raw slice
    pub fn get_raw_public_key(&self) -> Result<[u8; 32], UpdateError> {
        match general_purpose::STANDARD.decode(&self.public_key) {
            Err(err) => Err(UpdateError::InvalidPublicKey(format!(
                "Unable to parse wireguard public key: {err}"
            ))),
            Ok(vec) => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&vec);
                Ok(key)
            }
        }
    }
}

impl FromStr for Endpoint {
    type Err = Box<dyn Error>;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = input.parse::<SocketAddr>() {
            // Try parsing into SocketAddr first
            Ok(Endpoint::SocketAddr(addr))
        } else {
            let parts = input
                .split_once(':')
                .ok_or_else(|| format!("Invalid endpoint: {input}"))?;
            Ok(Endpoint::Hostname {
                host: parts.0.to_string(),
                port: parts.1.parse()?,
            })
        }
    }
}

impl Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::Hostname { host, port } => write!(f, "{}:{}", host, port),
            Endpoint::SocketAddr(addr) => write!(f, "{}", addr),
        }
    }
}

impl Endpoint {
    pub fn resolve(&self) -> Result<SocketAddr, Box<dyn Error>> {
        match self {
            Endpoint::SocketAddr(s) => Ok(*s),
            Endpoint::Hostname { .. } => format!("{}", self)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| "Unable to resolve endoint address".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! peer {
        ($pub_key:expr, $endpoint:expr) => {
            CfgPeer {
                public_key: $pub_key.to_string(),
                endpoint: Endpoint::from_str($endpoint).unwrap(),
            }
        };
    }

    #[test]
    fn invalid_file() {
        assert!(get_cfg_peers("test-data/invalid.conf").is_err());
    }

    #[test]
    fn raw_key() {
        let endpoints = get_cfg_peers("test-data/multiple_peers.conf").unwrap();

        assert_eq!(
            endpoints[0].get_raw_public_key().unwrap(),
            [
                112, 196, 234, 101, 88, 72, 28, 170, 120, 133, 247, 77, 161, 77, 92, 89, 216, 186, 31, 234, 205, 19,
                51, 85, 67, 252, 248, 138, 193, 194, 78, 98
            ]
        );
        assert_eq!(
            endpoints[1].get_raw_public_key().unwrap(),
            [
                208, 233, 177, 169, 89, 247, 101, 102, 224, 12, 199, 150, 190, 132, 253, 203, 122, 185, 139, 164, 133,
                187, 165, 156, 16, 234, 135, 203, 244, 251, 139, 115
            ]
        );
    }

    #[test]
    fn multiple_peers() {
        let endpoints = get_cfg_peers("test-data/multiple_peers.conf").unwrap();

        assert_eq!(
            endpoints,
            [
                peer!("cMTqZVhIHKp4hfdNoU1cWdi6H+rNEzNVQ/z4isHCTmI=", "example.com:51820"),
                peer!("0OmxqVn3ZWbgDMeWvoT9y3q5i6SFu6WcEOqHy/T7i3M=", "example2.com:51820"),
            ]
        );
    }

    #[test]
    fn no_endpoint() {
        let endpoints = get_cfg_peers("test-data/no_endpoint.conf").unwrap();
        assert_eq!(endpoints, [peer!("1213=", "example.com:51820")]);
    }
}
