use std::error::Error;
use std::fmt::{self, Display};

#[derive(Debug)]
#[allow(dead_code)]
pub enum UpdateError {
    ConfigFileError(String),
    MissingWireguardInterface(String),
    InvalidPublicKey(String),
    ErrorSettingDevice(String),
}

pub struct Client(wireguard_uapi::WgSocket);

impl Client {
    pub fn connect() -> Result<Self, Box<dyn Error>> {
        let wg = wireguard_uapi::WgSocket::connect()?;
        Ok(Client(wg))
    }

    pub fn update_endpoints(&mut self, interface_name: &str, config_file: &str) -> Result<(), UpdateError> {
        use wireguard_uapi::DeviceInterface;
        use wireguard_uapi::linux::set::{Device, Peer, WgPeerF};

        use crate::wireguard_config::{Endpoint, get_cfg_peers};

        // Try get the device
        // This is done for every check as the device might me unavailable
        // if the wireguard interface is down temporarily
        let device = match self.0.get_device(DeviceInterface::from_name(interface_name)) {
            Err(err) => {
                return Err(UpdateError::MissingWireguardInterface(format!(
                    "Unable to get wireguard interface {interface_name}: {err}"
                )));
            }
            Ok(dev) => dev,
        };

        // Re-read the wireguard config because it might have been changed while sleeping
        // + filter out peers to have only the ones with a hostname defined
        let peers = get_cfg_peers(config_file)
            .map_err(|e| UpdateError::ConfigFileError(format!("Unable to read config file: {e}")))?
            .into_iter()
            .filter(|peer| matches!(peer.endpoint, Endpoint::Hostname { .. }));

        let mut peer_updates: Vec<([u8; 32], std::net::SocketAddr)> = vec![];

        // Collect data to update peers
        for peer in peers {
            let raw_public_key = peer.get_raw_public_key().map_err(UpdateError::InvalidPublicKey)?;

            // Find matching peer in active interface
            if let Some(active_peer) = device.peers.iter().find(|&p| p.public_key == raw_public_key) {
                // Resolve the endpoint address
                match peer.endpoint.resolve() {
                    Err(err) => {
                        log::warn!("Unable to resolve endpoint '{}': {err}", &peer.endpoint);
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
        let mut device_update = Device::from_ifname(interface_name);

        for peer in &peer_updates {
            let mut peer_update = Peer::from_public_key(&peer.0);
            peer_update.flags.push(WgPeerF::UpdateOnly);
            peer_update.endpoint = Some(&peer.1);

            device_update.peers.push(peer_update);
        }

        // Update the peer endpoints
        self.0
            .set_device(device_update)
            .map_err(|e| UpdateError::ErrorSettingDevice(format!("{e:#}")))?;
        Ok(())
    }
}

impl Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for UpdateError {}
