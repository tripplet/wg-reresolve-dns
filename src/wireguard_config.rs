use std::{error::Error, fmt::Display, net::SocketAddr, str::FromStr};

use ini::Ini;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Peer {
    pub public_key: String,
    pub endpoint: Endpoint,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum Endpoint {
    Hostname { host: String, port: u16 },
    SocketAddr(SocketAddr),
}

/// Get all peers from a wireguard config file which have a endpoint defined.
pub fn get_peers(config_filepath: &str) -> Result<Vec<Peer>, Box<dyn Error>> {
    let conf = Ini::load_from_file(config_filepath)?;

    conf.iter()
        // Filter for all peers which have a endpoint defined.
        .filter(|(sec, prop)| sec.unwrap_or("") == "Peer" && prop.get("Endpoint").is_some())
        // Map to a Peer struct.
        .map(|(_, prop)| {
            Ok(Peer {
                public_key: prop.get("PublicKey").ok_or("Missing PublicKey")?.to_string(),
                endpoint: prop.get("Endpoint").unwrap().parse()?,
            })
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! peer {
        ($pub_key:expr, $endpoint:expr) => {
            Peer {
                public_key: $pub_key.to_string(),
                endpoint: Endpoint::from_str($endpoint).unwrap(),
            }
        };
    }

    #[test]
    fn invalid_file() {
        assert!(get_peers("test-data/invalid.conf").is_err());
    }

    #[test]
    fn multiple_peers() {
        let endpoints = get_peers("test-data/multiple_peers.conf").unwrap();

        assert_eq!(
            endpoints,
            [
                peer!("1213=", "example.com:51820"),
                peer!("peer2", "example2.com:51820"),
            ]
        );
    }

    #[test]
    fn no_endpoint() {
        let endpoints = get_peers("test-data/no_endpoint.conf").unwrap();
        assert_eq!(endpoints, [peer!("1213=", "example.com:51820")]);
    }
}
