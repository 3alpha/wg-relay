//! `relay.toml` loading and validation.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use serde::Deserialize;

use crate::key::{PeerKey, PrivateKey};

pub mod error;
mod rate;
mod summary;
pub use error::{ConfigError, RateError};
pub use rate::Rate;
pub use summary::Summary;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default = "default_listen")]
    listen: SocketAddr,
    private_key: PrivateKey,
    #[serde(default = "default_tunnel_ip")]
    tunnel_ip: Ipv4Addr,
    #[serde(default)]
    handshake_rate_per_ip: Rate,
    #[serde(default)]
    peer: Vec<Peer>,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 51820))
}

fn default_tunnel_ip() -> Ipv4Addr {
    Ipv4Addr::new(10, 99, 0, 254)
}

/// A listed peer: it registers with the relay, and anyone may handshake with it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub name: String,
    pub pubkey: PeerKey,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub private_key: PrivateKey,
    pub tunnel_ip: Ipv4Addr,
    pub handshake_rate: Rate,
    pub peers: Vec<Peer>,
}

impl Config {
    /// Read and validate a config file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Self::parse(&std::fs::read_to_string(path)?)
    }

    /// Parse and validate config text.
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(s)?;
        if raw.peer.is_empty() {
            return Err(ConfigError::NoPeer);
        }
        let relay_pub = raw.private_key.public_key();
        let (mut names, mut keys) = (HashSet::new(), HashSet::new());
        for p in &raw.peer {
            if p.pubkey == relay_pub {
                return Err(ConfigError::RelayKeyReused { name: p.name.clone() });
            }
            if !keys.insert(p.pubkey) {
                return Err(ConfigError::DuplicatePubkey { name: p.name.clone() });
            }
            if !names.insert(&p.name) {
                return Err(ConfigError::DuplicateName { name: p.name.clone() });
            }
        }
        Ok(Config {
            listen: raw.listen,
            private_key: raw.private_key,
            tunnel_ip: raw.tunnel_ip,
            handshake_rate: raw.handshake_rate_per_ip,
            peers: raw.peer,
        })
    }

    /// Summarise the effective config for humans.
    pub fn summary(&self) -> Summary<'_> {
        Summary(self)
    }
}
