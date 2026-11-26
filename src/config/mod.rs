//! `relay.toml` loading and validation.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::Path;

use serde::Deserialize;

use crate::key::{PrivateKey, PublicKey};

pub mod error;
mod rate;
mod summary;
pub use error::{ConfigError, RateError};
pub use rate::Rate;
pub use summary::Summary;

/// Most forwarding workers: far beyond the cores one socket's traffic can use.
pub const MAX_WORKERS: usize = 256;

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
    #[serde(default = "default_workers")]
    workers: usize,
    #[serde(default)]
    peer: Vec<Peer>,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 51820))
}

fn default_tunnel_ip() -> Ipv4Addr {
    Ipv4Addr::new(10, 99, 0, 254)
}

/// One forwarding worker per core the process may use, up to `MAX_WORKERS`.
fn default_workers() -> usize {
    std::thread::available_parallelism().map_or(1, NonZeroUsize::get).min(MAX_WORKERS)
}

/// Check a configured worker count against `1..=MAX_WORKERS`.
fn parse_workers(n: usize) -> Result<NonZeroUsize, ConfigError> {
    NonZeroUsize::new(n)
        .filter(|n| n.get() <= MAX_WORKERS)
        .ok_or(ConfigError::Workers { got: n, max: MAX_WORKERS })
}

/// A configured peer: it registers with the relay, and anyone may handshake with it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub name: String,
    pub pubkey: PublicKey,
}

/// The validated contents of `relay.toml`.
#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub private_key: PrivateKey,
    pub tunnel_ip: Ipv4Addr,
    pub handshake_rate: Rate,
    /// Forwarding worker threads, each with its own socket.
    pub workers: NonZeroUsize,
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
        let workers = parse_workers(raw.workers)?;
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
            workers,
            peers: raw.peer,
        })
    }

    /// Summarise the effective config for humans.
    pub fn summary(&self) -> Summary<'_> {
        Summary(self)
    }
}
