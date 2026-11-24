//! `relay.toml` loading and validation.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use serde::Deserialize;

use crate::key::{PeerKey, PrivateKey};

pub mod error;
mod rate;
pub use error::{ConfigError, ConfigWarning, RateError};
pub use rate::Rate;

/// How strictly clients are admitted before their traffic reaches a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Gate {
    /// Anyone may send initiations to a registered server (rate-limited).
    None,
    /// As `none`, but a server's response only passes if its mac1 names an allowlisted client.
    Response,
    /// Clients register with the relay; only their registered address may initiate.
    Register,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Server,
    Client,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default = "default_listen")]
    listen: SocketAddr,
    private_key: PrivateKey,
    tunnel_ip: Ipv4Addr,
    #[serde(default = "default_gate")]
    client_gate: Gate,
    #[serde(default)]
    handshake_rate_per_ip: Rate,
    #[serde(default)]
    server: Vec<RawServer>,
    #[serde(default)]
    client: Vec<RawClient>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    name: String,
    pubkey: PeerKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClient {
    name: String,
    pubkey: PeerKey,
    servers: Vec<String>,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 51820))
}
fn default_gate() -> Gate {
    Gate::Register
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub name: String,
    pub pubkey: PeerKey,
    pub role: Role,
    /// For clients: the servers it may reach.
    pub servers: Vec<PeerKey>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub private_key: PrivateKey,
    pub tunnel_ip: Ipv4Addr,
    pub gate: Gate,
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
        if raw.server.is_empty() {
            return Err(ConfigError::NoServer);
        }
        let relay_pub = raw.private_key.public_key();
        let mut peers: Vec<Peer> = Vec::new();
        let (mut names, mut keys) = (HashSet::new(), HashSet::new());
        let servers = raw.server.iter().map(|s| (&s.name, s.pubkey, Role::Server, None));
        let clients = raw.client.iter().map(|c| (&c.name, c.pubkey, Role::Client, Some(&c.servers)));
        for (name, pubkey, role, allowed) in servers.chain(clients) {
            if pubkey == relay_pub {
                return Err(ConfigError::RelayKeyReused { name: name.clone() });
            }
            if !keys.insert(pubkey) {
                return Err(ConfigError::DuplicatePubkey { name: name.clone() });
            }
            if !names.insert(name.clone()) {
                return Err(ConfigError::DuplicateName { name: name.clone() });
            }
            let servers = allowed
                .into_iter()
                .flatten()
                .map(|s| {
                    peers
                        .iter()
                        .find(|p| p.role == Role::Server && &p.name == s)
                        .map(|p| p.pubkey)
                        .ok_or_else(|| ConfigError::UnknownServer { client: name.clone(), server: s.clone() })
                })
                .collect::<Result<_, _>>()?;
            peers.push(Peer { name: name.clone(), pubkey, role, servers });
        }
        Ok(Config {
            listen: raw.listen,
            private_key: raw.private_key,
            tunnel_ip: raw.tunnel_ip,
            gate: raw.client_gate,
            handshake_rate: raw.handshake_rate_per_ip,
            peers,
        })
    }

    /// List valid but probably unintended settings.
    pub fn warnings(&self) -> Vec<ConfigWarning> {
        let clients = self.peers.iter().filter(|p| p.role == Role::Client);
        let mut w = Vec::new();
        if self.gate != Gate::None && clients.clone().next().is_none() {
            w.push(ConfigWarning::NoClients { gate: self.gate });
        }
        w.extend(
            clients
                .filter(|c| c.servers.is_empty())
                .map(|c| ConfigWarning::ClientWithoutServers { name: c.name.clone() }),
        );
        w
    }
}
