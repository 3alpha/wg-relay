//! `relay.toml` loading and validation.

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};

pub mod error;
pub use error::{ConfigError, ConfigWarning, KeyError};

pub type Key = [u8; 32];

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
    private_key: String,
    tunnel_ip: Ipv4Addr,
    #[serde(default = "default_gate")]
    client_gate: Gate,
    #[serde(default = "default_rate")]
    handshake_rate_per_ip: String,
    #[serde(default)]
    server: Vec<RawServer>,
    #[serde(default)]
    client: Vec<RawClient>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    name: String,
    pubkey: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClient {
    name: String,
    pubkey: String,
    servers: Vec<String>,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 51820))
}
fn default_gate() -> Gate {
    Gate::Register
}
fn default_rate() -> String {
    "10/s".into()
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub name: String,
    pub pubkey: Key,
    pub role: Role,
    /// For clients: the servers it may reach.
    pub servers: Vec<Key>,
}

#[derive(Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub private_key: Key,
    pub tunnel_ip: Ipv4Addr,
    pub gate: Gate,
    pub rate_per_sec: f64,
    pub peers: Vec<Peer>,
}

pub fn decode_key(s: &str) -> Result<Key, KeyError> {
    let v = STANDARD.decode(s.trim())?;
    <Key>::try_from(v.as_slice()).map_err(|_| KeyError::Length(v.len()))
}

pub fn encode_key(k: &Key) -> String {
    STANDARD.encode(k)
}

/// "10/s", "600/m" or "10" -> events per second.
pub fn parse_rate(s: &str) -> Result<f64, ConfigError> {
    let bad = || ConfigError::Rate { value: s.to_owned() };
    let (n, unit) = s.trim().split_once('/').unwrap_or((s.trim(), "s"));
    let n: f64 = n.trim().parse().map_err(|_| bad())?;
    let div = match unit.trim() {
        "s" => 1.0,
        "m" => 60.0,
        _ => return Err(bad()),
    };
    if n.is_finite() && n > 0.0 { Ok(n / div) } else { Err(bad()) }
}

impl Config {
    /// Read and validate a config file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Self::parse(&std::fs::read_to_string(path)?)
    }

    /// Parse and validate config text.
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(s)?;
        let private_key = decode_key(&raw.private_key).map_err(ConfigError::PrivateKey)?;
        let relay_pub = PublicKey::from(&StaticSecret::from(private_key)).to_bytes();
        let rate_per_sec = parse_rate(&raw.handshake_rate_per_ip)?;
        if raw.server.is_empty() {
            return Err(ConfigError::NoServer);
        }

        let mut peers: Vec<Peer> = Vec::new();
        let (mut names, mut keys) = (HashSet::new(), HashSet::new());
        let servers = raw.server.iter().map(|s| (&s.name, &s.pubkey, Role::Server, None));
        let clients = raw.client.iter().map(|c| (&c.name, &c.pubkey, Role::Client, Some(&c.servers)));
        for (name, pubkey, role, allowed) in servers.chain(clients) {
            let pubkey =
                decode_key(pubkey).map_err(|source| ConfigError::Pubkey { name: name.clone(), source })?;
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
            private_key,
            tunnel_ip: raw.tunnel_ip,
            gate: raw.client_gate,
            rate_per_sec,
            peers,
        })
    }

    pub fn relay_pubkey(&self) -> Key {
        PublicKey::from(&StaticSecret::from(self.private_key)).to_bytes()
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
