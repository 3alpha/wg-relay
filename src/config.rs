//! `relay.toml` loading and validation.

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};

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

pub fn decode_key(s: &str) -> Result<Key, String> {
    let v = STANDARD.decode(s.trim()).map_err(|e| format!("invalid base64 key: {e}"))?;
    <Key>::try_from(v.as_slice()).map_err(|_| format!("key must be 32 bytes, got {}", v.len()))
}

pub fn encode_key(k: &Key) -> String {
    STANDARD.encode(k)
}

/// "10/s", "600/m" or "10" -> events per second.
pub fn parse_rate(s: &str) -> Result<f64, String> {
    let (n, unit) = s.trim().split_once('/').unwrap_or((s.trim(), "s"));
    let n: f64 = n.trim().parse().map_err(|_| format!("bad rate {s:?}"))?;
    let div = match unit.trim() {
        "s" => 1.0,
        "m" => 60.0,
        _ => return Err(format!("bad rate unit in {s:?} (use /s or /m)")),
    };
    if n.is_finite() && n > 0.0 { Ok(n / div) } else { Err(format!("rate must be positive: {s:?}")) }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let s = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&s)
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        let raw: RawConfig = toml::from_str(s).map_err(|e| e.to_string())?;
        let private_key = decode_key(&raw.private_key).map_err(|e| format!("private_key: {e}"))?;
        let relay_pub = PublicKey::from(&StaticSecret::from(private_key)).to_bytes();
        let rate_per_sec = parse_rate(&raw.handshake_rate_per_ip)?;
        if raw.server.is_empty() {
            return Err("at least one [[server]] is required".into());
        }

        let mut peers: Vec<Peer> = Vec::new();
        let (mut names, mut keys) = (HashSet::new(), HashSet::new());
        let servers = raw.server.iter().map(|s| (&s.name, &s.pubkey, Role::Server, None));
        let clients = raw.client.iter().map(|c| (&c.name, &c.pubkey, Role::Client, Some(&c.servers)));
        for (name, pubkey, role, allowed) in servers.chain(clients) {
            let pubkey = decode_key(pubkey).map_err(|e| format!("{name}: {e}"))?;
            if pubkey == relay_pub {
                return Err(format!("{name}: pubkey equals the relay's own key"));
            }
            if !keys.insert(pubkey) {
                return Err(format!("{name}: duplicate pubkey"));
            }
            if !names.insert(name.clone()) {
                return Err(format!("duplicate name {name}"));
            }
            let servers = allowed
                .into_iter()
                .flatten()
                .map(|s| {
                    peers
                        .iter()
                        .find(|p| p.role == Role::Server && &p.name == s)
                        .map(|p| p.pubkey)
                        .ok_or_else(|| format!("client {name}: unknown server {s:?}"))
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

    /// Valid but probably unintended settings.
    pub fn warnings(&self) -> Vec<String> {
        let clients = self.peers.iter().filter(|p| p.role == Role::Client);
        let mut w = Vec::new();
        if self.gate != Gate::None && clients.clone().next().is_none() {
            w.push(format!("client_gate = {:?} but no [[client]] entries: no client can connect", self.gate));
        }
        for c in clients.filter(|c| c.servers.is_empty()) {
            w.push(format!("client {} may not reach any server", c.name));
        }
        w
    }
}
