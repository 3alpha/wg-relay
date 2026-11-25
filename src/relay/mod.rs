//! The relay state machine: registration tunnels plus opaque forwarding.
//!
//! `Relay::handle` does no I/O: it returns a `Verdict` for the datagram and
//! queues the relay's own tunnel output for `take_outbox`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use tracing::{debug, info};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::Config;
use crate::key::PeerKey;
use crate::packet::{self, IdxPrefix, Mac1Key, Packet, SessionIdx};
use crate::tables::{PENDING_TTL, REGISTRY_TTL, RateLimiter, Registry, SESSION_TTL, SessionTable};

mod forward;
mod metrics;
mod reason;
mod registration;
mod reload;

use forward::Indexed;
pub use metrics::Metrics;
pub use reason::{Reason, Verdict};

const SCRATCH_LEN: usize = 65536 + 256;
/// Expiry scans every table, so it runs less often than the tunnel timers.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// What the relay holds for each listed peer.
struct PeerState {
    name: String,
    mac1: Mac1Key,
    /// The peer's registration tunnel with the relay.
    tunn: Box<Tunn>,
}

pub struct Relay {
    secret: StaticSecret,
    public: PublicKey,
    relay_mac1: Mac1Key,
    tunnel_ip: Ipv4Addr,
    peers: HashMap<PeerKey, PeerState>,
    /// Index prefix of each relay tunnel. Forwarded sessions may never use
    /// these (see `reserved`).
    tunn_by_prefix: HashMap<IdxPrefix, PeerKey>,
    /// Where each listed peer last proved it can be reached.
    registry: Registry,
    sessions: SessionTable,
    limiter: RateLimiter,
    metrics: Metrics,
    /// Datagrams produced by the relay's own tunnels, to be sent by the caller.
    outbox: Vec<(SocketAddr, Vec<u8>)>,
    scratch: Vec<u8>,
    last_sweep: Option<Instant>,
}

impl Relay {
    pub fn new(cfg: &Config) -> Self {
        let secret = cfg.private_key.secret().clone();
        let public = PublicKey::from(&secret);
        let mut relay = Relay {
            relay_mac1: packet::mac1_key(public.as_bytes()),
            secret,
            public,
            tunnel_ip: cfg.tunnel_ip,
            peers: HashMap::new(),
            tunn_by_prefix: HashMap::new(),
            registry: Registry::new(REGISTRY_TTL),
            sessions: SessionTable::new(SESSION_TTL, PENDING_TTL),
            limiter: RateLimiter::new(cfg.handshake_rate.per_sec()),
            metrics: Metrics::default(),
            outbox: Vec::new(),
            scratch: vec![0; SCRATCH_LEN],
            last_sweep: None,
        };
        relay.reload(cfg);
        relay
    }

    pub fn public_key(&self) -> PeerKey {
        self.public.into()
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Where `key` is currently registered, if anywhere.
    pub fn registered_addr(&self, key: &PeerKey, now: Instant) -> Option<SocketAddr> {
        self.registry.addr(key, now)
    }

    /// Hand over the datagrams the relay's own tunnels want to send.
    pub fn take_outbox(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let out = std::mem::take(&mut self.outbox);
        self.metrics.tunnel_tx += out.len() as u64;
        out
    }

    /// Count a datagram the caller failed to send.
    pub fn record_send_error(&mut self) {
        self.metrics.send_errors += 1;
    }

    /// Process one datagram, counting and logging the outcome.
    pub fn handle(&mut self, src: SocketAddr, pkt: &[u8], now: Instant) -> Verdict {
        let verdict = self.route(src, pkt, now);
        self.metrics.record(verdict);
        if let Verdict::Drop(reason) = verdict {
            debug!(%reason, %src, "reject");
        }
        verdict
    }

    fn route(&mut self, src: SocketAddr, pkt: &[u8], now: Instant) -> Verdict {
        let Ok(p) = packet::parse(pkt) else { return Verdict::Drop(Reason::Malformed) };
        match p {
            Packet::Init { .. } if !self.limiter.allow(src.ip(), now) => {
                Verdict::Drop(Reason::RateLimited)
            }
            Packet::Init { .. } if packet::mac1_matches(&self.relay_mac1, pkt) => {
                self.register_init(src, pkt, now)
            }
            Packet::Init { sender } => self.forward_init(src, pkt, sender, now).into(),
            Packet::Response { receiver, .. }
            | Packet::Cookie { receiver }
            | Packet::Data { receiver }
                if let Some(k) = self.relay_tunnel(receiver) =>
            {
                self.tunnel_rx(k, src, pkt, now)
            }
            Packet::Response { sender, receiver } => {
                self.forward_response(src, sender, receiver, now).into()
            }
            Packet::Cookie { receiver } => {
                self.forward_indexed(src, Indexed::Cookie, receiver, now).into()
            }
            Packet::Data { receiver } => {
                self.forward_indexed(src, Indexed::Data, receiver, now).into()
            }
        }
    }

    /// Run relay tunnel timers and expire soft state. Call a few times a second.
    pub fn tick(&mut self, now: Instant) {
        for (key, peer) in &mut self.peers {
            let TunnResult::WriteToNetwork(out) = peer.tunn.update_timers(&mut self.scratch) else {
                continue;
            };
            if let Some(addr) = self.registry.addr(key, now) {
                self.outbox.push((addr, out.to_vec()));
            }
        }
        let swept_recently =
            self.last_sweep.is_some_and(|t| now.saturating_duration_since(t) < SWEEP_INTERVAL);
        if swept_recently {
            return;
        }
        self.last_sweep = Some(now);
        for k in self.registry.expire(now) {
            info!(peer = %self.peers.get(&k).map_or("?", |p| &p.name), "registration expired");
        }
        let gone = self.sessions.expire(now);
        if gone > 0 {
            debug!(gone, live = self.sessions.len(), "expired sessions");
        }
        self.limiter.prune(now);
    }

    fn reserved(&self, idx: SessionIdx) -> bool {
        self.tunn_by_prefix.contains_key(&idx.prefix())
    }

    /// The registration tunnel that owns this receiver index, if any.
    fn relay_tunnel(&self, idx: SessionIdx) -> Option<PeerKey> {
        self.tunn_by_prefix.get(&idx.prefix()).copied()
    }

    /// Find the listed peer whose key the packet's mac1 was made for.
    fn mac1_peer(&self, pkt: &[u8]) -> Option<PeerKey> {
        self.peers.iter().find(|(_, p)| packet::mac1_matches(&p.mac1, pkt)).map(|(k, _)| *k)
    }
}
