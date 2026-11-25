use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use boringtun::noise::Tunn;
use x25519_dalek::{PublicKey, StaticSecret};

use super::forwarder::Forwarder;
use super::{Accepted, Metrics, Reason, Verdict, settle};
use crate::config::Config;
use crate::key::PeerKey;
use crate::packet::{IdxPrefix, Mac1Key, Packet, SessionIdx};
use crate::tables::{
    PENDING_TTL, REGISTRY_TTL, RateLimiter, Registry, SESSION_TTL, SessionLimits, SessionTable,
    WorkBudget,
};

mod forward;
mod registration;
mod reload;
#[cfg(test)]
mod tests;
mod timers;

use forward::Indexed;

const SCRATCH_LEN: usize = 65536 + 256;
/// Expiry scans every table, so it runs less often than the tunnel timers.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// Mac1 checks per second for finding forwarded initiations' destinations;
/// separate from registration so a flood of either cannot starve the other.
const FORWARD_WORK_PER_SEC: f64 = 1_000_000.0;
/// Registration work per second from sources that are not a registered
/// peer's address, in mac1 checks: 500 attempts.
const REGISTRATION_WORK_PER_SEC: f64 = 200_000.0;
/// What a registration attempt costs: its X25519 work, measured in mac1 checks.
const REGISTRATION_WORK: usize = 400;
/// Most handshakes one listed peer may have awaiting a response; a new one
/// evicts its oldest, so a flood aimed at one peer only disturbs that peer.
const MAX_PENDING_PER_PEER: usize = 1_024;
/// Most handshakes awaiting a response at once, so a flood of initiations
/// leaves most of the table to open sessions; the forwarding budget keeps
/// floods well below it.
const MAX_PENDING: usize = 262_144;
/// Most entries, pending or open, routed to one listed peer: room for about
/// 16,000 busy sessions (4 entries each), so a listed peer answering spoofed
/// initiations cannot take the whole table.
const MAX_SESSIONS_PER_PEER: usize = 65_536;
/// Most entries in the session table, a memory backstop: 7 × 2^17 is the
/// most a `HashMap` holds in 2^20 buckets of 129 bytes, about 135 MB.
const MAX_SESSIONS: usize = 917_504;

/// What the relay holds for each listed peer.
struct PeerState {
    name: String,
    /// The peer's registration tunnel with the relay.
    tunn: Box<Tunn>,
}

/// The listed peers' mac1 keys in one contiguous list, for batched scans.
#[derive(Default)]
struct Mac1Index {
    peers: Vec<PeerKey>,
    keys: Vec<Mac1Key>,
}

/// The control half: listed peers and their tunnels, the registry, limits,
/// budgets and every session with its lifetime. It decides what the
/// forwarding half hands over and is the forwarding half's only writer.
pub(super) struct Control {
    secret: StaticSecret,
    public: PublicKey,
    relay_mac1: Mac1Key,
    tunnel_ip: Ipv4Addr,
    peers: HashMap<PeerKey, PeerState>,
    mac1: Mac1Index,
    /// Index prefix of each relay tunnel. Forwarded sessions may never use
    /// these (see `reserved`).
    tunn_by_prefix: HashMap<IdxPrefix, PeerKey>,
    /// Where each listed peer last proved it can be reached.
    registry: Registry,
    /// Every session, pending or open: the truth the forwarding half's open
    /// sessions are kept in step with.
    sessions: SessionTable,
    /// What the forwarding half reads. Its open sessions change only through
    /// `sessions`, its reserved prefixes only on reload.
    forwarder: Forwarder,
    limiter: RateLimiter,
    forward_budget: WorkBudget,
    registration_budget: WorkBudget,
    /// What the control half decided, and its own tunnels' output.
    metrics: Metrics,
    /// Datagrams produced by the relay's own tunnels, to be sent by the caller.
    outbox: Vec<(SocketAddr, Vec<u8>)>,
    scratch: Vec<u8>,
    last_sweep: Option<Instant>,
}

impl Control {
    pub(super) fn new(cfg: &Config) -> Self {
        let secret = cfg.private_key.secret().clone();
        let public = PublicKey::from(&secret);
        let sessions = SessionTable::new(
            SESSION_TTL,
            PENDING_TTL,
            SessionLimits {
                pending_per_peer: MAX_PENDING_PER_PEER,
                per_peer: MAX_SESSIONS_PER_PEER,
                total: MAX_SESSIONS,
            },
        );
        let mut control = Control {
            relay_mac1: Mac1Key::new(public.as_bytes()),
            secret,
            public,
            tunnel_ip: cfg.tunnel_ip,
            peers: HashMap::new(),
            mac1: Mac1Index::default(),
            tunn_by_prefix: HashMap::new(),
            registry: Registry::new(REGISTRY_TTL),
            forwarder: Forwarder::new(sessions.new_view()),
            sessions,
            limiter: RateLimiter::new(cfg.handshake_rate.per_sec()),
            forward_budget: WorkBudget::new(FORWARD_WORK_PER_SEC),
            registration_budget: WorkBudget::new(REGISTRATION_WORK_PER_SEC),
            metrics: Metrics::default(),
            outbox: Vec::new(),
            scratch: vec![0; SCRATCH_LEN],
            last_sweep: None,
        };
        control.reload(cfg);
        control
    }

    pub(super) fn forwarder(&self) -> &Forwarder {
        &self.forwarder
    }

    pub(super) fn public_key(&self) -> PeerKey {
        self.public.into()
    }

    pub(super) fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub(super) fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub(super) fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub(super) fn registered_addr(&self, key: &PeerKey, now: Instant) -> Option<SocketAddr> {
        self.registry.addr(key, now)
    }

    pub(super) fn take_outbox(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let out = std::mem::take(&mut self.outbox);
        self.metrics.tunnel_tx += out.len() as u64;
        out
    }

    /// Decide a datagram the forwarding half handed over, counting and logging the outcome.
    pub(super) fn handle(
        &mut self,
        src: SocketAddr,
        pkt: &[u8],
        packet: Packet,
        now: Instant,
    ) -> Verdict {
        let outcome = self.route(src, pkt, packet, now);
        settle(&mut self.metrics, src, outcome)
    }

    fn route(
        &mut self,
        src: SocketAddr,
        pkt: &[u8],
        packet: Packet,
        now: Instant,
    ) -> Result<Accepted, Reason> {
        match packet {
            Packet::Init { sender } => self.initiation(src, pkt, sender, now),
            Packet::Response { sender, receiver } => {
                self.indexed(src, pkt, receiver, Indexed::Response { sender }, now)
            }
            Packet::Cookie { receiver } => self.indexed(src, pkt, receiver, Indexed::Cookie, now),
            Packet::Data { receiver } => self.indexed(src, pkt, receiver, Indexed::Data, now),
        }
    }

    /// Route an initiation: to the relay's own tunnel if its mac1 is for the
    /// relay, otherwise to the listed peer its mac1 names.
    fn initiation(
        &mut self,
        src: SocketAddr,
        pkt: &[u8],
        sender: SessionIdx,
        now: Instant,
    ) -> Result<Accepted, Reason> {
        if !self.limiter.allow(src.ip(), now) {
            return Err(Reason::RateLimited);
        }
        if !self.relay_mac1.matches(pkt) {
            return self.forward_init(src, pkt, sender, now).map(Accepted::Forward);
        }
        self.admit_registration(src, now)?;
        self.register_init(src, pkt, now)
    }

    /// Route a packet by its receiver index: to the relay tunnel that owns the
    /// index, otherwise along the session it names.
    fn indexed(
        &mut self,
        src: SocketAddr,
        pkt: &[u8],
        receiver: SessionIdx,
        kind: Indexed,
        now: Instant,
    ) -> Result<Accepted, Reason> {
        match self.relay_tunnel(receiver) {
            Some(key) => self.tunnel_rx(key, src, pkt, now),
            None => self.forward_on_session(src, receiver, kind, now).map(Accepted::Forward),
        }
    }

    /// The registration tunnel that owns this receiver index, if any.
    fn relay_tunnel(&self, idx: SessionIdx) -> Option<PeerKey> {
        self.tunn_by_prefix.get(&idx.prefix()).copied()
    }

    /// Panic unless the session table's accounts are exact and the forwarding
    /// half holds exactly the open sessions and relay tunnel prefixes this half holds.
    #[cfg(test)]
    fn assert_forwarder_in_step(&self) {
        assert!(self.sessions.accounts_exact(), "session accounts diverged");
        assert!(self.sessions.matches_view(&self.forwarder.open), "open sessions diverged");
        let prefixes: std::collections::HashSet<IdxPrefix> =
            self.tunn_by_prefix.keys().copied().collect();
        assert_eq!(self.forwarder.reserved(), &prefixes, "reserved prefixes diverged");
    }
}
