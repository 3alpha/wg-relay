//! The control half, its `impl` split by topic: dispatch, forwarded
//! handshakes, registration, reload and timers.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boringtun::noise::Tunn;
use x25519_dalek::{PublicKey, StaticSecret};

use super::Metrics;
use super::forwarder::Forwarder;
use crate::config::Config;
use crate::key::PeerKey;
use crate::packet::{Mac1Key, SessionIdx};
use crate::tables::{
    ESTABLISHED_TTL, PENDING_TTL, REGISTRY_TTL, RateLimiter, Registry, SessionLimits, SessionTable,
    WorkBudget,
};

mod dispatch;
mod forward;
mod registration;
mod reload;
#[cfg(test)]
mod tests;
mod timers;

use timers::Cadence;

/// Room for any datagram a registration tunnel decrypts or builds.
const SCRATCH_LEN: usize = 65536 + 256;
/// How often the registration tunnels' timers run. Every forwarding thread
/// offers a tick this often, and the control half takes one per interval.
pub const TICK_INTERVAL: Duration = Duration::from_millis(250);
/// Expiry scans every table, so it runs less often than the registration tunnels' timers.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// Mac1 checks per second spent finding forwarded initiations' destinations.
/// Kept apart from registration so a flood of either cannot starve the other.
const FORWARDING_WORK_PER_SEC: f64 = 1_000_000.0;
/// Registration work per second from sources that are not a registered
/// peer's address, in mac1 checks: 500 attempts.
const REGISTRATION_WORK_PER_SEC: f64 = 200_000.0;
/// What a registration attempt costs: its X25519 work, measured in mac1 checks.
const REGISTRATION_WORK: usize = 400;
/// Most pending sessions one listed peer may have. A new one evicts its
/// oldest, so a flood aimed at one peer only disturbs that peer.
const MAX_PENDING_PER_PEER: usize = 1_024;
/// Most pending sessions at once, so a flood of initiations leaves most of
/// the table to established sessions. The forwarding budget keeps floods well below it.
const MAX_PENDING: usize = 262_144;
/// Most sessions, pending or established, routed to one listed peer: room for about
/// 16,000 busy WireGuard sessions (4 indexes each), so a listed peer answering
/// spoofed initiations cannot take the whole table.
const MAX_SESSIONS_PER_PEER: usize = 65_536;
/// Most sessions in the table, a memory backstop: 7 × 2^17 is the most a
/// `HashMap` holds in 2^20 buckets of 129 bytes, about 135 MB. With every
/// entry established, the forwarding half's copy (about 117 bytes each) brings it to
/// about 240 MB.
const MAX_SESSIONS: usize = 917_504;

/// What the relay holds for each listed peer.
struct PeerState {
    name: String,
    /// The peer's registration tunnel, where the relay is its WireGuard peer.
    tunnel: Box<Tunn>,
}

/// The listed peers' mac1 keys in one contiguous list, for batched scans.
#[derive(Default)]
struct Mac1Index {
    peers: Vec<PeerKey>,
    keys: Vec<Mac1Key>,
}

/// The control half: listed peers and their registration tunnels, the
/// registry, limits, budgets and every session with its lifetime. It decides
/// what the forwarding half hands over and is the forwarding half's only writer.
pub(super) struct Control {
    secret: StaticSecret,
    public: PublicKey,
    /// Matches handshake initiations addressed to the relay itself.
    relay_mac1: Mac1Key,
    tunnel_ip: Ipv4Addr,
    peers: HashMap<PeerKey, PeerState>,
    mac1: Mac1Index,
    /// Where each listed peer last proved it can be reached.
    registry: Registry,
    /// Every session, pending or established: the truth the forwarding half's
    /// established sessions are kept in step with.
    sessions: SessionTable,
    /// What the forwarding half reads. Its established sessions change only
    /// through `sessions`, its reserved prefixes only as registration tunnels
    /// come and go.
    forwarder: Arc<Forwarder>,
    /// Per-source limit on handshake initiations, registration and forwarded alike.
    limiter: RateLimiter,
    forwarding_budget: WorkBudget,
    registration_budget: WorkBudget,
    /// What the control half decided, and the registration tunnels' output.
    metrics: Metrics,
    /// Datagrams the registration tunnels produced, for the caller to send.
    outbox: Vec<(SocketAddr, Vec<u8>)>,
    scratch: Vec<u8>,
    ticks: Cadence,
    sweeps: Cadence,
}

impl Control {
    pub(super) fn new(cfg: &Config) -> Self {
        let secret = cfg.private_key.secret().clone();
        let public = PublicKey::from(&secret);
        let sessions = SessionTable::new(
            PENDING_TTL,
            ESTABLISHED_TTL,
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
            registry: Registry::new(REGISTRY_TTL),
            forwarder: Arc::new(Forwarder::new(sessions.new_view())),
            sessions,
            limiter: RateLimiter::new(cfg.handshake_rate.per_sec()),
            forwarding_budget: WorkBudget::new(FORWARDING_WORK_PER_SEC),
            registration_budget: WorkBudget::new(REGISTRATION_WORK_PER_SEC),
            metrics: Metrics::default(),
            outbox: Vec::new(),
            scratch: vec![0; SCRATCH_LEN],
            ticks: Cadence::new(TICK_INTERVAL),
            sweeps: Cadence::new(SWEEP_INTERVAL),
        };
        control.reload(cfg);
        control
    }

    /// The forwarding half, for the threads that read it without locking this half.
    pub(super) fn forwarder(&self) -> Arc<Forwarder> {
        Arc::clone(&self.forwarder)
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

    /// Find the listed peer whose registration tunnel owns this index, if
    /// it is in a reserved prefix.
    fn tunnel_owner(&self, idx: SessionIdx) -> Option<PeerKey> {
        self.forwarder.reserved.owner(idx)
    }

    /// Panic unless the session table's accounts are exact, the forwarding half
    /// holds exactly its established sessions, and none is in a reserved prefix.
    #[cfg(test)]
    fn assert_forwarder_in_step(&self) {
        assert!(self.sessions.accounts_exact(), "session accounts diverged");
        let view = &self.forwarder.established;
        assert!(self.sessions.matches_view(view), "established sessions diverged");
        // The forwarding half relies on it to look up the reserved prefixes only on a miss.
        let in_reserved =
            self.sessions.established_pairs().any(|(i, ..)| self.tunnel_owner(i).is_some());
        assert!(!in_reserved, "an established session in a reserved prefix");
    }
}
