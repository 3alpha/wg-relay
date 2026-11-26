//! The control plane, its `impl` split by topic: dispatch, forwarded
//! handshakes, registration, reload and timers.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boringtun::noise::Tunn;
use x25519_dalek::StaticSecret;

use super::data_plane::DataPlane;
use super::{ControlMetrics, Metrics};
use crate::config::Config;
use crate::key::PublicKey;
use crate::message::{Mac1Key, SessionIndex};
use crate::tables::{
    ESTABLISHED_TIMEOUT, PENDING_TIMEOUT, REGISTRATION_TIMEOUT, RateLimiter, Registry,
    SessionLimits, SessionTable, WorkBudget,
};

mod dispatch;
mod forward;
mod registration;
mod reload;
mod snapshot;
#[cfg(test)]
mod tests;
mod timers;

pub use snapshot::LIMITS;

use timers::Throttle;

/// Room for any datagram a registration tunnel decrypts or builds.
const SCRATCH_BUFFER_LEN: usize = 65536 + 256;
/// How often the registration tunnels' timers run. Every forwarding thread
/// offers a tick this often, and the control plane takes one per interval.
pub const TICK_INTERVAL: Duration = Duration::from_millis(250);
/// Garbage collection scans every table, so it runs less often than the tunnels' timers.
const GC_INTERVAL: Duration = Duration::from_secs(1);
/// Mac1 checks per second spent finding forwarded initiations' destinations.
/// Kept apart from registration so a flood of either cannot starve the other.
const FORWARDING_WORK_PER_SEC: f64 = 1_000_000.0;
/// Registration work per second from sources that are not a registered
/// peer's address, in mac1 checks: 500 attempts.
const REGISTRATION_WORK_PER_SEC: f64 = 200_000.0;
/// What a registration attempt costs: its X25519 work, measured in mac1 checks.
const REGISTRATION_WORK: usize = 400;
/// Most pending sessions one configured peer may have. A new one evicts its
/// oldest, so a flood aimed at one peer only disturbs that peer.
const MAX_PENDING_PER_PEER: usize = 1_024;
/// Most pending sessions at once, so a flood of initiations leaves most of
/// the table to established sessions. The forwarding budget keeps floods well below it.
const MAX_PENDING: usize = 262_144;
/// Most sessions, pending or established, routed to one configured peer: room for about
/// 16,000 busy WireGuard sessions (4 indexes each), so a configured peer answering
/// spoofed initiations cannot take the whole table.
const MAX_SESSIONS_PER_PEER: usize = 65_536;
/// Most sessions in the table, a memory backstop: 7 × 2^17 is the most a
/// `HashMap` holds in 2^20 buckets of 129 bytes, about 135 MB. With every
/// entry established, the data plane's copy (about 117 bytes each) brings it to
/// about 240 MB.
const MAX_SESSIONS: usize = 917_504;

/// What the relay holds for each configured peer.
struct PeerState {
    name: String,
    /// The peer's registration tunnel, where the relay is its WireGuard peer.
    tunnel: Box<Tunn>,
    /// Forwarded initiations sent to this peer since it was configured.
    initiations_forwarded: u64,
    /// Initiations whose mac1 named this peer but were dropped after the scan.
    initiations_dropped: u64,
}

/// The configured peers' mac1 keys in one contiguous list, for batched scans.
#[derive(Default)]
struct Mac1Table {
    peers: Vec<PublicKey>,
    keys: Vec<Mac1Key>,
}

/// The control plane: configured peers and their registration tunnels, the
/// registry, limits, budgets and every session with its lifetime. It decides
/// what the data plane hands over and is the data plane's only writer.
pub(super) struct ControlPlane {
    secret: StaticSecret,
    public: x25519_dalek::PublicKey,
    /// Matches handshake initiations addressed to the relay itself.
    relay_mac1: Mac1Key,
    tunnel_ip: Ipv4Addr,
    peers: HashMap<PublicKey, PeerState>,
    mac1: Mac1Table,
    /// Where each configured peer last proved it can be reached.
    registry: Registry,
    /// Every session, pending or established: the truth the data plane's
    /// established sessions are kept in step with.
    sessions: SessionTable,
    /// What the data plane reads. Its established sessions change only
    /// through `sessions`, its reserved prefixes only as registration tunnels
    /// come and go.
    data_plane: Arc<DataPlane>,
    /// Per-source limit on handshake initiations, registration and forwarded alike.
    limiter: RateLimiter,
    forwarding_budget: WorkBudget,
    registration_budget: WorkBudget,
    /// What the control plane decided, and the registration tunnels' output.
    metrics: Metrics,
    /// Session and registration lifecycles and handshake work.
    counters: ControlMetrics,
    /// Datagrams the registration tunnels produced, for the caller to send.
    tx_queue: Vec<(SocketAddr, Vec<u8>)>,
    scratch: Vec<u8>,
    ticks: Throttle,
    gc: Throttle,
}

impl ControlPlane {
    pub(super) fn new(config: &Config) -> Self {
        let secret = config.private_key.secret().clone();
        let public = x25519_dalek::PublicKey::from(&secret);
        let sessions = SessionTable::new(
            PENDING_TIMEOUT,
            ESTABLISHED_TIMEOUT,
            SessionLimits {
                pending_per_peer: MAX_PENDING_PER_PEER,
                per_peer: MAX_SESSIONS_PER_PEER,
                total: MAX_SESSIONS,
            },
        );
        let mut control_plane = ControlPlane {
            relay_mac1: Mac1Key::new(public.as_bytes()),
            secret,
            public,
            tunnel_ip: config.tunnel_ip,
            peers: HashMap::new(),
            mac1: Mac1Table::default(),
            registry: Registry::new(REGISTRATION_TIMEOUT),
            data_plane: Arc::new(DataPlane::new(sessions.new_view())),
            sessions,
            limiter: RateLimiter::new(config.handshake_rate.per_sec()),
            forwarding_budget: WorkBudget::new(FORWARDING_WORK_PER_SEC),
            registration_budget: WorkBudget::new(REGISTRATION_WORK_PER_SEC),
            metrics: Metrics::default(),
            counters: ControlMetrics::default(),
            tx_queue: Vec::new(),
            scratch: vec![0; SCRATCH_BUFFER_LEN],
            ticks: Throttle::new(TICK_INTERVAL),
            gc: Throttle::new(GC_INTERVAL),
        };
        control_plane.reload(config);
        control_plane
    }

    /// The data plane, for the threads that read it without locking the control plane.
    pub(super) fn data_plane(&self) -> Arc<DataPlane> {
        Arc::clone(&self.data_plane)
    }

    pub(super) fn public_key(&self) -> PublicKey {
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

    pub(super) fn registered_endpoint(&self, key: &PublicKey, now: Instant) -> Option<SocketAddr> {
        self.registry.endpoint(key, now)
    }

    pub(super) fn drain_tx_queue(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let out = std::mem::take(&mut self.tx_queue);
        self.metrics.tunnel_tx += out.len() as u64;
        self.metrics.tunnel_tx_bytes += out.iter().map(|(_, d)| d.len() as u64).sum::<u64>();
        out
    }

    /// Find the configured peer whose registration tunnel owns this index, if
    /// it is in a reserved prefix.
    fn tunnel_owner(&self, index: SessionIndex) -> Option<PublicKey> {
        self.data_plane.reserved.owner(index)
    }

    /// Panic unless the session table's accounts are exact, the data plane
    /// holds exactly its established sessions, and none is in a reserved prefix.
    #[cfg(test)]
    fn assert_data_plane_in_step(&self) {
        assert!(self.sessions.accounts_exact(), "session accounts diverged");
        let view = &self.data_plane.established;
        assert!(self.sessions.matches_view(view), "established sessions diverged");
        // The data plane relies on it to look up the reserved prefixes only on a miss.
        let in_reserved =
            self.sessions.established_pairs().any(|(i, ..)| self.tunnel_owner(i).is_some());
        assert!(!in_reserved, "an established session in a reserved prefix");
    }
}
