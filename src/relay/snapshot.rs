use std::time::Duration;

use super::{ControlMetrics, Metrics};

/// The control plane's state at one instant, copied out under one short hold of its lock.
#[derive(Debug, Clone, Default)]
pub struct ControlSnapshot {
    /// What the control plane decided.
    pub metrics: Metrics,
    /// Session and registration lifecycles and handshake work.
    pub counters: ControlMetrics,
    /// Sessions, pending or established, including expired ones not yet collected.
    pub sessions: usize,
    pub pending: usize,
    /// Per-source rate-limit buckets some source has used since startup; they are never freed.
    pub rate_limit_buckets_used: usize,
    pub rate_limit_buckets: usize,
    /// Index prefixes reserved for registration tunnels.
    pub reserved_prefixes: usize,
    /// Mac1 checks each budget would allow now; negative while in debt.
    pub forwarding_budget_remaining: f64,
    pub registration_budget_remaining: f64,
    /// Every configured peer, by name.
    pub peers: Vec<PeerSnapshot>,
}

/// One configured peer's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSnapshot {
    /// Its name in the config.
    pub name: String,
    /// Has it a live registration?
    pub registered: bool,
    /// How long ago it last authenticated on its registration tunnel, if the
    /// registry still holds it.
    pub since_authenticated: Option<Duration>,
    /// Sessions routed to it, pending or established.
    pub sessions: usize,
    pub pending: usize,
    /// Forwarded initiations sent to it since it was configured.
    pub initiations_forwarded: u64,
    /// Initiations whose mac1 named it but were dropped after the scan:
    /// not registered, at its quota, a loop or an index in use.
    pub initiations_dropped: u64,
}

/// The relay's fixed limits on sessions and handshake work.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limits {
    pub sessions: usize,
    pub pending: usize,
    pub sessions_per_peer: usize,
    pub pending_per_peer: usize,
    /// Mac1 checks per second the forwarding budget allows.
    pub forwarding_work_per_sec: f64,
    /// Mac1 checks per second the registration budget allows.
    pub registration_work_per_sec: f64,
}
