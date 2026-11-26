use std::time::Instant;

use super::{
    ControlPlane, FORWARDING_WORK_PER_SEC, MAX_PENDING, MAX_PENDING_PER_PEER, MAX_SESSIONS,
    MAX_SESSIONS_PER_PEER, REGISTRATION_WORK_PER_SEC,
};
use crate::relay::{ControlSnapshot, Limits, PeerSnapshot};

/// The limits the control plane enforces.
pub const LIMITS: Limits = Limits {
    sessions: MAX_SESSIONS,
    pending: MAX_PENDING,
    sessions_per_peer: MAX_SESSIONS_PER_PEER,
    pending_per_peer: MAX_PENDING_PER_PEER,
    forwarding_work_per_sec: FORWARDING_WORK_PER_SEC,
    registration_work_per_sec: REGISTRATION_WORK_PER_SEC,
};

impl ControlPlane {
    /// Copy out the counters, session counts and every configured peer's state.
    /// One lookup per table per configured peer; nothing is scanned.
    pub(in crate::relay) fn snapshot(&self, now: Instant) -> ControlSnapshot {
        let mut peers: Vec<PeerSnapshot> = self
            .peers
            .iter()
            .map(|(key, state)| PeerSnapshot {
                name: state.name.clone(),
                registered: self.registry.endpoint(key, now).is_some(),
                since_authenticated: self
                    .registry
                    .last_authenticated(key)
                    .map(|t| now.saturating_duration_since(t)),
                sessions: self.sessions.peer_len(key),
                pending: self.sessions.peer_pending_len(key),
                initiations_forwarded: state.initiations_forwarded,
                initiations_dropped: state.initiations_dropped,
            })
            .collect();
        peers.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        let (rate_limit_buckets_used, rate_limit_buckets) = self.limiter.occupancy();
        ControlSnapshot {
            metrics: self.metrics.clone(),
            counters: self.counters.clone(),
            sessions: self.sessions.len(),
            pending: self.sessions.pending_len(),
            rate_limit_buckets_used,
            rate_limit_buckets,
            reserved_prefixes: self.data_plane.reserved.len(),
            forwarding_budget_remaining: self.forwarding_budget.remaining(now),
            registration_budget_remaining: self.registration_budget.remaining(now),
            peers,
        }
    }
}
