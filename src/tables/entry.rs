use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::live;
use crate::key::PeerKey;

/// Where a forwarded handshake stands for one index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Initiation forwarded, response not yet accepted: only cookie replies pass.
    Pending,
    /// Response accepted: transport data passes too.
    Open,
}

/// A session: the relay's routing entry for one index, which later messages
/// carry as `receiver_idx`. Not a WireGuard session: each forwarded handshake
/// creates two, one per direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    /// Where messages carrying this index are sent.
    pub dest: SocketAddr,
    /// The only address allowed to send messages carrying this index.
    pub expected_src: SocketAddr,
    pub state: SessionState,
    /// When the entry entered its current state; its lifetime runs from here.
    pub since: Instant,
    /// The listed peer the session was routed to; removing it revokes the session.
    pub peer: PeerKey,
}

impl Session {
    /// The initiator's session once its initiation is forwarded.
    pub fn pending(
        dest: SocketAddr,
        expected_src: SocketAddr,
        peer: PeerKey,
        now: Instant,
    ) -> Self {
        Session { dest, expected_src, state: SessionState::Pending, since: now, peer }
    }

    /// The responder's session once its response is accepted.
    pub fn open(dest: SocketAddr, expected_src: SocketAddr, peer: PeerKey, now: Instant) -> Self {
        Session { state: SessionState::Open, ..Self::pending(dest, expected_src, peer, now) }
    }

    pub(super) fn same_pair(&self, other: &Session) -> bool {
        (self.dest, self.expected_src) == (other.dest, other.expected_src)
    }
}

/// Fixed lifetimes per session state, counted from `Session::since`.
#[derive(Debug, Clone, Copy)]
pub(super) struct Ttls {
    pub(super) open: Duration,
    pub(super) pending: Duration,
}

impl Ttls {
    pub(super) fn live(self, s: &Session, now: Instant) -> bool {
        let ttl = match s.state {
            SessionState::Open => self.open,
            SessionState::Pending => self.pending,
        };
        live(s.since, now, ttl)
    }
}
