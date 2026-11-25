use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::live;
use crate::key::PeerKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Initiation forwarded, response not yet accepted: only cookie replies pass.
    Pending,
    /// Handshake complete: data passes.
    Open,
}

/// Forwarding state for one session index (the receiver_idx of later packets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    /// Where packets carrying this index are sent.
    pub dest: SocketAddr,
    /// The only address allowed to send packets carrying this index.
    pub expected_src: SocketAddr,
    pub state: SessionState,
    /// When the entry entered its current state; its lifetime runs from here.
    pub since: Instant,
    /// The listed peer the session was routed to; removing it revokes the session.
    pub peer: PeerKey,
}

impl Session {
    /// The initiator's index after its initiation was forwarded.
    pub fn pending(
        dest: SocketAddr,
        expected_src: SocketAddr,
        peer: PeerKey,
        now: Instant,
    ) -> Self {
        Session { dest, expected_src, state: SessionState::Pending, since: now, peer }
    }

    /// The responder's index after its response was accepted.
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
