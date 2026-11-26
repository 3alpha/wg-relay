use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::live;
use crate::key::PublicKey;

/// Where a forwarded handshake stands for one index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Initiation forwarded, response not yet accepted: only cookie replies pass.
    Pending,
    /// Response accepted: transport data passes too.
    Established,
}

/// A session: the relay's routing entry for one index, which later messages
/// carry as `receiver_index`. Not a WireGuard session: each forwarded handshake
/// creates two, one per direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    /// Where messages carrying this index are sent.
    pub dst: SocketAddr,
    /// The only address allowed to send messages carrying this index.
    pub src: SocketAddr,
    pub state: SessionState,
    /// When the entry entered its current state; its lifetime runs from here.
    pub since: Instant,
    /// The configured peer the session was routed to; removing it revokes the session.
    pub peer: PublicKey,
}

impl Session {
    /// The initiator's session once its initiation is forwarded.
    pub fn pending(dst: SocketAddr, src: SocketAddr, peer: PublicKey, now: Instant) -> Self {
        Session { dst, src, state: SessionState::Pending, since: now, peer }
    }

    /// The responder's session once its response is accepted.
    pub fn established(dst: SocketAddr, src: SocketAddr, peer: PublicKey, now: Instant) -> Self {
        Session { state: SessionState::Established, ..Self::pending(dst, src, peer, now) }
    }

    pub(super) fn same_pair(&self, other: &Session) -> bool {
        (self.dst, self.src) == (other.dst, other.src)
    }
}

/// Fixed lifetimes per session state, counted from `Session::since`.
#[derive(Debug, Clone, Copy)]
pub(super) struct Timeouts {
    pub(super) pending: Duration,
    pub(super) established: Duration,
}

impl Timeouts {
    pub(super) fn live(self, s: &Session, now: Instant) -> bool {
        let timeout = match s.state {
            SessionState::Pending => self.pending,
            SessionState::Established => self.established,
        };
        live(s.since, now, timeout)
    }
}
