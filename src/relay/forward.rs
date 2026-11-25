use std::net::SocketAddr;
use std::time::Instant;

use super::{MAX_PENDING, Reason, Relay};
use crate::packet::SessionIdx;
use crate::tables::{Refusal, Session, SessionState};

/// Cookie replies and data are both routed by receiver index alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Indexed {
    Cookie,
    Data,
}

impl Relay {
    /// Route a handshake initiation to the registered peer its mac1 names.
    pub(super) fn forward_init(
        &mut self,
        src: SocketAddr,
        pkt: &[u8],
        sender: SessionIdx,
        now: Instant,
    ) -> Result<SocketAddr, Reason> {
        if self.reserved(sender) {
            return Err(Reason::ReservedIndex);
        }
        // Checked before the scan, so a full table also spares the forwarding budget.
        if self.sessions.is_full() {
            return Err(Reason::TooManySessions);
        }
        if self.sessions.pending() >= MAX_PENDING {
            return Err(Reason::TooManyPending);
        }
        // Anyone may initiate to a listed peer; its own WireGuard peer list decides.
        let peer = self.mac1_peer(pkt, now)?;
        if self.sessions.peer_at_quota(&peer) {
            return Err(Reason::PeerQuota);
        }
        let dst = self.registry.addr(&peer, now).ok_or(Reason::PeerNotRegistered)?;
        if dst == src {
            return Err(Reason::Loop);
        }
        self.insert_session(sender, Session::pending(src, dst, peer, now))
    }

    /// Store a session and return its counterpart's address, where the
    /// handshake message that created it goes.
    fn insert_session(&mut self, idx: SessionIdx, s: Session) -> Result<SocketAddr, Reason> {
        match self.sessions.insert(idx, s) {
            Ok(evicted) => {
                self.metrics.pending_evicted += u64::from(evicted.is_some());
                Ok(s.expected_src)
            }
            Err(Refusal::IndexInUse) => Err(Reason::IndexInUse),
            Err(Refusal::PeerQuota) => Err(Reason::PeerQuota),
            Err(Refusal::Full) => Err(Reason::TooManySessions),
        }
    }

    /// Route a handshake response from the listed peer back to its initiator.
    pub(super) fn forward_response(
        &mut self,
        src: SocketAddr,
        sender: SessionIdx,
        receiver: SessionIdx,
        now: Instant,
    ) -> Result<SocketAddr, Reason> {
        let init = self.sessions.get(receiver, now).ok_or(Reason::UnknownIndex)?;
        // The listed peer's registered address, so only it can open the session.
        if src != init.expected_src {
            return Err(Reason::WrongSource);
        }
        // One response per initiation, or an open session could mint new ones.
        if init.state != SessionState::Pending {
            return Err(Reason::SessionNotPending);
        }
        if self.reserved(sender) {
            return Err(Reason::ReservedIndex);
        }
        self.insert_session(sender, Session::open(src, init.dest, init.peer, now))?;
        self.sessions.open(receiver, now);
        Ok(init.dest)
    }

    /// Route cookie replies and data: only from the expected source; data only
    /// on open sessions. Read-only: traffic never extends an entry's lifetime.
    pub(super) fn forward_indexed(
        &self,
        src: SocketAddr,
        kind: Indexed,
        receiver: SessionIdx,
        now: Instant,
    ) -> Result<SocketAddr, Reason> {
        let s = self.sessions.get(receiver, now).ok_or(Reason::UnknownIndex)?;
        if src != s.expected_src {
            return Err(Reason::WrongSource);
        }
        match (kind, s.state) {
            (Indexed::Data, SessionState::Pending) => Err(Reason::SessionNotOpen),
            (Indexed::Data, SessionState::Open) | (Indexed::Cookie, _) => Ok(s.dest),
        }
    }
}
