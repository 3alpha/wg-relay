use std::net::SocketAddr;
use std::time::Instant;

use super::{Control, MAX_PENDING};
use crate::key::PeerKey;
use crate::packet::{self, SessionIdx};
use crate::relay::{Accepted, Reason};
use crate::tables::{Session, SessionState};

impl Control {
    /// Forward a handshake initiation to the registered listed peer its mac1
    /// names, opening a pending session for the initiator's index.
    pub(super) fn forward_initiation(
        &mut self,
        src: SocketAddr,
        datagram: &[u8],
        sender: SessionIdx,
        now: Instant,
    ) -> Result<Accepted, Reason> {
        if self.is_reserved(sender) {
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
        let peer = self.listed_peer_by_mac1(datagram, now)?;
        if self.sessions.peer_at_quota(&peer) {
            return Err(Reason::PeerQuota);
        }
        let dst = self.registry.addr(&peer, now).ok_or(Reason::PeerNotRegistered)?;
        if dst == src {
            return Err(Reason::Loop);
        }
        self.insert_session(sender, Session::pending(src, dst, peer, now))?;
        Ok(Accepted::Forward(dst))
    }

    /// Forward a handshake response from the listed peer, opening the pending
    /// session it answers. One response per initiation.
    pub(super) fn forward_response(
        &mut self,
        src: SocketAddr,
        sender: SessionIdx,
        receiver: SessionIdx,
        now: Instant,
    ) -> Result<Accepted, Reason> {
        // The expected source is the listed peer's registered address, so only
        // that peer can open the session.
        let initiator = self.session_from(src, receiver, now)?;
        match initiator.state {
            SessionState::Pending => {}
            // An open session could otherwise mint new entries.
            SessionState::Open => return Err(Reason::SessionNotPending),
        }
        if self.is_reserved(sender) {
            return Err(Reason::ReservedIndex);
        }
        let responder = Session::open(initiator.expected_src, initiator.dest, initiator.peer, now);
        self.insert_session(sender, responder)?;
        self.sessions.open(receiver, now, &self.forwarder.open);
        Ok(Accepted::Forward(initiator.dest))
    }

    /// Forward a cookie reply. A pending session passes it too, so a peer
    /// under load can still answer an initiation.
    pub(super) fn forward_cookie_reply(
        &self,
        src: SocketAddr,
        receiver: SessionIdx,
        now: Instant,
    ) -> Result<Accepted, Reason> {
        let session = self.session_from(src, receiver, now)?;
        Ok(Accepted::Forward(session.dest))
    }

    /// Forward transport data on an open session.
    pub(super) fn forward_data(
        &self,
        src: SocketAddr,
        receiver: SessionIdx,
        now: Instant,
    ) -> Result<Accepted, Reason> {
        let session = self.session_from(src, receiver, now)?;
        match session.state {
            SessionState::Pending => Err(Reason::SessionNotOpen),
            SessionState::Open => Ok(Accepted::Forward(session.dest)),
        }
    }

    /// Find the live session `receiver` names, if `src` may send on it.
    fn session_from(
        &self,
        src: SocketAddr,
        receiver: SessionIdx,
        now: Instant,
    ) -> Result<Session, Reason> {
        let session = self.sessions.get(receiver, now).ok_or(Reason::UnknownIndex)?;
        if src != session.expected_src {
            return Err(Reason::WrongSource);
        }
        Ok(session)
    }

    /// Is `idx` in a reserved prefix, where forwarded sessions may not go?
    fn is_reserved(&self, idx: SessionIdx) -> bool {
        self.reserved.contains_key(&idx.prefix())
    }

    /// Find the listed peer whose key the initiation's mac1 was made for,
    /// charging the scan to the forwarding budget.
    fn listed_peer_by_mac1(&mut self, datagram: &[u8], now: Instant) -> Result<PeerKey, Reason> {
        if !self.forwarding_budget.available(now) {
            return Err(Reason::ForwardingBudget);
        }
        let search = packet::find_mac1(&self.mac1.keys, datagram);
        self.forwarding_budget.spend(search.tried);
        search.found.map(|i| self.mac1.peers[i]).ok_or(Reason::NoMac1Match)
    }

    /// Store a session, counting the pending session it evicts, if any.
    fn insert_session(&mut self, idx: SessionIdx, s: Session) -> Result<(), Reason> {
        let evicted = self.sessions.insert(idx, s, &self.forwarder.open)?;
        self.metrics.pending_evicted += u64::from(evicted.is_some());
        Ok(())
    }
}
