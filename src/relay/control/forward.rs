use std::net::SocketAddr;
use std::time::Instant;

use super::{Control, MAX_PENDING, Reason};
use crate::key::PeerKey;
use crate::packet::{self, SessionIdx};
use crate::tables::{Session, SessionState};

/// The packets routed by receiver index along a session, and what each needs from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Indexed {
    /// Opens a pending session, announcing the responder's index.
    Response { sender: SessionIdx },
    /// Passes on a pending or open session.
    Cookie,
    /// Passes on an open session only.
    Data,
}

impl Control {
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

    /// Is `idx` in a relay tunnel's prefix, where forwarded sessions may not go?
    fn reserved(&self, idx: SessionIdx) -> bool {
        self.tunn_by_prefix.contains_key(&idx.prefix())
    }

    /// Find the listed peer whose key the packet's mac1 was made for,
    /// charging the scan to the forwarding budget.
    fn mac1_peer(&mut self, pkt: &[u8], now: Instant) -> Result<PeerKey, Reason> {
        if !self.forward_budget.available(now) {
            return Err(Reason::HandshakeBudget);
        }
        let search = packet::find_mac1(&self.mac1.keys, pkt);
        self.forward_budget.spend(search.tried);
        search.found.map(|i| self.mac1.peers[i]).ok_or(Reason::NoMac1Match)
    }

    /// Store a session and return its counterpart's address, where the
    /// handshake message that created it goes.
    fn insert_session(&mut self, idx: SessionIdx, s: Session) -> Result<SocketAddr, Reason> {
        let evicted = self.sessions.insert(idx, s, &mut self.forwarder.open)?;
        self.metrics.pending_evicted += u64::from(evicted.is_some());
        Ok(s.expected_src)
    }

    /// Route along the session `receiver` names: only from its expected
    /// source, data only once it is open, one response per initiation.
    pub(super) fn forward_on_session(
        &mut self,
        src: SocketAddr,
        receiver: SessionIdx,
        kind: Indexed,
        now: Instant,
    ) -> Result<SocketAddr, Reason> {
        let session = self.sessions.get(receiver, now).ok_or(Reason::UnknownIndex)?;
        // For a response, the listed peer's registered address, so only it can open the session.
        if src != session.expected_src {
            return Err(Reason::WrongSource);
        }
        match (kind, session.state) {
            (Indexed::Response { sender }, SessionState::Pending) => {
                self.accept_response(receiver, sender, session, now)
            }
            // An open session could otherwise mint new entries.
            (Indexed::Response { .. }, SessionState::Open) => Err(Reason::SessionNotPending),
            (Indexed::Data, SessionState::Pending) => Err(Reason::SessionNotOpen),
            (Indexed::Data, SessionState::Open)
            | (Indexed::Cookie, SessionState::Pending | SessionState::Open) => Ok(session.dest),
        }
    }

    /// Open the session a response answers: the responder's index gets an
    /// open entry and the initiator's opens, both living from now.
    fn accept_response(
        &mut self,
        receiver: SessionIdx,
        sender: SessionIdx,
        init: Session,
        now: Instant,
    ) -> Result<SocketAddr, Reason> {
        if self.reserved(sender) {
            return Err(Reason::ReservedIndex);
        }
        let responder = Session::open(init.expected_src, init.dest, init.peer, now);
        self.insert_session(sender, responder)?;
        self.sessions.open(receiver, now, &mut self.forwarder.open);
        Ok(init.dest)
    }
}
