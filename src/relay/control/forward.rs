use std::net::SocketAddr;
use std::time::Instant;

use super::{Control, MAX_PENDING, Reason};
use crate::key::PeerKey;
use crate::packet::{self, SessionIdx};
use crate::tables::{Session, SessionState};

/// The messages routed along a forwarded session by their receiver index,
/// and what each needs from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OnSession {
    /// Opens a pending session, announcing the responder's index.
    HandshakeResponse { sender: SessionIdx },
    /// Passes on a pending or open session.
    CookieReply,
    /// Passes on an open session only.
    TransportData,
}

impl Control {
    /// Forward a handshake initiation to the registered listed peer its mac1
    /// names, opening a pending session for the initiator's index.
    pub(super) fn forward_initiation(
        &mut self,
        src: SocketAddr,
        datagram: &[u8],
        sender: SessionIdx,
        now: Instant,
    ) -> Result<SocketAddr, Reason> {
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
        self.insert_session(sender, Session::pending(src, dst, peer, now))
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

    /// Store a session and return its counterpart's address, where the
    /// handshake message that created it goes.
    fn insert_session(&mut self, idx: SessionIdx, s: Session) -> Result<SocketAddr, Reason> {
        let evicted = self.sessions.insert(idx, s, &mut self.forwarder.open)?;
        self.metrics.pending_evicted += u64::from(evicted.is_some());
        Ok(s.expected_src)
    }

    /// Forward along the session `receiver` names: only from its expected
    /// source, transport data only once it is open, one response per initiation.
    pub(super) fn forward_on_session(
        &mut self,
        src: SocketAddr,
        receiver: SessionIdx,
        kind: OnSession,
        now: Instant,
    ) -> Result<SocketAddr, Reason> {
        let session = self.sessions.get(receiver, now).ok_or(Reason::UnknownIndex)?;
        // For a handshake response this is the listed peer's registered address,
        // so only that peer can open the session.
        if src != session.expected_src {
            return Err(Reason::WrongSource);
        }
        match (kind, session.state) {
            (OnSession::HandshakeResponse { sender }, SessionState::Pending) => {
                self.accept_response(receiver, sender, session, now)
            }
            // An open session could otherwise mint new entries.
            (OnSession::HandshakeResponse { .. }, SessionState::Open) => {
                Err(Reason::SessionNotPending)
            }
            (OnSession::TransportData, SessionState::Pending) => Err(Reason::SessionNotOpen),
            (OnSession::TransportData, SessionState::Open)
            | (OnSession::CookieReply, SessionState::Pending | SessionState::Open) => {
                Ok(session.dest)
            }
        }
    }

    /// Open the session a handshake response answers: the responder's index
    /// gets an open session and the initiator's opens, both living from now.
    fn accept_response(
        &mut self,
        receiver: SessionIdx,
        sender: SessionIdx,
        initiator: Session,
        now: Instant,
    ) -> Result<SocketAddr, Reason> {
        if self.is_reserved(sender) {
            return Err(Reason::ReservedIndex);
        }
        let responder = Session::open(initiator.expected_src, initiator.dest, initiator.peer, now);
        self.insert_session(sender, responder)?;
        self.sessions.open(receiver, now, &mut self.forwarder.open);
        Ok(initiator.dest)
    }
}
