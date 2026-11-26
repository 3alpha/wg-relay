use std::net::SocketAddr;
use std::time::Instant;

use super::{ControlPlane, MAX_PENDING};
use crate::key::PublicKey;
use crate::message::{self, SessionIndex};
use crate::relay::{Accepted, DropReason};
use crate::tables::{Session, SessionState};

impl ControlPlane {
    /// Forward a handshake initiation to the endpoint of the configured peer its
    /// mac1 names, creating a pending session for the initiator's index.
    pub(super) fn forward_initiation(
        &mut self,
        src: SocketAddr,
        datagram: &[u8],
        sender_index: SessionIndex,
        now: Instant,
    ) -> Result<Accepted, DropReason> {
        if self.tunnel_owner(sender_index).is_some() {
            return Err(DropReason::ReservedIndex);
        }
        // Checked before the scan, so a full table also spares the forwarding budget.
        if self.sessions.is_full() {
            return Err(DropReason::TooManySessions);
        }
        if self.sessions.pending_len() >= MAX_PENDING {
            return Err(DropReason::TooManyPending);
        }
        // Anyone may initiate to a configured peer; its own WireGuard peer list decides.
        let peer = self.find_peer_by_mac1(datagram, now)?;
        if self.sessions.peer_at_quota(&peer) {
            return Err(DropReason::PeerQuota);
        }
        let dst = self.registry.endpoint(&peer, now).ok_or(DropReason::PeerNotRegistered)?;
        if dst == src {
            return Err(DropReason::Loop);
        }
        self.insert_session(sender_index, Session::pending(src, dst, peer, now))?;
        Ok(Accepted::Forward(dst))
    }

    /// Forward a handshake response from the configured peer, establishing the
    /// pending session it answers. One response per initiation.
    pub(super) fn forward_response(
        &mut self,
        src: SocketAddr,
        sender_index: SessionIndex,
        receiver_index: SessionIndex,
        now: Instant,
    ) -> Result<Accepted, DropReason> {
        // The expected source is the configured peer's endpoint, so only that
        // peer can establish the session.
        let initiator = self.session_from(src, receiver_index, now)?;
        match initiator.state {
            SessionState::Pending => {}
            // An established session could otherwise mint new entries.
            SessionState::Established => return Err(DropReason::SessionNotPending),
        }
        if self.tunnel_owner(sender_index).is_some() {
            return Err(DropReason::ReservedIndex);
        }
        let responder = Session::established(initiator.src, initiator.dst, initiator.peer, now);
        self.insert_session(sender_index, responder)?;
        self.sessions.establish(receiver_index, now, &self.data_plane.established);
        Ok(Accepted::Forward(initiator.dst))
    }

    /// Forward a cookie reply on a pending or established session: a pending
    /// one passes it too, so a peer under load can still answer an initiation.
    pub(super) fn forward_cookie_reply(
        &self,
        src: SocketAddr,
        receiver_index: SessionIndex,
        now: Instant,
    ) -> Result<Accepted, DropReason> {
        let session = self.session_from(src, receiver_index, now)?;
        Ok(Accepted::Forward(session.dst))
    }

    /// Find the live session `receiver_index` names, if `src` may send on it.
    fn session_from(
        &self,
        src: SocketAddr,
        receiver_index: SessionIndex,
        now: Instant,
    ) -> Result<Session, DropReason> {
        let session = self.sessions.get(receiver_index, now).ok_or(DropReason::UnknownIndex)?;
        if src != session.src {
            return Err(DropReason::WrongSource);
        }
        Ok(session)
    }

    /// Find the configured peer whose key the initiation's mac1 was made for,
    /// charging the scan to the forwarding budget.
    fn find_peer_by_mac1(
        &mut self,
        datagram: &[u8],
        now: Instant,
    ) -> Result<PublicKey, DropReason> {
        if !self.forwarding_budget.available(now) {
            return Err(DropReason::ForwardingBudget);
        }
        let lookup = message::find_mac1(&self.mac1.keys, datagram);
        self.forwarding_budget.spend(lookup.tried);
        lookup.found.map(|i| self.mac1.peers[i]).ok_or(DropReason::NoMac1Match)
    }

    /// Store a session, counting the pending session it evicts, if any.
    fn insert_session(&mut self, index: SessionIndex, s: Session) -> Result<(), DropReason> {
        let evicted = self.sessions.insert(index, s, &self.data_plane.established)?;
        self.metrics.pending_evicted += u64::from(evicted.is_some());
        Ok(())
    }
}
