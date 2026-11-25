use std::net::SocketAddr;
use std::time::Instant;

use super::{PeerKind, Reason, Relay};
use crate::config::Gate;
use crate::packet::{self, SessionIdx};
use crate::tables::{Session, SessionState};

/// Cookie replies and data are both routed by receiver index alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Indexed {
    Cookie,
    Data,
}

impl Relay {
    /// Route a handshake initiation to the server or client its mac1 names.
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
        if let Some(server) = self.mac1_peer(pkt, PeerKind::is_server) {
            // Anyone may initiate to a registered server; the gate applies to its response.
            let dst = self.registry.addr(&server, now).ok_or(Reason::ServerNotRegistered)?;
            if dst == src {
                return Err(Reason::Loop);
            }
            let s = Session::pending(src, dst, server, None, now);
            return self.insert_session(sender, s);
        }
        // Only a registered server re-keys towards a client. Checking the source
        // first spares junk from anyone else the mac1 scan over every client.
        let server = self.server_at(src, now).ok_or(Reason::NoMac1Match)?;
        let client = self.mac1_peer(pkt, PeerKind::is_client).ok_or(Reason::NoMac1Match)?;
        if !self.may_reach(&client, &server) {
            return Err(Reason::Acl);
        }
        let dst = self.learned.get(&client).copied().ok_or(Reason::ClientAddrUnknown)?;
        let s = Session::pending(src, dst, server, Some(client), now);
        self.insert_session(sender, s)
    }

    /// Store a session and return its counterpart's address, where the
    /// handshake message that created it goes.
    fn insert_session(&mut self, idx: SessionIdx, s: Session) -> Result<SocketAddr, Reason> {
        if self.sessions.insert(idx, s) { Ok(s.expected_src) } else { Err(Reason::IndexInUse) }
    }

    /// Route a handshake response back to its initiator, applying the client gate.
    pub(super) fn forward_response(
        &mut self,
        src: SocketAddr,
        pkt: &[u8],
        sender: SessionIdx,
        receiver: SessionIdx,
        now: Instant,
    ) -> Result<SocketAddr, Reason> {
        let init = self.sessions.get(receiver, now).ok_or(Reason::UnknownIndex)?;
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
        let client = match self.server_at(src, now) {
            // Server answering a client: mac1 names the client the server authenticated.
            Some(server) if server != init.server => return Err(Reason::WrongSource),
            Some(server) => match (self.mac1_peer(pkt, PeerKind::is_client), self.gate) {
                (Some(c), _) if !self.may_reach(&c, &server) => return Err(Reason::Acl),
                (Some(c), _) => {
                    self.learned.insert(c, init.dest);
                    Some(c)
                }
                (None, Gate::None) => None,
                (None, Gate::Response) => return Err(Reason::ResponseUnknownClient),
            },
            // Client answering a server-initiated handshake.
            None => {
                let for_server = self
                    .peers
                    .get(&init.server)
                    .is_some_and(|p| packet::mac1_matches(&p.mac1, pkt));
                if !for_server {
                    return Err(Reason::ResponseNotForServer);
                }
                init.client
            }
        };
        let s = Session::open(src, init.dest, init.server, client, now);
        self.insert_session(sender, s)?;
        self.sessions.open(receiver, now, client);
        Ok(init.dest)
    }

    /// Route cookie replies and data: only from the expected source; data only on open sessions.
    pub(super) fn forward_indexed(
        &mut self,
        src: SocketAddr,
        kind: Indexed,
        receiver: SessionIdx,
        now: Instant,
    ) -> Result<SocketAddr, Reason> {
        let s = self.sessions.get_mut(receiver, now).ok_or(Reason::UnknownIndex)?;
        if src != s.expected_src {
            return Err(Reason::WrongSource);
        }
        match (kind, s.state) {
            (Indexed::Data, SessionState::Pending) => Err(Reason::SessionNotOpen),
            (Indexed::Data, SessionState::Open) | (Indexed::Cookie, _) => {
                s.last_seen = now;
                Ok(s.dest)
            }
        }
    }
}
