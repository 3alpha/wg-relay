use std::net::SocketAddr;
use std::time::Instant;

use super::ControlPlane;
use crate::key::PublicKey;
use crate::message::{Message, SessionIndex};
use crate::relay::{Accepted, DropReason, Verdict, record_verdict};

/// Every kind of datagram the control plane decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Class {
    /// A handshake initiation whose mac1 is for the relay: a configured peer
    /// starting a handshake on its registration tunnel.
    RegistrationInitiation,
    /// Any other message, to an index in `peer`'s registration tunnel.
    RegistrationTunnel { peer: PublicKey },
    /// A handshake initiation for anyone but the relay.
    ForwardedInitiation { sender_index: SessionIndex },
    /// A handshake response between two peers.
    ForwardedResponse { sender_index: SessionIndex, receiver_index: SessionIndex },
    /// A cookie reply between two peers, on a session the data plane does not hold.
    ForwardedCookieReply { receiver_index: SessionIndex },
}

impl ControlPlane {
    /// Decide a datagram the data plane handed over, counting and logging the outcome.
    pub(in crate::relay) fn handle(
        &mut self,
        src: SocketAddr,
        datagram: &[u8],
        message: Message,
        now: Instant,
    ) -> Verdict {
        let outcome = self.decide(src, datagram, message, now);
        record_verdict(&mut self.metrics, src, outcome)
    }

    /// Rate-limit initiations, classify the datagram and run its handler.
    pub(super) fn decide(
        &mut self,
        src: SocketAddr,
        datagram: &[u8],
        message: Message,
        now: Instant,
    ) -> Result<Accepted, DropReason> {
        // Every handshake initiation, registration or forwarded, pays the
        // per-source limit before any hashing.
        let initiation = matches!(message, Message::HandshakeInitiation { .. });
        if initiation && !self.limiter.allow(src.ip(), now) {
            return Err(DropReason::RateLimited);
        }
        match self.classify(datagram, message)? {
            Class::RegistrationInitiation => {
                self.handle_registration_initiation(src, datagram, now)
            }
            Class::RegistrationTunnel { peer } => self.receive_on_tunnel(src, datagram, peer, now),
            Class::ForwardedInitiation { sender_index } => {
                self.forward_initiation(src, datagram, sender_index, now)
            }
            Class::ForwardedResponse { sender_index, receiver_index } => {
                self.forward_response(src, sender_index, receiver_index, now)
            }
            Class::ForwardedCookieReply { receiver_index } => {
                self.forward_cookie_reply(src, receiver_index, now)
            }
        }
    }

    /// Name the case a message falls in, or why none does. Changes nothing; at most one mac1 check.
    pub(super) fn classify(&self, datagram: &[u8], message: Message) -> Result<Class, DropReason> {
        if let Some(peer) = message.receiver_index().and_then(|index| self.tunnel_owner(index)) {
            return Ok(Class::RegistrationTunnel { peer });
        }
        match message {
            Message::HandshakeInitiation { .. } if self.relay_mac1.matches(datagram) => {
                Ok(Class::RegistrationInitiation)
            }
            Message::HandshakeInitiation { sender_index } => {
                Ok(Class::ForwardedInitiation { sender_index })
            }
            Message::HandshakeResponse { sender_index, receiver_index } => {
                Ok(Class::ForwardedResponse { sender_index, receiver_index })
            }
            Message::CookieReply { receiver_index } => {
                Ok(Class::ForwardedCookieReply { receiver_index })
            }
            // The data plane hands over transport data only in a reserved
            // prefix, which a reload may have freed since: no case takes it now.
            Message::TransportData { .. } => Err(DropReason::UnknownIndex),
        }
    }
}
