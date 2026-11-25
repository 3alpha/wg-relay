use std::net::SocketAddr;
use std::time::Instant;

use super::Control;
use crate::key::PeerKey;
use crate::packet::{Message, SessionIdx};
use crate::relay::{Accepted, Reason, Verdict, settle};

/// Every kind of datagram the control half decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Class {
    /// A handshake initiation whose mac1 is for the relay: a listed peer
    /// starting a handshake on its registration tunnel.
    RegistrationInitiation,
    /// Any other message, to an index in `peer`'s registration tunnel.
    RegistrationTunnel { peer: PeerKey },
    /// A handshake initiation for anyone but the relay.
    ForwardedInitiation { sender: SessionIdx },
    /// A handshake response between two peers.
    ForwardedResponse { sender: SessionIdx, receiver: SessionIdx },
    /// A cookie reply between two peers, on a session the forwarding half does not hold.
    ForwardedCookieReply { receiver: SessionIdx },
    /// Transport data between two peers, on a session the forwarding half does not hold.
    ForwardedData { receiver: SessionIdx },
}

impl Control {
    /// Decide a datagram the forwarding half handed over, counting and logging the outcome.
    pub(in crate::relay) fn handle(
        &mut self,
        src: SocketAddr,
        datagram: &[u8],
        message: Message,
        now: Instant,
    ) -> Verdict {
        let outcome = self.decide(src, datagram, message, now);
        settle(&mut self.metrics, src, outcome)
    }

    /// Rate-limit initiations, classify the datagram and run its handler.
    pub(super) fn decide(
        &mut self,
        src: SocketAddr,
        datagram: &[u8],
        message: Message,
        now: Instant,
    ) -> Result<Accepted, Reason> {
        // Every handshake initiation, registration or forwarded, pays the
        // per-source limit before any hashing.
        let initiation = matches!(message, Message::HandshakeInitiation { .. });
        if initiation && !self.limiter.allow(src.ip(), now) {
            return Err(Reason::RateLimited);
        }
        match self.classify(message, datagram) {
            Class::RegistrationInitiation => self.start_registration_handshake(src, datagram, now),
            Class::RegistrationTunnel { peer } => self.feed_tunnel(peer, src, datagram, now),
            Class::ForwardedInitiation { sender } => {
                self.forward_initiation(src, datagram, sender, now)
            }
            Class::ForwardedResponse { sender, receiver } => {
                self.forward_response(src, sender, receiver, now)
            }
            Class::ForwardedCookieReply { receiver } => {
                self.forward_cookie_reply(src, receiver, now)
            }
            Class::ForwardedData { receiver } => self.forward_data(src, receiver, now),
        }
    }

    /// Name the case a message falls in. Changes nothing and costs at most one mac1 check.
    pub(super) fn classify(&self, message: Message, datagram: &[u8]) -> Class {
        if let Some(peer) = message.receiver().and_then(|idx| self.tunnel_owner(idx)) {
            return Class::RegistrationTunnel { peer };
        }
        match message {
            Message::HandshakeInitiation { .. } if self.relay_mac1.matches(datagram) => {
                Class::RegistrationInitiation
            }
            Message::HandshakeInitiation { sender } => Class::ForwardedInitiation { sender },
            Message::HandshakeResponse { sender, receiver } => {
                Class::ForwardedResponse { sender, receiver }
            }
            Message::CookieReply { receiver } => Class::ForwardedCookieReply { receiver },
            Message::TransportData { receiver } => Class::ForwardedData { receiver },
        }
    }

    /// Find the listed peer whose registration tunnel owns this index.
    fn tunnel_owner(&self, idx: SessionIdx) -> Option<PeerKey> {
        self.reserved.get(&idx.prefix()).copied()
    }
}
