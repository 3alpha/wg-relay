use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use papaya::HashMap;

use super::Reason;
use crate::key::PeerKey;
use crate::packet::{self, IdxPrefix, Message, SessionIdx};
use crate::tables::{OpenSessions, Route};

/// The forwarding half: from state it only reads, forwards transport data and
/// cookie replies on open sessions, drops transport data that neither an open
/// session nor a registration tunnel takes, and hands every other datagram to
/// the control half, its only writer. Every forwarding thread reads it at once,
/// without a lock.
pub(super) struct Forwarder {
    /// Open sessions, written only by the session table as its open entries change.
    pub(super) open: OpenSessions,
    /// Reserved prefixes, written only by the control half as registration tunnels come and go.
    pub(super) reserved: ReservedPrefixes,
}

// Forwarding threads share it, so it must stay plain shareable data.
const _: () = {
    const fn shareable<T: Send + Sync>() {}
    shareable::<Forwarder>();
};

/// The forwarding half's decision on one datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Triage {
    /// Send it, unchanged, to this address.
    Forward(SocketAddr),
    Drop(Reason),
    /// Only the control half can decide: a handshake message, a message to a
    /// registration tunnel, or a cookie reply on an index that is not a live open session.
    ToControl(Message),
}

impl Forwarder {
    pub(super) fn new(open: OpenSessions) -> Self {
        Forwarder { open, reserved: ReservedPrefixes::default() }
    }

    /// Forward or drop a datagram if the state it reads can decide, else hand it on.
    pub(super) fn triage(&self, src: SocketAddr, datagram: &[u8], now: Instant) -> Triage {
        if !replyable(src) {
            return Triage::Drop(Reason::InvalidSource);
        }
        let message = match packet::parse(datagram) {
            Ok(message) => message,
            Err(e) => return Triage::Drop(Reason::from(e)),
        };
        let Some(route) = self.open_route(message, now) else {
            return self.unrouted(message);
        };
        if src != route.expected_src {
            return Triage::Drop(Reason::WrongSource);
        }
        Triage::Forward(route.dest)
    }

    /// Find the live open session a transport data message or cookie reply
    /// travels on. Handshake messages never have one, and neither does an
    /// index in a registration tunnel's reserved prefix: forwarded sessions may
    /// not use those, and a new tunnel never takes a prefix in use.
    fn open_route(&self, message: Message, now: Instant) -> Option<Route> {
        let receiver = match message {
            Message::HandshakeInitiation { .. } | Message::HandshakeResponse { .. } => return None,
            Message::CookieReply { receiver } | Message::TransportData { receiver } => receiver,
        };
        self.open.get(receiver, now)
    }

    /// Drop transport data unless a registration tunnel takes it, and hand the rest over.
    /// Reached only on a miss, so forwarded traffic never pays for the prefix lookup.
    fn unrouted(&self, message: Message) -> Triage {
        match message {
            Message::TransportData { receiver } if self.reserved.owner(receiver).is_none() => {
                Triage::Drop(Reason::UnknownIndex)
            }
            Message::HandshakeInitiation { .. }
            | Message::HandshakeResponse { .. }
            | Message::CookieReply { .. }
            | Message::TransportData { .. } => Triage::ToControl(message),
        }
    }
}

/// Reserved prefixes, each with the listed peer whose registration tunnel
/// numbers its indexes there. Both halves read it; only the control half writes it.
#[derive(Default)]
pub(super) struct ReservedPrefixes {
    map: HashMap<IdxPrefix, PeerKey>,
}

impl ReservedPrefixes {
    /// The listed peer whose registration tunnel owns `idx`, if it is in a reserved prefix.
    pub(super) fn owner(&self, idx: SessionIdx) -> Option<PeerKey> {
        self.map.pin().get(&idx.prefix()).copied()
    }

    /// Is `prefix` reserved?
    pub(super) fn contains(&self, prefix: IdxPrefix) -> bool {
        self.map.pin().contains_key(&prefix)
    }

    /// Reserve `prefix` for `peer`'s registration tunnel. For the control half only.
    pub(super) fn reserve(&self, prefix: IdxPrefix, peer: PeerKey) {
        self.map.pin().insert(prefix, peer);
    }

    /// Free every prefix whose listed peer fails `keep`. For the control half only.
    pub(super) fn retain(&self, mut keep: impl FnMut(&PeerKey) -> bool) {
        self.map.pin().retain(|_, peer| keep(peer));
    }

    /// Every reserved prefix with its listed peer.
    #[cfg(test)]
    pub(super) fn pairs(&self) -> Vec<(IdxPrefix, PeerKey)> {
        self.map.pin().iter().map(|(p, k)| (*p, *k)).collect()
    }
}

/// Can `src` ever be a reply destination? Spoofed sources such as port 0 or a
/// broadcast address would otherwise be stored as a session's `dest`.
fn replyable(src: SocketAddr) -> bool {
    let ip = src.ip().to_canonical();
    let bad_ip =
        ip.is_unspecified() || ip.is_multicast() || matches!(ip, IpAddr::V4(a) if a.is_broadcast());
    src.port() != 0 && !bad_ip
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::testing::{cookie, data, initiation, response};
    use crate::tables::{OPEN_TTL, PENDING_TTL, Session, SessionLimits, SessionTable};
    use std::time::Duration;

    fn addr(i: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, i], 1))
    }

    const OPEN: u32 = 0x10;
    const PENDING: u32 = 0x20;
    const RESERVED: u32 = 0x3005;

    /// A forwarder written by a session table: `OPEN` carries traffic from
    /// addr(1) to addr(2), `PENDING` awaits a handshake response, and
    /// `RESERVED` is in a registration tunnel's reserved prefix.
    fn setup(t0: Instant) -> Forwarder {
        let limits = SessionLimits { pending_per_peer: 8, per_peer: 8, total: 8 };
        let mut table = SessionTable::new(PENDING_TTL, OPEN_TTL, limits);
        let fwd = Forwarder::new(table.new_view());
        let peer = PeerKey::from([1; 32]);
        for (idx, s) in [
            (OPEN, Session::open(addr(2), addr(1), peer, t0)),
            (PENDING, Session::pending(addr(2), addr(1), peer, t0)),
        ] {
            table.insert(idx.into(), s, &fwd.open).unwrap();
        }
        fwd.reserved.reserve(SessionIdx::from(RESERVED).prefix(), peer);
        fwd
    }

    #[test]
    fn forwards_data_and_cookie_replies_on_open_sessions_from_the_expected_source_only() {
        let t0 = Instant::now();
        let fwd = setup(t0);
        let later = t0 + OPEN_TTL - Duration::from_secs(1);
        for datagram in [data(OPEN), cookie(OPEN)] {
            assert_eq!(fwd.triage(addr(1), &datagram, t0), Triage::Forward(addr(2)));
            assert_eq!(fwd.triage(addr(1), &datagram, later), Triage::Forward(addr(2)));
            assert_eq!(fwd.triage(addr(3), &datagram, t0), Triage::Drop(Reason::WrongSource));
            assert_eq!(
                fwd.triage(addr(2), &datagram, t0),
                Triage::Drop(Reason::WrongSource),
                "reflected"
            );
        }
    }

    #[test]
    fn drops_transport_data_off_open_sessions_and_registration_tunnels() {
        let t0 = Instant::now();
        let fwd = setup(t0);
        let cases = [
            (data(PENDING), t0, "a pending index"),
            (data(0x99), t0, "an unknown index"),
            (data(OPEN), t0 + OPEN_TTL, "expired, not yet swept"),
        ];
        for (datagram, now, what) in cases {
            assert_eq!(
                fwd.triage(addr(1), &datagram, now),
                Triage::Drop(Reason::UnknownIndex),
                "{what}"
            );
        }
    }

    #[test]
    fn hands_everything_else_to_the_control_half() {
        let t0 = Instant::now();
        let fwd = setup(t0);
        let cases = [
            (initiation(OPEN), t0, "handshake initiation"),
            (response(0x99, OPEN), t0, "handshake response, even to an open index"),
            (data(RESERVED), t0, "transport data to a registration tunnel"),
            (cookie(RESERVED), t0, "cookie reply to a registration tunnel"),
            (cookie(PENDING), t0, "cookie reply on a pending index"),
            (cookie(0x99), t0, "cookie reply on an unknown index"),
            (cookie(OPEN), t0 + OPEN_TTL, "cookie reply on an expired index"),
        ];
        for (datagram, now, what) in cases {
            let message = packet::parse(&datagram).unwrap();
            assert_eq!(fwd.triage(addr(1), &datagram, now), Triage::ToControl(message), "{what}");
        }
    }

    #[test]
    fn drops_unreplyable_sources_and_malformed_datagrams_first() {
        let t0 = Instant::now();
        let fwd = setup(t0);
        let broadcast = SocketAddr::from(([255, 255, 255, 255], 1));
        assert_eq!(fwd.triage(broadcast, &data(OPEN), t0), Triage::Drop(Reason::InvalidSource));
        assert_eq!(fwd.triage(addr(1), &data(OPEN)[..20], t0), Triage::Drop(Reason::Malformed));
    }
}
