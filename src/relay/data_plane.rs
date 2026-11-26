use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use papaya::HashMap;

use super::DropReason;
use crate::key::PublicKey;
use crate::message::{self, IndexPrefix, Message, SessionIndex};
use crate::tables::{EstablishedSessions, Route};

/// The data plane: from state it only reads, forwards transport data and
/// cookie replies on established sessions, drops transport data that neither an
/// established session nor a registration tunnel takes, and hands every other
/// datagram to the control plane, its only writer. Every forwarding thread reads
/// it at once, without a lock.
pub(super) struct DataPlane {
    /// Established sessions, written only by the session table as they change.
    pub(super) established: EstablishedSessions,
    /// Reserved prefixes, written only by the control plane as registration tunnels come and go.
    pub(super) reserved: ReservedPrefixes,
}

// Forwarding threads share it, so it must stay plain shareable data.
const _: () = {
    const fn shareable<T: Send + Sync>() {}
    shareable::<DataPlane>();
};

/// The data plane's decision on one datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Triage {
    /// Send it, unchanged, to this address.
    Forward(SocketAddr),
    Drop(DropReason),
    /// Only the control plane can decide: a handshake message, a message to a
    /// registration tunnel, or a cookie reply on an index that is not a live established session.
    ToControl(Message),
}

impl DataPlane {
    pub(super) fn new(established: EstablishedSessions) -> Self {
        DataPlane { established, reserved: ReservedPrefixes::default() }
    }

    /// Forward or drop a datagram if the state it reads can decide, else hand it on.
    pub(super) fn triage(&self, src: SocketAddr, datagram: &[u8], now: Instant) -> Triage {
        // A source nobody could answer (unspecified, multicast, broadcast, port 0) is spoofed.
        if !is_valid_source(src) {
            return Triage::Drop(DropReason::InvalidSource);
        }
        // Only the header is read: the type and the indexes. Nothing is decrypted.
        let message = match message::parse(datagram) {
            Ok(message) => message,
            Err(e) => return Triage::Drop(DropReason::from(e)),
        };
        // The fast path: transport data or a cookie reply on an established session.
        let Some(route) = self.established_route(message, now) else {
            // Transport data on no session is junk unless its index belongs to a
            // registration tunnel; dropping it here keeps floods off the control lock.
            if let Message::TransportData { receiver_index } = message
                && self.reserved.owner(receiver_index).is_none()
            {
                return Triage::Drop(DropReason::UnknownIndex);
            }
            // Handshakes, registration tunnel traffic and stray cookie replies
            // need state only the control plane holds.
            return Triage::ToControl(message);
        };
        // A session is pinned to the address that established it; anyone else
        // who learned or guessed the index is refused.
        if src != route.src {
            return Triage::Drop(DropReason::WrongSource);
        }
        // Forward byte for byte to the other end of the session.
        Triage::Forward(route.dst)
    }

    /// Find the live established session a transport data message or cookie
    /// reply travels on. Handshake messages never have one, and neither does an
    /// index in a registration tunnel's reserved prefix: forwarded sessions may
    /// not use those, and a new tunnel never takes a prefix in use.
    fn established_route(&self, message: Message, now: Instant) -> Option<Route> {
        match message {
            Message::CookieReply { receiver_index } | Message::TransportData { receiver_index } => {
                self.established.get(receiver_index, now)
            }
            Message::HandshakeInitiation { .. } | Message::HandshakeResponse { .. } => None,
        }
    }
}

/// Reserved prefixes, each with the configured peer whose registration tunnel
/// numbers its indexes there. Both planes read it; only the control plane writes it.
#[derive(Default)]
pub(super) struct ReservedPrefixes {
    map: HashMap<IndexPrefix, PublicKey>,
}

impl ReservedPrefixes {
    /// The configured peer whose registration tunnel owns `index`, if it is in a reserved prefix.
    pub(super) fn owner(&self, index: SessionIndex) -> Option<PublicKey> {
        self.map.pin().get(&index.prefix()).copied()
    }

    /// Is `prefix` reserved?
    pub(super) fn contains(&self, prefix: IndexPrefix) -> bool {
        self.map.pin().contains_key(&prefix)
    }

    /// How many prefixes are reserved: one per configured peer's registration tunnel.
    pub(super) fn len(&self) -> usize {
        self.map.len()
    }

    /// Reserve `prefix` for `peer`'s registration tunnel. For the control plane only.
    pub(super) fn reserve(&self, prefix: IndexPrefix, peer: PublicKey) {
        self.map.pin().insert(prefix, peer);
    }

    /// Free every prefix whose configured peer fails `keep`. For the control plane only.
    pub(super) fn retain(&self, mut keep: impl FnMut(&PublicKey) -> bool) {
        self.map.pin().retain(|_, peer| keep(peer));
    }

    /// Every reserved prefix with its configured peer.
    #[cfg(test)]
    pub(super) fn pairs(&self) -> Vec<(IndexPrefix, PublicKey)> {
        self.map.pin().iter().map(|(p, k)| (*p, *k)).collect()
    }
}

/// Can `src` ever be a reply destination? Spoofed sources such as port 0 or a
/// broadcast address would otherwise be stored as a session's `dst`.
fn is_valid_source(src: SocketAddr) -> bool {
    let ip = src.ip().to_canonical();
    let bad_ip =
        ip.is_unspecified() || ip.is_multicast() || matches!(ip, IpAddr::V4(a) if a.is_broadcast());
    src.port() != 0 && !bad_ip
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::testing::{cookie, data, initiation, response};
    use crate::tables::{
        ESTABLISHED_TIMEOUT, PENDING_TIMEOUT, Session, SessionLimits, SessionTable,
    };
    use std::time::Duration;

    fn addr(i: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, i], 1))
    }

    const ESTABLISHED: u32 = 0x10;
    const PENDING: u32 = 0x20;
    const RESERVED: u32 = 0x3005;

    /// A data plane written by a session table: `ESTABLISHED` carries traffic from
    /// addr(1) to addr(2), `PENDING` awaits a handshake response, and
    /// `RESERVED` is in a registration tunnel's reserved prefix.
    fn setup(t0: Instant) -> DataPlane {
        let limits = SessionLimits { pending_per_peer: 8, per_peer: 8, total: 8 };
        let mut table = SessionTable::new(PENDING_TIMEOUT, ESTABLISHED_TIMEOUT, limits);
        let plane = DataPlane::new(table.new_view());
        let peer = PublicKey::from([1; 32]);
        for (index, s) in [
            (ESTABLISHED, Session::established(addr(2), addr(1), peer, t0)),
            (PENDING, Session::pending(addr(2), addr(1), peer, t0)),
        ] {
            table.insert(index.into(), s, &plane.established).unwrap();
        }
        plane.reserved.reserve(SessionIndex::from(RESERVED).prefix(), peer);
        plane
    }

    #[test]
    fn forwards_data_and_cookie_replies_on_established_sessions_from_the_expected_source_only() {
        let t0 = Instant::now();
        let plane = setup(t0);
        let later = t0 + ESTABLISHED_TIMEOUT - Duration::from_secs(1);
        for datagram in [data(ESTABLISHED), cookie(ESTABLISHED)] {
            assert_eq!(plane.triage(addr(1), &datagram, t0), Triage::Forward(addr(2)));
            assert_eq!(plane.triage(addr(1), &datagram, later), Triage::Forward(addr(2)));
            assert_eq!(plane.triage(addr(3), &datagram, t0), Triage::Drop(DropReason::WrongSource));
            assert_eq!(
                plane.triage(addr(2), &datagram, t0),
                Triage::Drop(DropReason::WrongSource),
                "reflected"
            );
        }
    }

    #[test]
    fn drops_transport_data_off_established_sessions_and_registration_tunnels() {
        let t0 = Instant::now();
        let plane = setup(t0);
        let cases = [
            (data(PENDING), t0, "a pending index"),
            (data(0x99), t0, "an unknown index"),
            (data(ESTABLISHED), t0 + ESTABLISHED_TIMEOUT, "expired, not yet collected"),
        ];
        for (datagram, now, what) in cases {
            assert_eq!(
                plane.triage(addr(1), &datagram, now),
                Triage::Drop(DropReason::UnknownIndex),
                "{what}"
            );
        }
    }

    #[test]
    fn hands_everything_else_to_the_control_plane() {
        let t0 = Instant::now();
        let plane = setup(t0);
        let cases = [
            (initiation(ESTABLISHED), t0, "handshake initiation"),
            (response(0x99, ESTABLISHED), t0, "handshake response, even to an established index"),
            (data(RESERVED), t0, "transport data to a registration tunnel"),
            (cookie(RESERVED), t0, "cookie reply to a registration tunnel"),
            (cookie(PENDING), t0, "cookie reply on a pending index"),
            (cookie(0x99), t0, "cookie reply on an unknown index"),
            (cookie(ESTABLISHED), t0 + ESTABLISHED_TIMEOUT, "cookie reply on an expired index"),
        ];
        for (datagram, now, what) in cases {
            let message = message::parse(&datagram).unwrap();
            assert_eq!(plane.triage(addr(1), &datagram, now), Triage::ToControl(message), "{what}");
        }
    }

    #[test]
    fn drops_invalid_sources_and_malformed_datagrams_first() {
        let t0 = Instant::now();
        let plane = setup(t0);
        let broadcast = SocketAddr::from(([255, 255, 255, 255], 1));
        let datagram = data(ESTABLISHED);
        assert_eq!(plane.triage(broadcast, &datagram, t0), Triage::Drop(DropReason::InvalidSource));
        assert_eq!(plane.triage(addr(1), &datagram[..20], t0), Triage::Drop(DropReason::Malformed));
    }
}
