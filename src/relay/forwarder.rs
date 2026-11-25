use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use super::Reason;
use crate::packet::{self, IdxPrefix, Message};
use crate::tables::{OpenSessions, Route};

/// The forwarding half: forwards transport data and cookie replies on open
/// sessions from state it only reads, and hands every other datagram to the
/// control half, which is also its only writer.
pub(super) struct Forwarder {
    /// Open sessions, written only by the session table as its open entries change.
    pub(super) open: OpenSessions,
    /// Index prefixes of the registration tunnels. Messages to them go to the control half.
    reserved: HashSet<IdxPrefix>,
}

// Forwarding workers will share it, so it must stay plain shareable data.
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
    /// registration tunnel, or an index that is not a live open session.
    ToControl(Message),
}

impl Forwarder {
    pub(super) fn new(open: OpenSessions) -> Self {
        Forwarder { open, reserved: HashSet::new() }
    }

    /// Forward or drop a datagram if open sessions alone can decide, else hand it on.
    pub(super) fn triage(&self, src: SocketAddr, datagram: &[u8], now: Instant) -> Triage {
        if !replyable(src) {
            return Triage::Drop(Reason::InvalidSource);
        }
        let message = match packet::parse(datagram) {
            Ok(message) => message,
            Err(e) => return Triage::Drop(Reason::from(e)),
        };
        let Some(route) = self.open_route(message, now) else {
            return Triage::ToControl(message);
        };
        if src != route.expected_src {
            return Triage::Drop(Reason::WrongSource);
        }
        Triage::Forward(route.dest)
    }

    /// Find the live open session a transport data message or cookie reply
    /// travels on. Handshake messages and reserved indexes never have one.
    fn open_route(&self, message: Message, now: Instant) -> Option<&Route> {
        let receiver = match message {
            Message::HandshakeInitiation { .. } | Message::HandshakeResponse { .. } => return None,
            Message::CookieReply { receiver } | Message::TransportData { receiver } => receiver,
        };
        if self.reserved.contains(&receiver.prefix()) {
            return None;
        }
        self.open.get(receiver, now)
    }

    /// Replace the registration tunnels' index prefixes.
    pub(super) fn set_reserved(&mut self, prefixes: impl IntoIterator<Item = IdxPrefix>) {
        self.reserved = prefixes.into_iter().collect();
    }

    #[cfg(test)]
    pub(super) fn reserved(&self) -> &HashSet<IdxPrefix> {
        &self.reserved
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
    use crate::key::PeerKey;
    use crate::packet::SessionIdx;
    use crate::tables::{PENDING_TTL, SESSION_TTL, Session, SessionLimits, SessionTable};
    use std::time::Duration;

    fn addr(i: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, i], 1))
    }

    /// A datagram of WireGuard message type `kind` and length `len`, carrying `idx` at offset 4.
    fn datagram_of(kind: u8, len: usize, idx: u32) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0] = kind;
        p[4..8].copy_from_slice(&idx.to_le_bytes());
        p
    }

    fn data(receiver: u32) -> Vec<u8> {
        datagram_of(4, 48, receiver)
    }

    fn cookie(receiver: u32) -> Vec<u8> {
        datagram_of(3, packet::COOKIE_LEN, receiver)
    }

    const OPEN: u32 = 0x10;
    const PENDING: u32 = 0x20;
    const RESERVED: u32 = 0x3005;

    /// A forwarder written by a session table: `OPEN` carries traffic from
    /// addr(1) to addr(2), `PENDING` awaits a handshake response, and prefix
    /// 0x30 is reserved, with an open session in it that must not be forwarded.
    fn setup(t0: Instant) -> Forwarder {
        let limits = SessionLimits { pending_per_peer: 8, per_peer: 8, total: 8 };
        let mut table = SessionTable::new(SESSION_TTL, PENDING_TTL, limits);
        let mut fwd = Forwarder::new(table.new_view());
        let peer = PeerKey::from([1; 32]);
        for (idx, s) in [
            (OPEN, Session::open(addr(2), addr(1), peer, t0)),
            (PENDING, Session::pending(addr(2), addr(1), peer, t0)),
            (RESERVED, Session::open(addr(2), addr(1), peer, t0)),
        ] {
            table.insert(idx.into(), s, &mut fwd.open).unwrap();
        }
        fwd.set_reserved([SessionIdx::from(RESERVED).prefix()]);
        fwd
    }

    #[test]
    fn forwards_data_and_cookie_replies_on_open_sessions_from_the_expected_source_only() {
        let t0 = Instant::now();
        let fwd = setup(t0);
        let later = t0 + SESSION_TTL - Duration::from_secs(1);
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
    fn hands_everything_else_to_the_control_half() {
        let t0 = Instant::now();
        let fwd = setup(t0);
        let init = datagram_of(1, packet::INIT_LEN, OPEN);
        let mut response = datagram_of(2, packet::RESP_LEN, 0x99);
        response[8..12].copy_from_slice(&OPEN.to_le_bytes());
        let cases = [
            (init, t0, "handshake initiation"),
            (response, t0, "handshake response, even to an open index"),
            (data(PENDING), t0, "transport data on a pending index"),
            (cookie(PENDING), t0, "cookie reply on a pending index"),
            (data(0x99), t0, "unknown index"),
            (data(RESERVED), t0, "a registration tunnel's prefix"),
            (data(OPEN), t0 + SESSION_TTL, "expired, not yet swept"),
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
