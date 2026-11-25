use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use super::Reason;
use crate::packet::{self, IdxPrefix, Packet};
use crate::tables::{OpenSessions, Route};

/// The forwarding half: forwards data and cookie replies on open sessions
/// from state it holds alone, writing nothing, and hands every other datagram
/// to the control half, its only writer.
pub(super) struct Forwarder {
    /// Open sessions, written only by the session table as its open entries change.
    pub(super) open: OpenSessions,
    /// Index prefixes of the relay's own tunnels, whose packets only the control half takes.
    reserved: HashSet<IdxPrefix>,
}

// Forwarding workers will share it, so it must stay plain shareable data.
const _: () = {
    const fn shareable<T: Send + Sync>() {}
    shareable::<Forwarder>();
};

/// What the forwarding half makes of a datagram it does not drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Lookup {
    /// Send it, unchanged, to this address.
    Forward(SocketAddr),
    /// Only the control half can decide: a handshake, a relay tunnel's packet,
    /// or an index that is not an open session (it may be pending, or unknown).
    NotMine(Packet),
}

impl Forwarder {
    pub(super) fn new(open: OpenSessions) -> Self {
        Forwarder { open, reserved: HashSet::new() }
    }

    /// Decide a datagram if open sessions alone can.
    pub(super) fn lookup(
        &self,
        src: SocketAddr,
        pkt: &[u8],
        now: Instant,
    ) -> Result<Lookup, Reason> {
        if !replyable(src) {
            return Err(Reason::InvalidSource);
        }
        let packet = packet::parse(pkt)?;
        let Some(route) = self.open_route(packet, now) else {
            return Ok(Lookup::NotMine(packet));
        };
        if src != route.expected_src {
            return Err(Reason::WrongSource);
        }
        Ok(Lookup::Forward(route.dest))
    }

    /// The live open session a data packet or cookie reply travels on; never
    /// one for a handshake or for an index a relay tunnel owns.
    fn open_route(&self, packet: Packet, now: Instant) -> Option<&Route> {
        let receiver = match packet {
            Packet::Init { .. } | Packet::Response { .. } => return None,
            Packet::Cookie { receiver } | Packet::Data { receiver } => receiver,
        };
        if self.reserved.contains(&receiver.prefix()) {
            return None;
        }
        self.open.get(receiver, now)
    }

    /// Replace the relay tunnels' index prefixes.
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
    fn message(kind: u8, len: usize, idx: u32) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0] = kind;
        p[4..8].copy_from_slice(&idx.to_le_bytes());
        p
    }

    fn data(receiver: u32) -> Vec<u8> {
        message(4, 48, receiver)
    }

    fn cookie(receiver: u32) -> Vec<u8> {
        message(3, packet::COOKIE_LEN, receiver)
    }

    const OPEN: u32 = 0x10;
    const PENDING: u32 = 0x20;
    const IN_TUNNEL_PREFIX: u32 = 0x3005;

    /// A forwarder written by a session table: `OPEN` carries traffic from
    /// addr(1) to addr(2), `PENDING` awaits a response, and prefix 0x30 is a
    /// relay tunnel's, with an open session in it that must not be forwarded.
    fn setup(t0: Instant) -> Forwarder {
        let limits = SessionLimits { pending_per_peer: 8, per_peer: 8, total: 8 };
        let mut table = SessionTable::new(SESSION_TTL, PENDING_TTL, limits);
        let mut fwd = Forwarder::new(table.new_view());
        let peer = PeerKey::from([1; 32]);
        for (idx, s) in [
            (OPEN, Session::open(addr(2), addr(1), peer, t0)),
            (PENDING, Session::pending(addr(2), addr(1), peer, t0)),
            (IN_TUNNEL_PREFIX, Session::open(addr(2), addr(1), peer, t0)),
        ] {
            table.insert(idx.into(), s, &mut fwd.open).unwrap();
        }
        fwd.set_reserved([SessionIdx::from(IN_TUNNEL_PREFIX).prefix()]);
        fwd
    }

    #[test]
    fn forwards_data_and_cookies_on_open_sessions_from_the_expected_source_only() {
        let t0 = Instant::now();
        let fwd = setup(t0);
        let later = t0 + SESSION_TTL - Duration::from_secs(1);
        for pkt in [data(OPEN), cookie(OPEN)] {
            assert_eq!(fwd.lookup(addr(1), &pkt, t0), Ok(Lookup::Forward(addr(2))));
            assert_eq!(fwd.lookup(addr(1), &pkt, later), Ok(Lookup::Forward(addr(2))));
            assert_eq!(fwd.lookup(addr(3), &pkt, t0), Err(Reason::WrongSource));
            assert_eq!(fwd.lookup(addr(2), &pkt, t0), Err(Reason::WrongSource), "reflected");
        }
    }

    #[test]
    fn hands_everything_else_to_the_control_half() {
        let t0 = Instant::now();
        let fwd = setup(t0);
        let init = message(1, packet::INIT_LEN, OPEN);
        let mut response = message(2, packet::RESP_LEN, 0x99);
        response[8..12].copy_from_slice(&OPEN.to_le_bytes());
        let cases = [
            (init, t0, "initiation"),
            (response, t0, "response, even to an open index"),
            (data(PENDING), t0, "data on a pending index"),
            (cookie(PENDING), t0, "cookie reply on a pending index"),
            (data(0x99), t0, "unknown index"),
            (data(IN_TUNNEL_PREFIX), t0, "a relay tunnel's prefix"),
            (data(OPEN), t0 + SESSION_TTL, "expired, not yet swept"),
        ];
        for (pkt, now, what) in cases {
            let packet = packet::parse(&pkt).unwrap();
            assert_eq!(fwd.lookup(addr(1), &pkt, now), Ok(Lookup::NotMine(packet)), "{what}");
        }
    }

    #[test]
    fn drops_unreplyable_sources_and_malformed_datagrams_first() {
        let t0 = Instant::now();
        let fwd = setup(t0);
        let broadcast = SocketAddr::from(([255, 255, 255, 255], 1));
        assert_eq!(fwd.lookup(broadcast, &data(OPEN), t0), Err(Reason::InvalidSource));
        assert_eq!(fwd.lookup(addr(1), &data(OPEN)[..20], t0), Err(Reason::Malformed));
    }
}
