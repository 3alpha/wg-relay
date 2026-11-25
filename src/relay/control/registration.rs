use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;

use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Tunn, TunnResult};
use tracing::{debug, info};

use super::{Accepted, Control, PeerState, REGISTRATION_WORK, Reason};
use crate::key::PeerKey;

/// Whether a datagram on a registration tunnel proved its peer live at the source address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Proof {
    Live,
    Unproven,
}

impl Proof {
    /// A transport data message (type 4) on the tunnel proves it; a handshake
    /// message (which can be replayed) or a cookie reply does not.
    fn of_transport(datagram: &[u8]) -> Self {
        match datagram.first() {
            Some(4) => Proof::Live,
            _ => Proof::Unproven,
        }
    }
}

impl Control {
    /// Decide whether a relay-bound initiation may cost an X25519 operation.
    /// A registered peer's address skips the registration budget, so a flood from
    /// elsewhere cannot stop it re-handshaking; its per-source limit still applies.
    pub(super) fn admit_registration(
        &mut self,
        src: SocketAddr,
        now: Instant,
    ) -> Result<(), Reason> {
        if self.registry.is_registered(src, now) {
            return Ok(());
        }
        if !self.registration_budget.available(now) {
            return Err(Reason::RegistrationBudget);
        }
        self.registration_budget.spend(REGISTRATION_WORK);
        Ok(())
    }

    /// Identify the sender of a relay-bound initiation, then let its
    /// registration tunnel fully authenticate it.
    pub(super) fn register_init(
        &mut self,
        src: SocketAddr,
        pkt: &[u8],
        now: Instant,
    ) -> Result<Accepted, Reason> {
        let half = match Tunn::parse_incoming_packet(pkt) {
            Ok(boringtun::noise::Packet::HandshakeInit(h)) => {
                parse_handshake_anon(&self.secret, &self.public, &h).ok()
            }
            _ => None,
        };
        let key = half.map(|h| PeerKey::from(h.peer_static_public)).ok_or(Reason::TunnelAuth)?;
        if !self.peers.contains_key(&key) {
            debug!(%src, %key, "registration from unlisted key");
            return Err(Reason::UnknownKey);
        }
        self.tunnel_rx(key, src, pkt, now)
    }

    /// Feed a datagram to peer `key`'s registration tunnel; once it proves
    /// the peer live, (re-)register the source address.
    pub(super) fn tunnel_rx(
        &mut self,
        key: PeerKey,
        src: SocketAddr,
        pkt: &[u8],
        now: Instant,
    ) -> Result<Accepted, Reason> {
        match self.decapsulate(key, src, pkt)? {
            Proof::Live => self.confirm(key, src, now),
            Proof::Unproven => {}
        }
        Ok(Accepted::Consumed)
    }

    /// Run a datagram through peer `key`'s tunnel and queue whatever the
    /// tunnel answers, including echo replies to pings for the relay.
    fn decapsulate(&mut self, key: PeerKey, src: SocketAddr, pkt: &[u8]) -> Result<Proof, Reason> {
        let Some(PeerState { name, tunn }) = self.peers.get_mut(&key) else {
            return Err(Reason::TunnelAuth);
        };
        match tunn.decapsulate(Some(src.ip()), pkt, &mut self.scratch) {
            TunnResult::Err(e) => {
                debug!(%src, peer = %name, ?e, "registration tunnel rejected packet");
                Err(Reason::TunnelAuth)
            }
            TunnResult::WriteToNetwork(out) => {
                // Only our keepalive, sent once the peer's response checks out, proves
                // the sender is live. Our response to an initiation does not (an
                // initiation can be replayed), nor does a cookie reply under load.
                let proof = Proof::of_transport(out);
                self.outbox.push((src, out.to_vec()));
                while let TunnResult::WriteToNetwork(q) =
                    tunn.decapsulate(None, &[], &mut self.scratch)
                {
                    self.outbox.push((src, q.to_vec()));
                }
                Ok(proof)
            }
            TunnResult::WriteToTunnelV4(ip, _) => {
                if let Some(reply) = icmp_echo_reply(ip, self.tunnel_ip)
                    && let TunnResult::WriteToNetwork(out) =
                        tunn.encapsulate(&reply, &mut self.scratch)
                {
                    self.outbox.push((src, out.to_vec()));
                }
                Ok(Proof::Live)
            }
            TunnResult::WriteToTunnelV6(..) => Ok(Proof::Live),
            // Keepalive (authenticated) or an incoming cookie reply (not).
            TunnResult::Done => Ok(Proof::of_transport(pkt)),
        }
    }

    /// Record that `key` is live at `src`; if it moved there, its sessions move too.
    pub(super) fn confirm(&mut self, key: PeerKey, src: SocketAddr, now: Instant) {
        let Some(old) = self.registry.update(key, src, now) else { return };
        let name = self.peers.get(&key).map_or("?", |p| &p.name);
        info!(peer = %name, addr = %src, old = ?old, "registered");
        if let Some(old) = old {
            self.sessions.migrate(old, src, &mut self.forwarder.open);
        }
    }
}

/// If `ip` is an ICMP echo request to `me`, build the echo reply.
fn icmp_echo_reply(ip: &[u8], me: Ipv4Addr) -> Option<Vec<u8>> {
    let ihl = usize::from(*ip.first()? & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]));
    if ip[0] >> 4 != 4 || ihl < 20 || total > ip.len() || total < ihl + 8 {
        return None;
    }
    if ip[9] != 1 || ip[16..20] != me.octets() || ip[ihl] != 8 {
        return None;
    }
    // A fragment (more-fragments flag or a non-zero offset) is not a whole echo request.
    if ip[6] & 0x3f != 0 || ip[7] != 0 {
        return None;
    }
    let mut r = ip[..total].to_vec();
    let (src, dst) = ([r[12], r[13], r[14], r[15]], [r[16], r[17], r[18], r[19]]);
    r[12..16].copy_from_slice(&dst);
    r[16..20].copy_from_slice(&src);
    r[8] = 64;
    r[ihl] = 0;
    r[ihl + 2..ihl + 4].fill(0);
    let c = checksum(&r[ihl..]);
    r[ihl + 2..ihl + 4].copy_from_slice(&c.to_be_bytes());
    r[10..12].fill(0);
    let c = checksum(&r[..ihl]);
    r[10..12].copy_from_slice(&c.to_be_bytes());
    Some(r)
}

fn checksum(b: &[u8]) -> u16 {
    let mut sum: u32 =
        b.chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))).sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_reply_swaps_addresses_and_fixes_checksums() {
        let me = Ipv4Addr::new(10, 99, 0, 1);
        let mut req = vec![0x45, 0, 0, 28, 0, 1, 0, 0, 64, 1, 0, 0, 10, 99, 0, 2, 10, 99, 0, 1];
        req.extend_from_slice(&[8, 0, 0, 0, 0x12, 0x34, 0, 1]);
        let c = checksum(&req[..20]);
        req[10..12].copy_from_slice(&c.to_be_bytes());
        let r = icmp_echo_reply(&req, me).unwrap();
        assert_eq!(&r[12..16], &[10, 99, 0, 1]);
        assert_eq!(&r[16..20], &[10, 99, 0, 2]);
        assert_eq!(r[20], 0);
        assert_eq!(checksum(&r[..20]), 0);
        assert_eq!(checksum(&r[20..]), 0);
        assert!(icmp_echo_reply(&req[..10], me).is_none());
        let mut fragment = req.clone();
        fragment[6] = 0x20;
        assert!(icmp_echo_reply(&fragment, me).is_none());
        assert!(icmp_echo_reply(&req, Ipv4Addr::new(1, 2, 3, 4)).is_none());
    }
}
