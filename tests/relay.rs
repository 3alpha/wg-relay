//! In-process tests: boringtun peers talking through `Relay::handle`.
//!
//! Config used throughout: `main` and `other` are configured peers, registered at
//! SRV and SRV2; `c1` and `c2` are unconfigured peers.
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test setup panics on failure")]

mod common;
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Tunn, TunnResult};
use common::*;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use wg_relay::config::Config;
use wg_relay::relay::{DropReason, Relay, Verdict};

const SRV: &str = "198.51.100.1:51820";
const SRV2: &str = "198.51.100.2:51820";
const C1: &str = "198.51.100.11:40001";
const C2: &str = "198.51.100.12:40002";

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

struct W {
    relay: Relay,
    r: Key,
    srv: Key,
    srv2: Key,
    c1: Key,
    c2: Key,
}

/// A config with these peers.
fn config(r: &Key, peers: &[(&str, &Key)]) -> Config {
    let text = peers.iter().fold(head(r, ""), |text, (name, k)| text + &peer(name, k));
    Config::parse(&text).unwrap()
}

fn world() -> W {
    let (r, srv, srv2) = (key(), key(), key());
    let relay = Relay::new(&config(&r, &[("main", &srv), ("other", &srv2)]));
    let mut w = W { relay, r, srv, srv2, c1: key(), c2: key() };
    let (srv, srv2) = (w.srv.clone(), w.srv2.clone());
    w.register(&srv, SRV);
    w.register(&srv2, SRV2);
    w
}

impl W {
    /// Register configured peer `k` from `src` via a real handshake with the relay.
    fn register(&mut self, k: &Key, src: &str) -> Tunn {
        self.register_at(k, src, Instant::now())
    }

    /// `register`, with every packet arriving at `now`.
    fn register_at(&mut self, k: &Key, src: &str, now: Instant) -> Tunn {
        let mut t = tunn(k, &self.r);
        let init = initiation(&mut t);
        assert_eq!(self.relay.handle(addr(src), &init, now), Verdict::DeliveredLocally);
        let out = self.relay.drain_tx_queue();
        assert_eq!(out.len(), 1, "relay should answer the registration");
        let ka = reply(&mut t, &out[0].1).expect("keepalive to relay");
        assert_eq!(self.relay.handle(addr(src), &ka, now), Verdict::DeliveredLocally);
        assert_eq!(self.relay.registered_endpoint(&k.id(), now), Some(addr(src)));
        t
    }

    /// Where the relay forwarded the datagram, if anywhere.
    fn fwd(&mut self, src: &str, pkt: &[u8]) -> Option<SocketAddr> {
        self.fwd_at(src, pkt, Instant::now())
    }

    /// `fwd`, with the datagram arriving at `now`.
    fn fwd_at(&mut self, src: &str, pkt: &[u8], now: Instant) -> Option<SocketAddr> {
        match self.relay.handle(addr(src), pkt, now) {
            Verdict::Forward(dst) => Some(dst),
            Verdict::DeliveredLocally | Verdict::Drop(_) => None,
        }
    }

    /// How many datagrams were dropped for `r`.
    fn n(&self, r: DropReason) -> u64 {
        self.relay.metrics().rejected(r)
    }

    /// Handshake initiator -> responder through the relay; returns where the
    /// relay sent the initiation, the response, and the initiator's first keepalive.
    fn hs(&mut self, it: &mut Tunn, ia: &str, rt: &mut Tunn, ra: &str) -> [Option<SocketAddr>; 3] {
        let init = initiation(it);
        let a = self.fwd(ia, &init);
        let resp = reply(rt, &init).expect("responder answers");
        let b = self.fwd(ra, &resp);
        let ka = reply(it, &resp).expect("initiator keepalive");
        let c = self.fwd(ia, &ka);
        if c.is_some() {
            reply(rt, &ka); // responder confirms the session
        }
        [a, b, c]
    }

    /// Send a ping through the relay; returns where it went (and checks it decrypts).
    fn data(&mut self, from: &mut Tunn, fa: &str, to: &mut Tunn) -> Option<SocketAddr> {
        self.data_at(from, fa, to, Instant::now())
    }

    /// `data`, with the packet arriving at the relay at `now`.
    fn data_at(
        &mut self,
        from: &mut Tunn,
        fa: &str,
        to: &mut Tunn,
        now: Instant,
    ) -> Option<SocketAddr> {
        let p = ping([10, 99, 0, 11], [10, 99, 0, 1]);
        let pkt = encrypt(from, &p);
        assert_eq!(pkt[0], 4, "sender has no session");
        let dst = self.fwd_at(fa, &pkt, now)?;
        let mut buf = vec![0u8; 2048];
        match to.decapsulate(None, &pkt, &mut buf) {
            TunnResult::WriteToTunnelV4(got, _) => assert_eq!(got, &p[..]),
            other => panic!("forwarded data did not decrypt: {other:?}"),
        }
        Some(dst)
    }
}

fn ok3(a: &str, b: &str) -> [Option<SocketAddr>; 3] {
    [Some(addr(a)), Some(addr(b)), Some(addr(a))]
}

/// A distinct spoofed source for flood packet `i`, each in its own rate-limit bucket.
fn spoofed(i: u32) -> SocketAddr {
    SocketAddr::from(([10, (i >> 16) as u8, (i >> 8) as u8, i as u8], 1))
}

/// The index a handshake message announces as its sender.
fn sender_index(pkt: &[u8]) -> u32 {
    u32::from_le_bytes(pkt[4..8].try_into().unwrap())
}

/// A cookie-reply-shaped datagram for `receiver_index`.
fn cookie(receiver_index: u32) -> Vec<u8> {
    let mut p = vec![0u8; 64];
    p[0] = 3;
    p[4..8].copy_from_slice(&receiver_index.to_le_bytes());
    p
}

#[test]
fn unconfigured_peer_reaches_configured_peer() {
    let mut w = world();
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    assert_eq!(w.hs(&mut c1s, C1, &mut sc1, SRV), ok3(SRV, C1));
    assert_eq!(w.data(&mut c1s, C1, &mut sc1), Some(addr(SRV)));
    assert_eq!(w.data(&mut sc1, SRV, &mut c1s), Some(addr(C1)));
    // Client-initiated rekey.
    assert_eq!(w.hs(&mut c1s, C1, &mut sc1, SRV), ok3(SRV, C1));
    assert_eq!(w.data(&mut sc1, SRV, &mut c1s), Some(addr(C1)));

    // A peer that moves network loses data until it re-handshakes.
    let moved = "198.51.100.11:49999";
    assert_eq!(w.data(&mut c1s, moved, &mut sc1), None);
    assert_eq!(w.n(DropReason::WrongSource), 1);
    assert_eq!(w.hs(&mut c1s, moved, &mut sc1, SRV), ok3(SRV, moved));
}

#[test]
fn configured_peer_cannot_initiate_to_unconfigured_peer() {
    let mut w = world();
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    assert_eq!(w.hs(&mut c1s, C1, &mut sc1, SRV), ok3(SRV, C1));
    // The relay has no key to match the initiation's mac1 against.
    assert_eq!(w.fwd(SRV, &initiation(&mut sc1)), None);
    assert_eq!(w.n(DropReason::NoMac1Match), 1);
}

#[test]
fn configured_peers_reach_each_other_both_ways() {
    let mut w = world();
    let (mut ab, mut ba) = (tunn(&w.srv, &w.srv2), tunn(&w.srv2, &w.srv));
    assert_eq!(w.hs(&mut ab, SRV, &mut ba, SRV2), ok3(SRV2, SRV));
    assert_eq!(w.data(&mut ab, SRV, &mut ba), Some(addr(SRV2)));
    assert_eq!(w.hs(&mut ba, SRV2, &mut ab, SRV), ok3(SRV, SRV2));
    assert_eq!(w.data(&mut ba, SRV2, &mut ab), Some(addr(SRV)));
}

#[test]
fn unconfigured_peer_cannot_register() {
    let mut w = world();
    let mut c1r = tunn(&w.c1, &w.r);
    assert_eq!(w.fwd(C1, &initiation(&mut c1r)), None);
    assert_eq!(w.n(DropReason::RegistrationUnknownKey), 1);
    assert!(w.relay.drain_tx_queue().is_empty());
}

#[test]
fn only_the_configured_peer_answers_and_pending_carries_no_data() {
    let mut w = world();
    let mut c1s = tunn(&w.c1, &w.srv);
    let init = initiation(&mut c1s);
    assert_eq!(w.fwd(C1, &init), Some(addr(SRV)));
    // A response for c1's pending index from anywhere but the server is refused.
    let forged = forged_response(0x7000_0001, sender_index(&init), &w.c1.pk);
    assert_eq!(w.fwd(C2, &forged), None);
    assert_eq!(w.n(DropReason::WrongSource), 1);
    // Until the server answers, data towards c1 is refused; a cookie reply may pass.
    let mut fake = vec![4, 0, 0, 0];
    fake.extend_from_slice(&init[4..8]);
    fake.resize(48, 0);
    assert_eq!(w.fwd(SRV, &fake), None);
    assert_eq!(w.n(DropReason::UnknownIndex), 1);
    fake[0] = 3;
    fake.resize(64, 0);
    assert_eq!(w.fwd(SRV, &fake), Some(addr(C1)));
    assert_eq!(w.fwd(C2, &fake), None, "only from the expected source");
}

#[test]
fn unregistered_configured_peer_is_unreachable() {
    let (r, srv) = (key(), key());
    let mut relay = Relay::new(&config(&r, &[("main", &srv)]));
    let init = initiation(&mut tunn(&key(), &srv));
    assert_eq!(
        relay.handle(addr(C1), &init, Instant::now()),
        Verdict::Drop(DropReason::PeerNotRegistered)
    );
}

#[test]
fn reload_revokes_removed_peer_immediately() {
    let mut w = world();
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    let (mut c2o, mut oc2) = (tunn(&w.c2, &w.srv2), tunn(&w.srv2, &w.c2));
    assert_eq!(w.hs(&mut c1s, C1, &mut sc1, SRV), ok3(SRV, C1));
    assert_eq!(w.hs(&mut c2o, C2, &mut oc2, SRV2), ok3(SRV2, C2));

    // Remove `main`: its registration and every session routed to it go.
    w.relay.reload(&config(&w.r, &[("other", &w.srv2)]));
    assert_eq!(w.relay.registered_endpoint(&w.srv.id(), Instant::now()), None);
    assert_eq!(w.data(&mut c1s, C1, &mut sc1), None);
    assert_eq!(w.data(&mut sc1, SRV, &mut c1s), None);
    assert_eq!(w.n(DropReason::UnknownIndex), 2);
    assert_eq!(w.fwd(C1, &initiation(&mut c1s)), None);
    assert_eq!(w.n(DropReason::NoMac1Match), 1);
    // Sessions with `other` are untouched.
    assert_eq!(w.data(&mut c2o, C2, &mut oc2), Some(addr(SRV2)));
    assert_eq!(w.data(&mut oc2, SRV2, &mut c2o), Some(addr(C2)));
}

#[test]
fn registration_tunnel_indexes_are_reserved() {
    let mut w = world();
    // The registration tunnel's index, as seen in the relay's handshake response.
    let srv = w.srv.clone();
    let mut t = tunn(&srv, &w.r);
    let init = initiation(&mut t);
    w.fwd(SRV, &init);
    let resp = w.relay.drain_tx_queue().pop().unwrap().1;
    let relay_index = u32::from_le_bytes(resp[4..8].try_into().unwrap());
    // A forwarded initiation trying to use an index in its reserved prefix is refused.
    let mut c1s = tunn(&w.c1, &w.srv);
    let forged = with_sender(&initiation(&mut c1s), relay_index ^ 0x7f, &w.srv.pk);
    assert_eq!(w.fwd(C1, &forged), None);
    assert_eq!(w.n(DropReason::ReservedIndex), 1);
    let fine = with_sender(&initiation(&mut c1s), relay_index ^ 0x7f00_0000, &w.srv.pk);
    assert_eq!(w.fwd(C1, &fine), Some(addr(SRV)));
}

#[test]
fn established_session_cannot_mint_or_take_over_indexes() {
    let mut w = world();
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    let (mut c2s, mut sc2) = (tunn(&w.c2, &w.srv), tunn(&w.srv, &w.c2));
    let c1_init = initiation(&mut c1s);
    w.fwd(C1, &c1_init);
    let c1_resp = reply(&mut sc1, &c1_init).unwrap();
    assert_eq!(w.fwd(SRV, &c1_resp), Some(addr(C1)));
    let c2_init = initiation(&mut c2s);
    w.fwd(C2, &c2_init);
    let c2_resp = reply(&mut sc2, &c2_init).unwrap();
    assert_eq!(w.fwd(SRV, &c2_resp), Some(addr(C2)));
    reply(&mut c2s, &c2_resp);
    let sessions = w.relay.session_count();

    // c1 forges a response on its own, already established, session.
    let forged = forged_response(0x7000_0001, sender_index(&c1_resp), &w.srv.pk);
    assert_eq!(w.fwd(C1, &forged), None);
    assert_eq!(w.n(DropReason::SessionNotPending), 1);
    // A duplicate of the server's real response is refused the same way.
    assert_eq!(w.fwd(SRV, &c1_resp), None);
    assert_eq!(w.n(DropReason::SessionNotPending), 2);

    // c1 starts handshakes that claim c2's two live indexes.
    for index in [sender_index(&c2_init), sender_index(&c2_resp)] {
        let init = with_sender(&initiation(&mut c1s), index, &w.srv.pk);
        assert_eq!(w.fwd(C1, &init), None);
    }
    assert_eq!(w.n(DropReason::IndexInUse), 2);
    assert_eq!(w.relay.session_count(), sessions);
    assert_eq!(w.data(&mut c2s, C2, &mut sc2), Some(addr(SRV)));
    assert_eq!(w.data(&mut sc2, SRV, &mut c2s), Some(addr(C2)));
}

#[test]
fn registration_needs_key_confirmation() {
    let mut w = world();
    let srv = w.srv.clone();
    let moved = "203.0.113.9:1234";
    let mut t = tunn(&srv, &w.r);
    // A registration initiation alone (which could be a replay) does not move the registration.
    assert_eq!(w.fwd(moved, &initiation(&mut t)), None);
    let resp = w.relay.drain_tx_queue().pop().unwrap().1;
    assert_eq!(w.relay.registered_endpoint(&srv.id(), Instant::now()), Some(addr(SRV)));
    let ka = reply(&mut t, &resp).unwrap();
    assert_eq!(w.fwd(moved, &ka), None);
    assert_eq!(w.relay.registered_endpoint(&srv.id(), Instant::now()), Some(addr(moved)));
}

#[test]
fn pending_session_expires_quickly() {
    let mut w = world();
    let mut c1s = tunn(&w.c1, &w.srv);
    assert_eq!(w.fwd(C1, &initiation(&mut c1s)), Some(addr(SRV)));
    assert_eq!(w.relay.session_count(), 1);
    w.relay.tick(Instant::now() + Duration::from_secs(11));
    assert_eq!(w.relay.session_count(), 0);
}

#[test]
fn configured_peer_roaming_moves_its_sessions() {
    let mut w = world();
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    assert_eq!(w.hs(&mut c1s, C1, &mut sc1, SRV), ok3(SRV, C1));
    let srv = w.srv.clone();
    let moved = "198.51.100.1:60000";
    w.register(&srv, moved);
    assert_eq!(w.data(&mut c1s, C1, &mut sc1), Some(addr(moved)));
    assert_eq!(w.data(&mut sc1, moved, &mut c1s), Some(addr(C1)));
}

#[test]
fn relay_key_cannot_open_forwarded_initiation_and_ping_works() {
    let mut w = world();
    let mut c1s = tunn(&w.c1, &w.srv);
    let init = initiation(&mut c1s);
    assert_eq!(w.fwd(C1, &init), Some(addr(SRV)));
    let Ok(boringtun::noise::Packet::HandshakeInit(h)) = Tunn::parse_incoming_packet(&init) else {
        panic!()
    };
    assert!(parse_handshake_anon(&w.r.sk, &w.r.pk, &h).is_err(), "relay must not decrypt");
    assert!(parse_handshake_anon(&w.srv.sk, &w.srv.pk, &h).is_ok());

    let srv = w.srv.clone();
    let mut sr = w.register(&srv, SRV);
    assert_eq!(w.fwd(SRV, &encrypt(&mut sr, &ping([10, 99, 0, 1], [10, 99, 0, 254]))), None);
    let out = w.relay.drain_tx_queue();
    let mut buf = vec![0u8; 2048];
    assert!(
        matches!(sr.decapsulate(None, &out[0].1, &mut buf), TunnResult::WriteToTunnelV4(p, _) if p[20] == 0)
    );
}

#[test]
fn expiry_and_rate_limit() {
    let mut w = world();
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    assert_eq!(w.hs(&mut c1s, C1, &mut sc1, SRV), ok3(SRV, C1));
    w.relay.tick(Instant::now() + Duration::from_secs(181));
    assert_eq!(
        w.relay.registered_endpoint(&w.srv.id(), Instant::now() + Duration::from_secs(181)),
        None
    );
    w.relay.tick(Instant::now() + Duration::from_secs(201));
    assert!(w.relay.session_count() == 0);

    let mut w = world();
    let mut c1s = tunn(&w.c1, &w.srv);
    let init = initiation(&mut c1s);
    let ok = (0..100).filter(|_| w.fwd(C1, &init).is_some()).count();
    assert_eq!(ok, 20, "default 10/s => burst of 20");
    assert_eq!(w.n(DropReason::RateLimited), 80);
}

#[test]
fn garbage_never_panics() {
    let mut w = world();
    let srv = w.srv.clone();
    let mut sr = w.register(&srv, SRV);
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    let init = initiation(&mut c1s);
    let resp = reply(&mut sc1, &init).unwrap();
    let seeds = [
        init,
        resp,
        encrypt(&mut sr, &ping([10, 99, 0, 1], [10, 99, 0, 254])),
        initiation(&mut sr),
    ];
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for i in 0..10_000 {
        let mut p = seeds[i % seeds.len()].clone();
        match rnd() % 4 {
            0 => p.truncate((rnd() % 200) as usize),
            1 => p = (0..rnd() % 300).map(|_| rnd() as u8).collect(),
            _ => {
                for _ in 0..1 + rnd() % 4 {
                    let j = (rnd() as usize) % p.len();
                    p[j] = rnd() as u8;
                }
            }
        }
        if let (0, Some(b)) = (rnd() % 2, p.first_mut()) {
            *b = 1 + (rnd() % 4) as u8;
        }
        let src = [SRV, C1, C2][(rnd() % 3) as usize];
        w.fwd(src, &p);
        w.relay.drain_tx_queue();
    }
    assert!(w.n(DropReason::Malformed) > 500, "{}", w.relay.metrics());
}

#[test]
fn registration_flood_does_not_block_registered_peers() {
    let mut w = world();
    let now = Instant::now();
    // Registration initiations from unregistered sources, more than the
    // registration budget's burst. All arrive at `now`, so nothing refills.
    let junk = with_sender(&initiation(&mut tunn(&w.c1, &w.r)), 0x5000_0000, &w.r.pk);
    for i in 0..600 {
        w.relay.handle(spoofed(i), &junk, now);
    }
    assert!(w.n(DropReason::RegistrationBudget) > 0, "{}", w.relay.metrics());
    // A configured peer re-handshakes from its endpoint all the same.
    let srv = w.srv.clone();
    w.register_at(&srv, SRV, now);
    // Registering from a new address competes with the flood.
    let mut t = tunn(&srv, &w.r);
    let moved = addr("203.0.113.9:1234");
    let shed = Verdict::Drop(DropReason::RegistrationBudget);
    assert_eq!(w.relay.handle(moved, &initiation(&mut t), now), shed);
    // Forwarded handshakes have their own budget.
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    assert_eq!(w.hs(&mut c1s, C1, &mut sc1, SRV), ok3(SRV, C1));
}

#[test]
fn pending_flood_aimed_at_one_peer_evicts_only_its_oldest() {
    const QUOTA: u32 = 1024;
    let mut w = world();
    let flood = |w: &mut W, from: u32, n: u32| {
        let template = initiation(&mut tunn(&key(), &w.srv));
        for i in from..from + n {
            let init = with_sender(&template, 0x5000_0000 + i, &w.srv.pk);
            assert_eq!(
                w.relay.handle(spoofed(i), &init, Instant::now()),
                Verdict::Forward(addr(SRV))
            );
        }
    };
    // A handshake answered while the peer is at quota survives.
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    let c1_init = initiation(&mut c1s);
    assert_eq!(w.fwd(C1, &c1_init), Some(addr(SRV)));
    flood(&mut w, 0, QUOTA - 1);
    assert_eq!(w.fwd(SRV, &reply(&mut sc1, &c1_init).unwrap()), Some(addr(C1)));

    // One that is still pending once QUOTA newer ones arrive is evicted, but
    // only towards the flooded peer.
    let (mut c2o, mut oc2) = (tunn(&w.c2, &w.srv2), tunn(&w.srv2, &w.c2));
    let c2_init = initiation(&mut c2o);
    assert_eq!(w.fwd(C2, &c2_init), Some(addr(SRV2)));
    let c1_init = initiation(&mut c1s);
    assert_eq!(w.fwd(C1, &c1_init), Some(addr(SRV)));
    flood(&mut w, QUOTA, QUOTA);
    assert_eq!(w.fwd(SRV, &reply(&mut sc1, &c1_init).unwrap()), None);
    assert_eq!(w.n(DropReason::UnknownIndex), 1);
    assert_eq!(w.fwd(SRV2, &reply(&mut oc2, &c2_init).unwrap()), Some(addr(C2)));
    // c1's earlier session, c2's new one and QUOTA flood entries remain.
    assert_eq!(w.relay.session_count(), 2 + 2 + QUOTA as usize);
    assert_eq!(w.relay.metrics().pending_evicted, u64::from(QUOTA), "c1's entry and the flood's");
}

#[test]
fn established_session_expires_on_time_however_busy() {
    let mut w = world();
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    assert_eq!(w.hs(&mut c1s, C1, &mut sc1, SRV), ok3(SRV, C1));
    let established = Instant::now();
    let at = |s: u64| established + Duration::from_secs(s);
    for s in (10..200).step_by(10).chain([199]) {
        assert_eq!(w.data_at(&mut c1s, C1, &mut sc1, at(s)), Some(addr(SRV)), "{s} s");
        assert_eq!(w.data_at(&mut sc1, SRV, &mut c1s, at(s)), Some(addr(C1)), "{s} s");
    }
    // WireGuard has rekeyed by now and never uses this session's keys again.
    assert_eq!(w.data_at(&mut c1s, C1, &mut sc1, at(200)), None);
    assert_eq!(w.data_at(&mut sc1, SRV, &mut c1s, at(200)), None);
    assert_eq!(w.n(DropReason::UnknownIndex), 2);
}

#[test]
fn cookie_replies_do_not_extend_a_pending_session() {
    let mut w = world();
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    let t0 = Instant::now();
    let init = initiation(&mut c1s);
    assert_eq!(w.fwd_at(C1, &init, t0), Some(addr(SRV)));
    let reply_cookie = cookie(sender_index(&init));
    for s in [1, 5, 9] {
        let t = t0 + Duration::from_secs(s);
        assert_eq!(w.fwd_at(SRV, &reply_cookie, t), Some(addr(C1)), "{s} s");
    }
    let t = t0 + Duration::from_secs(10);
    assert_eq!(w.fwd_at(SRV, &reply_cookie, t), None);
    assert_eq!(w.fwd_at(SRV, &reply(&mut sc1, &init).unwrap(), t), None, "too late to establish");
    assert_eq!(w.n(DropReason::UnknownIndex), 2);
}

#[test]
fn resent_initiation_cannot_reset_an_established_session() {
    let mut w = world();
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    let init = initiation(&mut c1s);
    // While pending, a duplicate initiation is forwarded again.
    assert_eq!(w.fwd(C1, &init), Some(addr(SRV)));
    assert_eq!(w.fwd(C1, &init), Some(addr(SRV)));
    let resp = reply(&mut sc1, &init).unwrap();
    assert_eq!(w.fwd(SRV, &resp), Some(addr(C1)));
    let ka = reply(&mut c1s, &resp).unwrap();
    assert_eq!(w.fwd(C1, &ka), Some(addr(SRV)));
    reply(&mut sc1, &ka);
    // Once established, neither a replay of it nor a new initiation reusing its
    // index may turn the entry back into a pending one or restart its lifetime.
    let reuse = with_sender(&initiation(&mut c1s), sender_index(&init), &w.srv.pk);
    assert_eq!(w.fwd(C1, &init), None);
    assert_eq!(w.fwd(C1, &reuse), None);
    assert_eq!(w.n(DropReason::IndexInUse), 2);
    assert_eq!(w.data(&mut sc1, SRV, &mut c1s), Some(addr(C1)));
}

#[test]
fn ipv4_mapped_source_is_a_normal_peer() {
    let mut w = world();
    let mapped = "[::ffff:198.51.100.11]:40001";
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    assert_eq!(w.hs(&mut c1s, mapped, &mut sc1, SRV), ok3(SRV, mapped));
    assert_eq!(w.data(&mut sc1, SRV, &mut c1s), Some(addr(mapped)));
    assert_eq!(w.fwd("[::ffff:255.255.255.255]:40001", &initiation(&mut c1s)), None);
    assert_eq!(w.n(DropReason::InvalidSource), 1);
}
