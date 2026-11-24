//! In-process tests of every gate mode: boringtun peers talking through `Relay::handle`.
//!
//! Config used throughout: servers `main` and `other`; clients `c1` -> main,
//! `c2` -> other, `c3` -> main; `st` (stranger) is not listed anywhere.
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test setup panics on failure")]

mod common;
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Tunn, TunnResult};
use common::*;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use wg_relay::config::Config;
use wg_relay::relay::{Reason, Relay};

const SRV: &str = "198.51.100.1:51820";
const SRV2: &str = "198.51.100.2:51820";
const C1: &str = "198.51.100.11:40001";
const C2: &str = "198.51.100.12:40002";
const C3: &str = "198.51.100.13:40003";
const ST: &str = "198.51.100.66:40066";

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
    c3: Key,
    st: Key,
}

fn config(w: &W, gate: &str, clients: &[(&str, &Key, &str)]) -> Config {
    let mut s = format!(
        "private_key = \"{}\"\ntunnel_ip = \"10.99.0.254\"\nclient_gate = \"{gate}\"\n\
         [[server]]\nname = \"main\"\npubkey = \"{}\"\n[[server]]\nname = \"other\"\npubkey = \"{}\"\n",
        b64_sk(&w.r),
        b64(&w.srv.pk),
        b64(&w.srv2.pk)
    );
    for (name, k, servers) in clients {
        s += &format!("[[client]]\nname = \"{name}\"\npubkey = \"{}\"\nservers = [{servers}]\n", b64(&k.pk));
    }
    Config::parse(&s).unwrap()
}

fn world(gate: &str) -> W {
    let r = key();
    let mut w = W {
        relay: Relay::new(&dummy(&r)),
        r,
        srv: key(),
        srv2: key(),
        c1: key(),
        c2: key(),
        c3: key(),
        st: key(),
    };
    let (c1, c2, c3) = (w.c1.clone(), w.c2.clone(), w.c3.clone());
    let cfg = config(&w, gate, &[("c1", &c1, "\"main\""), ("c2", &c2, "\"other\""), ("c3", &c3, "\"main\"")]);
    w.relay = Relay::new(&cfg);
    let (srv, srv2) = (w.srv.clone(), w.srv2.clone());
    w.register(&srv, SRV);
    w.register(&srv2, SRV2);
    w
}

fn dummy(r: &Key) -> Config {
    let s = format!(
        "private_key = \"{}\"\ntunnel_ip = \"10.99.0.254\"\n[[server]]\nname = \"x\"\npubkey = \"{}\"\n",
        b64_sk(r),
        b64(&key().pk)
    );
    Config::parse(&s).unwrap()
}

impl W {
    /// Register `k` from `src` via a real handshake with the relay.
    fn register(&mut self, k: &Key, src: &str) -> Tunn {
        let mut t = tunn(k, &self.r);
        let init = initiation(&mut t);
        assert_eq!(self.fwd(src, &init), None);
        let out = std::mem::take(&mut self.relay.outbox);
        assert_eq!(out.len(), 1, "relay should answer the registration");
        let ka = reply(&mut t, &out[0].1).expect("keepalive to relay");
        assert_eq!(self.fwd(src, &ka), None);
        assert_eq!(self.relay.registry.addr(&k.id(), Instant::now()), Some(addr(src)));
        t
    }

    fn fwd(&mut self, src: &str, pkt: &[u8]) -> Option<SocketAddr> {
        self.relay.handle(addr(src), pkt, Instant::now())
    }

    fn n(&self, r: Reason) -> u64 {
        self.relay.metrics.rejected(r)
    }
}

/// Handshake initiator -> responder through the relay; returns where the
/// relay sent the initiation, the response, and the initiator's first keepalive.
fn hs(w: &mut W, it: &mut Tunn, ia: &str, rt: &mut Tunn, ra: &str) -> [Option<SocketAddr>; 3] {
    let init = initiation(it);
    let a = w.fwd(ia, &init);
    let resp = reply(rt, &init).expect("responder answers");
    let b = w.fwd(ra, &resp);
    let ka = reply(it, &resp).expect("initiator keepalive");
    let c = w.fwd(ia, &ka);
    if c.is_some() {
        reply(rt, &ka); // responder confirms the session
    }
    [a, b, c]
}

/// Send a ping through the relay; returns where it went (and checks it decrypts).
fn data(w: &mut W, from: &mut Tunn, fa: &str, to: &mut Tunn) -> Option<SocketAddr> {
    let p = ping([10, 99, 0, 11], [10, 99, 0, 1]);
    let pkt = encrypt(from, &p);
    assert_eq!(pkt[0], 4, "sender has no session");
    let dst = w.fwd(fa, &pkt)?;
    let mut buf = vec![0u8; 2048];
    match to.decapsulate(None, &pkt, &mut buf) {
        TunnResult::WriteToTunnelV4(got, _) => assert_eq!(got, &p[..]),
        other => panic!("forwarded data did not decrypt: {other:?}"),
    }
    Some(dst)
}

fn ok3(a: &str, b: &str) -> [Option<SocketAddr>; 3] {
    [Some(addr(a)), Some(addr(b)), Some(addr(a))]
}

#[test]
fn gate_none() {
    let mut w = world("none");
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    // Listed client, never registered: works.
    assert_eq!(hs(&mut w, &mut c1s, C1, &mut sc1, SRV), ok3(SRV, C1));
    assert_eq!(data(&mut w, &mut c1s, C1, &mut sc1), Some(addr(SRV)));
    assert_eq!(data(&mut w, &mut sc1, SRV, &mut c1s), Some(addr(C1)));
    // Server-initiated rekey to the learned client address.
    assert_eq!(hs(&mut w, &mut sc1, SRV, &mut c1s, C1), ok3(C1, SRV));
    assert_eq!(data(&mut w, &mut c1s, C1, &mut sc1), Some(addr(SRV)));

    // Unlisted client the *server* accepts: the relay does not gate it.
    let (mut sts, mut sst) = (tunn(&w.st, &w.srv), tunn(&w.srv, &w.st));
    assert_eq!(hs(&mut w, &mut sts, ST, &mut sst, SRV), ok3(SRV, ST));
    assert_eq!(data(&mut w, &mut sts, ST, &mut sst), Some(addr(SRV)));
    // ...but the server cannot initiate to it (no key to match).
    assert_eq!(w.fwd(SRV, &initiation(&mut sst)), None);
    assert_eq!(w.n(Reason::NoMac1Match), 1);

    // Clients cannot register in this mode.
    let mut c1r = tunn(&w.c1, &w.r);
    assert_eq!(w.fwd(C1, &initiation(&mut c1r)), None);
    assert_eq!(w.n(Reason::ClientRegistrationOff), 1);
}

#[test]
fn gate_response() {
    let mut w = world("response");
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    assert_eq!(hs(&mut w, &mut c1s, C1, &mut sc1, SRV), ok3(SRV, C1));
    assert_eq!(data(&mut w, &mut sc1, SRV, &mut c1s), Some(addr(C1)));
    assert_eq!(hs(&mut w, &mut sc1, SRV, &mut c1s, C1), ok3(C1, SRV), "server rekey");

    // Stranger: its initiation reaches the server (any source), but even a
    // server that answers it gets its response dropped.
    let (mut sts, mut sst) = (tunn(&w.st, &w.srv), tunn(&w.srv, &w.st));
    let init = initiation(&mut sts);
    assert_eq!(w.fwd(ST, &init), Some(addr(SRV)));
    assert_eq!(w.fwd(SRV, &reply(&mut sst, &init).unwrap()), None);
    assert_eq!(w.n(Reason::ResponseUnknownClient), 1);
    // The stranger's index stays pending: data towards it is refused, a cookie may pass.
    let mut fake = vec![4, 0, 0, 0];
    fake.extend_from_slice(&init[4..8]);
    fake.resize(48, 0);
    assert_eq!(w.fwd(SRV, &fake), None);
    assert_eq!(w.n(Reason::SessionNotOpen), 1);
    fake[0] = 3;
    fake.resize(64, 0);
    assert_eq!(w.fwd(SRV, &fake), Some(addr(ST)));
    assert_eq!(w.fwd(C1, &fake), None, "only from the expected source");

    // c2 is listed but may only reach `other`.
    let (mut c2s, mut sc2) = (tunn(&w.c2, &w.srv), tunn(&w.srv, &w.c2));
    assert_eq!(hs(&mut w, &mut c2s, C2, &mut sc2, SRV)[1], None);
    assert_eq!(w.n(Reason::Acl), 1);
    let (mut c2o, mut oc2) = (tunn(&w.c2, &w.srv2), tunn(&w.srv2, &w.c2));
    assert_eq!(hs(&mut w, &mut c2o, C2, &mut oc2, SRV2), ok3(SRV2, C2));

    // A client that moves network loses data until it re-handshakes.
    let moved = "198.51.100.11:49999";
    assert_eq!(data(&mut w, &mut c1s, moved, &mut sc1), None);
    assert_eq!(w.n(Reason::WrongSource), 2);
    assert_eq!(hs(&mut w, &mut c1s, moved, &mut sc1, SRV), ok3(SRV, moved));
}

#[test]
fn gate_register() {
    let mut w = world("register");
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    // Not registered yet: dropped before reaching the server.
    assert_eq!(w.fwd(C1, &initiation(&mut c1s)), None);
    assert_eq!(w.n(Reason::SrcNotRegisteredClient), 1);
    let c1 = w.c1.clone();
    w.register(&c1, C1);
    assert_eq!(hs(&mut w, &mut c1s, C1, &mut sc1, SRV), ok3(SRV, C1));
    assert_eq!(data(&mut w, &mut c1s, C1, &mut sc1), Some(addr(SRV)));
    assert_eq!(hs(&mut w, &mut sc1, SRV, &mut c1s, C1), ok3(C1, SRV), "server rekey");
    assert_eq!(data(&mut w, &mut sc1, SRV, &mut c1s), Some(addr(C1)));

    // Stranger: cannot register, and its initiations never reach the server.
    let mut str_ = tunn(&w.st, &w.r);
    assert_eq!(w.fwd(ST, &initiation(&mut str_)), None);
    assert_eq!(w.n(Reason::UnknownKey), 1);
    let mut sts = tunn(&w.st, &w.srv);
    assert_eq!(w.fwd(ST, &initiation(&mut sts)), None);
    assert_eq!(w.n(Reason::SrcNotRegisteredClient), 2);

    // Registered c2 may not reach main.
    let c2 = w.c2.clone();
    w.register(&c2, C2);
    let mut c2s = tunn(&w.c2, &w.srv);
    assert_eq!(w.fwd(C2, &initiation(&mut c2s)), None);
    assert_eq!(w.n(Reason::Acl), 1);

    // Key/address binding: c3's handshake sent from c1's registered address.
    let c3 = w.c3.clone();
    w.register(&c3, C3);
    let (mut c3s, mut sc3) = (tunn(&w.c3, &w.srv), tunn(&w.srv, &w.c3));
    assert_eq!(hs(&mut w, &mut c3s, C1, &mut sc3, SRV)[..2], [Some(addr(SRV)), None]);
    assert_eq!(w.n(Reason::ClientAddrMismatch), 1);

    // Only a registered server may initiate towards a client.
    let mut fake = tunn(&w.c3, &w.c1);
    assert_eq!(w.fwd(C3, &initiation(&mut fake)), None);
    assert_eq!(w.n(Reason::RekeyNotFromServer), 1);
}

#[test]
fn reload_revokes_immediately() {
    let mut w = world("register");
    let (c1k, c3k) = (w.c1.clone(), w.c3.clone());
    w.register(&c1k, C1);
    w.register(&c3k, C3);
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    let (mut c3s, mut sc3) = (tunn(&w.c3, &w.srv), tunn(&w.srv, &w.c3));
    assert_eq!(hs(&mut w, &mut c1s, C1, &mut sc1, SRV), ok3(SRV, C1));
    assert_eq!(hs(&mut w, &mut c3s, C3, &mut sc3, SRV), ok3(SRV, C3));

    // Remove c1 entirely, and take `main` away from c3.
    let cfg = config(&w, "register", &[("c3", &c3k, "\"other\"")]);
    w.relay.reload(&cfg);
    assert_eq!(w.relay.registry.addr(&c1k.id(), Instant::now()), None);
    assert!(w.relay.sessions.is_empty(), "both sessions revoked");
    assert_eq!(data(&mut w, &mut c1s, C1, &mut sc1), None);
    assert_eq!(data(&mut w, &mut sc3, SRV, &mut c3s), None);
    assert_eq!(w.n(Reason::UnknownIndex), 2);
    // c3 is still registered (it is still a client), but may not reach main.
    assert!(w.relay.registry.addr(&c3k.id(), Instant::now()).is_some());
    assert_eq!(w.fwd(C3, &initiation(&mut c3s)), None);
    assert_eq!(w.n(Reason::Acl), 1);
    // Servers keep their registrations.
    assert!(w.relay.registry.addr(&w.srv.id(), Instant::now()).is_some());

    // Switching to `response` drops client registrations.
    let cfg = config(&w, "response", &[("c3", &c3k, "\"main\"")]);
    w.relay.reload(&cfg);
    assert_eq!(w.relay.registry.addr(&c3k.id(), Instant::now()), None);
    assert_eq!(hs(&mut w, &mut c3s, C3, &mut sc3, SRV), ok3(SRV, C3));
}

#[test]
fn relay_indexes_are_reserved() {
    let mut w = world("none");
    // The relay's own session index, as seen in its handshake response.
    let srv = w.srv.clone();
    let mut t = tunn(&srv, &w.r);
    let init = initiation(&mut t);
    w.fwd(SRV, &init);
    let resp = w.relay.outbox.pop().unwrap().1;
    let relay_idx = u32::from_le_bytes(resp[4..8].try_into().unwrap());
    // A forwarded handshake trying to use an index in the relay's range is refused.
    let mut c1s = tunn(&w.c1, &w.srv);
    let forged = with_sender(&initiation(&mut c1s), relay_idx ^ 0x7f, &w.srv.pk);
    assert_eq!(w.fwd(C1, &forged), None);
    assert_eq!(w.n(Reason::ReservedIndex), 1);
    let fine = with_sender(&initiation(&mut c1s), relay_idx ^ 0x7f00_0000, &w.srv.pk);
    assert_eq!(w.fwd(C1, &fine), Some(addr(SRV)));
}

#[test]
fn server_roaming_migrates_sessions() {
    let mut w = world("response");
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    assert_eq!(hs(&mut w, &mut c1s, C1, &mut sc1, SRV), ok3(SRV, C1));
    let srv = w.srv.clone();
    let moved = "198.51.100.1:60000";
    w.register(&srv, moved);
    assert_eq!(data(&mut w, &mut c1s, C1, &mut sc1), Some(addr(moved)));
    assert_eq!(data(&mut w, &mut sc1, moved, &mut c1s), Some(addr(C1)));
}

#[test]
fn relay_key_cannot_open_forwarded_initiation_and_ping_works() {
    let mut w = world("response");
    let mut c1s = tunn(&w.c1, &w.srv);
    let init = initiation(&mut c1s);
    assert_eq!(w.fwd(C1, &init), Some(addr(SRV)));
    let Ok(boringtun::noise::Packet::HandshakeInit(h)) = Tunn::parse_incoming_packet(&init) else { panic!() };
    assert!(parse_handshake_anon(&w.r.sk, &w.r.pk, &h).is_err(), "relay must not decrypt");
    assert!(parse_handshake_anon(&w.srv.sk, &w.srv.pk, &h).is_ok());

    let srv = w.srv.clone();
    let mut sr = w.register(&srv, SRV);
    assert_eq!(w.fwd(SRV, &encrypt(&mut sr, &ping([10, 99, 0, 1], [10, 99, 0, 254]))), None);
    let out = std::mem::take(&mut w.relay.outbox);
    let mut buf = vec![0u8; 2048];
    assert!(
        matches!(sr.decapsulate(None, &out[0].1, &mut buf), TunnResult::WriteToTunnelV4(p, _) if p[20] == 0)
    );
}

#[test]
fn expiry_and_rate_limit() {
    let mut w = world("none");
    let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
    assert_eq!(hs(&mut w, &mut c1s, C1, &mut sc1, SRV), ok3(SRV, C1));
    w.relay.tick(Instant::now() + Duration::from_secs(181));
    assert_eq!(w.relay.registry.addr(&w.srv.id(), Instant::now() + Duration::from_secs(181)), None);
    w.relay.tick(Instant::now() + Duration::from_secs(201));
    assert!(w.relay.sessions.is_empty());

    let mut w = world("none");
    let mut c1s = tunn(&w.c1, &w.srv);
    let init = initiation(&mut c1s);
    let ok = (0..100).filter(|_| w.fwd(C1, &init).is_some()).count();
    assert_eq!(ok, 20, "default 10/s => burst of 20");
    assert_eq!(w.n(Reason::RateLimited), 80);
}

#[test]
fn garbage_never_panics() {
    for gate in ["none", "response", "register"] {
        let mut w = world(gate);
        let srv = w.srv.clone();
        let mut sr = w.register(&srv, SRV);
        let (mut c1s, mut sc1) = (tunn(&w.c1, &w.srv), tunn(&w.srv, &w.c1));
        let init = initiation(&mut c1s);
        let resp = reply(&mut sc1, &init).unwrap();
        let seeds =
            [init, resp, encrypt(&mut sr, &ping([10, 99, 0, 1], [10, 99, 0, 254])), initiation(&mut sr)];
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
            let src = [SRV, C1, ST][(rnd() % 3) as usize];
            w.fwd(src, &p);
            w.relay.outbox.clear();
        }
        assert!(w.n(Reason::Malformed) > 500, "{}", w.relay.metrics);
    }
}
