//! Packet parsing, size checks, mac1 matching and soft-state tables.
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test setup panics on failure")]

mod common;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Tunn, TunnResult};
use common::*;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use wg_relay::packet::{self, Packet, ParseError};
use wg_relay::tables::{RateLimiter as InitLimiter, Registry, Session, SessionTable};

#[test]
fn parses_real_handshake_and_data() {
    let (a, b) = (key(), key());
    let (mut ta, mut tb) = (tunn(&a, &b), tunn(&b, &a));
    let (init, resp, ka) = handshake(&mut ta, &mut tb);
    assert_eq!((init.len(), resp.len(), ka.len()), (148, 92, 32));

    let Packet::Init { sender: i_idx } = packet::parse(&init).unwrap() else { panic!() };
    let Packet::Response { sender: r_idx, receiver } = packet::parse(&resp).unwrap() else { panic!() };
    assert_eq!(receiver, i_idx);
    assert_eq!(packet::parse(&ka).unwrap(), Packet::Data { receiver: r_idx });

    let data = encrypt(&mut ta, &ping([10, 0, 0, 1], [10, 0, 0, 2]));
    assert_eq!(packet::parse(&data).unwrap(), Packet::Data { receiver: r_idx });
    assert_eq!(&init[4..8], &i_idx.to_le_bytes());
}

#[test]
fn parses_real_cookie_reply() {
    let (a, b) = (key(), key());
    let mut ta = tunn(&a, &b);
    // limit 0: b is permanently "under load" and answers with a cookie.
    let rl = Arc::new(RateLimiter::new(&b.pk, 0));
    let mut tb = Tunn::new(b.sk.clone(), a.pk, None, None, 7, Some(rl));
    let init = initiation(&mut ta);
    let Packet::Init { sender } = packet::parse(&init).unwrap() else { panic!() };
    let mut buf = vec![0u8; 256];
    let TunnResult::WriteToNetwork(cookie) = tb.decapsulate(Some([1, 2, 3, 4].into()), &init, &mut buf)
    else {
        panic!("expected cookie reply")
    };
    assert_eq!(cookie.len(), 64);
    assert_eq!(packet::parse(cookie).unwrap(), Packet::Cookie { receiver: sender });
}

#[test]
fn size_and_header_checks() {
    use ParseError::*;
    let (a, b) = (key(), key());
    let (mut ta, mut tb) = (tunn(&a, &b), tunn(&b, &a));
    let (init, resp, ka) = handshake(&mut ta, &mut tb);

    for (pkt, kind, len) in [(&init, 1, 148), (&resp, 2, 92)] {
        assert_eq!(packet::parse(&pkt[..len - 1]), Err(BadLength { kind, len: len - 1 }));
        let mut long = pkt.clone();
        long.push(0);
        assert_eq!(packet::parse(&long), Err(BadLength { kind, len: len + 1 }));
    }
    let mut cookie = vec![3, 0, 0, 0];
    cookie.resize(64, 0);
    assert!(packet::parse(&cookie).is_ok());
    assert_eq!(packet::parse(&cookie[..63]), Err(BadLength { kind: 3, len: 63 }));
    assert_eq!(packet::parse(&ka[..31]), Err(BadLength { kind: 4, len: 31 }));
    assert!(packet::parse(&[ka.clone(), vec![0; 1000]].concat()).is_ok());

    let mut bad = init.clone();
    bad[2] = 1;
    assert_eq!(packet::parse(&bad), Err(BadReserved));
    for t in [0u8, 5, 255] {
        let mut p = init.clone();
        p[0] = t;
        assert_eq!(packet::parse(&p), Err(BadType(t)));
    }
    assert_eq!(packet::parse(&[]), Err(TooShort));
    assert_eq!(packet::parse(&[1, 0, 0]), Err(TooShort));
}

#[test]
fn mac1_matches_intended_recipient_only() {
    let (a, b, c) = (key(), key(), key());
    let (mut ta, mut tb) = (tunn(&a, &b), tunn(&b, &a));
    let (init, resp, ka) = handshake(&mut ta, &mut tb);
    let (ka_key, kb, kc) = (
        packet::mac1_key(a.pk.as_bytes()),
        packet::mac1_key(b.pk.as_bytes()),
        packet::mac1_key(c.pk.as_bytes()),
    );

    assert!(packet::mac1_matches(&kb, &init));
    assert!(!packet::mac1_matches(&ka_key, &init));
    assert!(!packet::mac1_matches(&kc, &init));
    assert!(packet::mac1_matches(&ka_key, &resp));
    assert!(!packet::mac1_matches(&kb, &resp));
    assert!(!packet::mac1_matches(&kb, &ka), "data packets have no mac1");

    for i in [0, 4, 50, 115, 116, 131] {
        let mut t = init.clone();
        t[i] ^= 1;
        assert!(!packet::mac1_matches(&kb, &t), "tamper at byte {i}");
    }
    // mac2 is outside the mac1 coverage.
    let mut t = init.clone();
    t[140] ^= 1;
    assert!(packet::mac1_matches(&kb, &t));
    assert!(!packet::mac1_matches(&kb, &init[..147]));
}

fn sess(dest: &str, src: &str, t: Instant) -> Session {
    Session {
        dest: dest.parse().unwrap(),
        expected_src: src.parse().unwrap(),
        open: false,
        last: t,
        server: [1; 32],
        client: None,
    }
}

#[test]
fn session_table_expiry_and_touch() {
    let t0 = Instant::now();
    let mut t = SessionTable::new(Duration::from_secs(200));
    t.insert(42, sess("192.0.2.1:1", "192.0.2.2:2", t0));
    assert!(t.get(42, t0 + Duration::from_secs(199)).is_some());
    assert!(t.get(42, t0 + Duration::from_secs(200)).is_none());
    t.touch(42, t0 + Duration::from_secs(150), true, Some([7; 32]));
    let s = t.get(42, t0 + Duration::from_secs(300)).unwrap();
    assert!(s.open);
    assert_eq!(s.client, Some([7; 32]));
    assert_eq!(t.expire(t0 + Duration::from_secs(349)), 0);
    assert_eq!(t.expire(t0 + Duration::from_secs(351)), 1);
    assert!(t.is_empty());
}

#[test]
fn session_table_collisions_keep_newest() {
    let t0 = Instant::now();
    let mut t = SessionTable::new(Duration::from_secs(200));
    assert!(!t.insert(7, sess("192.0.2.1:1", "192.0.2.2:2", t0)));
    assert!(!t.insert(7, sess("192.0.2.1:1", "192.0.2.2:2", t0 + Duration::from_secs(1))), "same pair");
    assert!(t.insert(7, sess("192.0.2.3:3", "192.0.2.4:4", t0 + Duration::from_secs(2))));
    assert_eq!(t.get(7, t0 + Duration::from_secs(2)).unwrap().dest, "192.0.2.3:3".parse().unwrap());
    assert!(!t.insert(7, sess("192.0.2.5:5", "192.0.2.6:6", t0 + Duration::from_secs(500))), "stale entry");
    assert_eq!(t.len(), 1);
}

#[test]
fn session_table_migrate_retain_prefix() {
    let t0 = Instant::now();
    let mut t = SessionTable::new(Duration::from_secs(200));
    t.insert(0x00ab_cd01, sess("192.0.2.1:1", "192.0.2.2:2", t0));
    t.insert(0x0011_2201, sess("192.0.2.2:2", "192.0.2.1:1", t0));
    assert!(t.has_prefix(0xabcd) && !t.has_prefix(0xabce));
    t.migrate("192.0.2.1:1".parse().unwrap(), "192.0.2.9:9".parse().unwrap());
    assert_eq!(t.get(0x00ab_cd01, t0).unwrap().dest, "192.0.2.9:9".parse().unwrap());
    assert_eq!(t.get(0x0011_2201, t0).unwrap().expected_src, "192.0.2.9:9".parse().unwrap());
    assert_eq!(t.retain(|s| s.dest.port() == 9), 1);
}

#[test]
fn registry_roaming_conflicts_and_expiry() {
    let t0 = Instant::now();
    let a1: SocketAddr = "192.0.2.10:1000".parse().unwrap();
    let a2: SocketAddr = "192.0.2.10:1001".parse().unwrap();
    let mut r = Registry::new(Duration::from_secs(180));
    assert_eq!(r.update(0, a1, t0), Some(None));
    assert_eq!(r.update(0, a1, t0), None);
    assert_eq!(r.key_at(a1, t0), Some(0));
    assert_eq!(r.update(0, a2, t0), Some(Some(a1)), "roamed");
    assert_eq!(r.key_at(a1, t0), None);
    assert_eq!(r.update(1, a2, t0), Some(None));
    assert_eq!((r.addr(&0, t0), r.key_at(a2, t0)), (None, Some(1)), "newest claimant owns address");
    assert_eq!(r.addr(&1, t0 + Duration::from_secs(179)), Some(a2));
    assert_eq!(r.key_at(a2, t0 + Duration::from_secs(180)), None);
    assert_eq!(r.expire(t0 + Duration::from_secs(181)), vec![1]);
    r.update(3, a1, t0);
    assert!(r.remove(&3) && !r.remove(&3));
    assert_eq!(r.key_at(a1, t0), None);
}

#[test]
fn init_rate_limiter() {
    let t0 = Instant::now();
    let ip = "192.0.2.1".parse().unwrap();
    let mut l = InitLimiter::new(1.5); // burst 3
    assert!((0..3).all(|_| l.allow(ip, t0)));
    assert!(!l.allow(ip, t0));
    assert!(l.allow("192.0.2.2".parse().unwrap(), t0), "per-source buckets");
    assert!(l.allow(ip, t0 + Duration::from_secs(1)));
    assert!(!l.allow(ip, t0 + Duration::from_secs(1)));
}

#[test]
fn rate_strings() {
    use wg_relay::config::parse_rate;
    assert_eq!(parse_rate("10/s").ok(), Some(10.0));
    assert_eq!(parse_rate("120/m").ok(), Some(2.0));
    assert_eq!(parse_rate(" 5 ").ok(), Some(5.0));
    for bad in ["0/s", "-1/s", "x/s", "10/h", ""] {
        assert!(parse_rate(bad).is_err(), "{bad}");
    }
}
