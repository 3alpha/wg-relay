//! Message parsing, size checks and mac1 matching on messages made by boringtun.
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test setup panics on failure")]

mod common;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Tunn, TunnResult};
use common::*;
use std::sync::Arc;
use wg_relay::message::{self, Mac1Key, Mac1Lookup, Message, ParseError, find_mac1};

#[test]
fn parses_real_handshake_and_data() {
    let (a, b) = (key(), key());
    let (mut ta, mut tb) = (tunn(&a, &b), tunn(&b, &a));
    let (init, resp, ka) = handshake(&mut ta, &mut tb);
    assert_eq!((init.len(), resp.len(), ka.len()), (148, 92, 32));

    let (init_message, resp_message) = (message::parse(&init), message::parse(&resp));
    let Ok(Message::HandshakeInitiation { sender_index: i_index }) = init_message else { panic!() };
    let Ok(Message::HandshakeResponse { sender_index: r_index, receiver_index }) = resp_message
    else {
        panic!()
    };
    assert_eq!(receiver_index, i_index);
    assert_eq!(message::parse(&ka).unwrap(), Message::TransportData { receiver_index: r_index });

    let data = encrypt(&mut ta, &ping([10, 0, 0, 1], [10, 0, 0, 2]));
    assert_eq!(message::parse(&data).unwrap(), Message::TransportData { receiver_index: r_index });
    assert_eq!(i_index, u32::from_le_bytes(init[4..8].try_into().unwrap()).into());
}

#[test]
fn parses_real_cookie_reply() {
    let (a, b) = (key(), key());
    let mut ta = tunn(&a, &b);
    // limit 0: b is permanently "under load" and answers with a cookie.
    let rl = Arc::new(RateLimiter::new(&b.pk, 0));
    let mut tb = Tunn::new(b.sk.clone(), a.pk, None, None, 7, Some(rl));
    let init = initiation(&mut ta);
    let parsed = message::parse(&init);
    let Ok(Message::HandshakeInitiation { sender_index: index }) = parsed else { panic!() };
    let mut buf = vec![0u8; 256];
    let TunnResult::WriteToNetwork(cookie) =
        tb.decapsulate(Some([1, 2, 3, 4].into()), &init, &mut buf)
    else {
        panic!("expected cookie reply")
    };
    assert_eq!(cookie.len(), 64);
    assert_eq!(message::parse(cookie).unwrap(), Message::CookieReply { receiver_index: index });
}

#[test]
fn size_and_header_checks() {
    use ParseError::*;
    let (a, b) = (key(), key());
    let (mut ta, mut tb) = (tunn(&a, &b), tunn(&b, &a));
    let (init, resp, ka) = handshake(&mut ta, &mut tb);

    for (pkt, kind, len) in [(&init, 1, 148), (&resp, 2, 92)] {
        assert_eq!(message::parse(&pkt[..len - 1]), Err(BadLength { kind, len: len - 1 }));
        let mut long = pkt.clone();
        long.push(0);
        assert_eq!(message::parse(&long), Err(BadLength { kind, len: len + 1 }));
    }
    let mut cookie = vec![3, 0, 0, 0];
    cookie.resize(64, 0);
    assert!(message::parse(&cookie).is_ok());
    assert_eq!(message::parse(&cookie[..63]), Err(BadLength { kind: 3, len: 63 }));
    assert_eq!(message::parse(&ka[..31]), Err(BadLength { kind: 4, len: 31 }));
    assert!(message::parse(&[ka.clone(), vec![0; 1000]].concat()).is_ok());

    let mut bad = init.clone();
    bad[2] = 1;
    assert_eq!(message::parse(&bad), Err(BadReserved));
    for t in [0u8, 5, 255] {
        let mut p = init.clone();
        p[0] = t;
        assert_eq!(message::parse(&p), Err(BadType(t)));
    }
    assert_eq!(message::parse(&[]), Err(TooShort));
    assert_eq!(message::parse(&[1, 0, 0]), Err(TooShort));
}

#[test]
fn mac1_matches_intended_recipient_only() {
    let (a, b, c) = (key(), key(), key());
    let (mut ta, mut tb) = (tunn(&a, &b), tunn(&b, &a));
    let (init, resp, ka) = handshake(&mut ta, &mut tb);
    let (ka_key, kb, kc) = (
        Mac1Key::new(a.pk.as_bytes()),
        Mac1Key::new(b.pk.as_bytes()),
        Mac1Key::new(c.pk.as_bytes()),
    );

    assert!(kb.matches(&init));
    assert!(!ka_key.matches(&init));
    assert!(!kc.matches(&init));
    assert!(ka_key.matches(&resp));
    assert!(!kb.matches(&resp));
    assert!(!kb.matches(&ka), "data packets have no mac1");
    assert_eq!(kb.mac(&init[..116]), init[116..132], "mac() computes the same mac1");

    for i in [0, 4, 50, 115, 116, 131] {
        let mut t = init.clone();
        t[i] ^= 1;
        assert!(!kb.matches(&t), "tamper at byte {i}");
    }
    // mac2 is outside the mac1 coverage.
    let mut t = init.clone();
    t[140] ^= 1;
    assert!(kb.matches(&t));
    assert!(!kb.matches(&init[..147]));
}

#[test]
fn find_mac1_searches_in_batches_and_counts_work() {
    let target = key();
    let mut t = tunn(&key(), &target);
    let init = initiation(&mut t);
    let mut keys: Vec<Mac1Key> = (0..20).map(|_| Mac1Key::new(key().pk.as_bytes())).collect();
    assert_eq!(find_mac1(&keys, &init), Mac1Lookup { found: None, tried: 20 });
    // Second batch of 8: the whole batch is hashed.
    keys[13] = Mac1Key::new(target.pk.as_bytes());
    assert_eq!(find_mac1(&keys, &init), Mac1Lookup { found: Some(13), tried: 16 });
    keys.swap(13, 2);
    assert_eq!(find_mac1(&keys, &init), Mac1Lookup { found: Some(2), tried: 8 });
    assert_eq!(find_mac1(&keys[..3], &init), Mac1Lookup { found: Some(2), tried: 3 });
    assert_eq!(find_mac1(&keys, &init[..100]), Mac1Lookup { found: None, tried: 0 });
    assert_eq!(find_mac1(&[], &init), Mac1Lookup { found: None, tried: 0 });
}
