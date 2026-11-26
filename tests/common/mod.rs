#![allow(dead_code, reason = "each test crate uses a different subset of these helpers")]
//! Shared test helpers: real WireGuard packets generated with boringtun.

use boringtun::noise::{Tunn, TunnResult};
use rand_core::OsRng;
use wg_relay::message::Mac1Key;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone)]
pub struct Key {
    pub sk: StaticSecret,
    pub pk: PublicKey,
}

impl Key {
    /// The public key as the relay identifies peers.
    pub fn id(&self) -> wg_relay::key::PublicKey {
        self.pk.into()
    }
}

pub fn key() -> Key {
    let sk = StaticSecret::random_from_rng(OsRng);
    let pk = PublicKey::from(&sk);
    Key { sk, pk }
}

pub fn tunn(me: &Key, peer: &Key) -> Tunn {
    Tunn::new(
        me.sk.clone(),
        peer.pk,
        None,
        None,
        rand_core::RngCore::next_u32(&mut OsRng) >> 8,
        None,
    )
}

/// Config text: the relay's private key `r`, then `extra`.
pub fn head(r: &Key, extra: &str) -> String {
    use base64::Engine;
    let sk = base64::engine::general_purpose::STANDARD.encode(r.sk.to_bytes());
    format!("private_key = \"{sk}\"\n{extra}")
}

/// Config text listing peer `name` with the public key of `k`.
pub fn peer(name: &str, k: &Key) -> String {
    format!("[[peer]]\nname = \"{name}\"\npubkey = \"{}\"\n", k.id())
}

pub fn initiation(t: &mut Tunn) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    match t.format_handshake_initiation(&mut buf, true) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("expected initiation, got {other:?}"),
    }
}

/// Feed `pkt` to `t` and return the datagram it wants to send back, if any.
pub fn reply(t: &mut Tunn, pkt: &[u8]) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 65536];
    match t.decapsulate(None, pkt, &mut buf) {
        TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
        _ => None,
    }
}

/// Run a full handshake between two tunnels; returns (init, response, keepalive).
pub fn handshake(a: &mut Tunn, b: &mut Tunn) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let init = initiation(a);
    let resp = reply(b, &init).expect("response");
    let ka = reply(a, &resp).expect("keepalive");
    (init, resp, ka)
}

pub fn encrypt(t: &mut Tunn, plain: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 65536];
    match t.encapsulate(plain, &mut buf) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("expected data, got {other:?}"),
    }
}

/// A minimal IPv4 ICMP echo request from `src` to `dst`.
pub fn ping(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 28, 0, 1, 0, 0, 64, 1, 0, 0];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(&[8, 0, 0xf7, 0xfe, 0, 1, 0, 0]);
    let sum: u32 = p[..20].chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], c[1]]))).sum();
    let c = !(((sum & 0xffff) + (sum >> 16)) as u16);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p
}

/// Overwrite an initiation's sender index and recompute mac1 for `recipient`.
pub fn with_sender(init: &[u8], sender_index: u32, recipient: &PublicKey) -> Vec<u8> {
    let mut p = init.to_vec();
    p[4..8].copy_from_slice(&sender_index.to_le_bytes());
    let mac = Mac1Key::new(recipient.as_bytes()).mac(&p[..116]);
    p[116..132].copy_from_slice(&mac);
    p
}

/// A response-shaped datagram with chosen indexes and a valid mac1 for `recipient`.
pub fn forged_response(sender_index: u32, receiver_index: u32, recipient: &PublicKey) -> Vec<u8> {
    let mut p = vec![0u8; 92];
    p[0] = 2;
    p[4..8].copy_from_slice(&sender_index.to_le_bytes());
    p[8..12].copy_from_slice(&receiver_index.to_le_bytes());
    let mac = Mac1Key::new(recipient.as_bytes()).mac(&p[..60]);
    p[60..76].copy_from_slice(&mac);
    p
}
