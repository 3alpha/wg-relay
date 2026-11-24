//! WireGuard wire format: header parsing and mac1 checks. Payloads stay opaque.

use std::fmt;

use blake2::digest::{KeyInit, Mac, consts::U16};
use blake2::{Blake2s256, Blake2sMac, Digest};

pub mod error;
pub use error::ParseError;

pub const INIT_LEN: usize = 148;
pub const RESP_LEN: usize = 92;
pub const COOKIE_LEN: usize = 64;
pub const DATA_MIN_LEN: usize = 32;
/// Offset of mac1 = number of bytes the MAC covers.
const INIT_MAC1_OFF: usize = 116;
const RESP_MAC1_OFF: usize = 60;

/// A WireGuard session index (`sender_idx` / `receiver_idx`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionIdx(u32);

impl SessionIdx {
    /// The upper 24 bits, which identify the relay tunnel that owns an index.
    pub fn prefix(self) -> IdxPrefix {
        IdxPrefix(self.0 >> 8)
    }
}

impl fmt::Display for SessionIdx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}

impl From<u32> for SessionIdx {
    fn from(idx: u32) -> Self {
        SessionIdx(idx)
    }
}

/// The upper 24 bits of a session index. boringtun numbers a tunnel's
/// sessions `prefix << 8 | counter`, so each prefix covers 256 indexes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdxPrefix(u32);

impl IdxPrefix {
    /// Build a prefix from any 32-bit value, keeping its low 24 bits.
    pub fn from_bits(bits: u32) -> Self {
        IdxPrefix(bits & 0x00ff_ffff)
    }

    /// The value boringtun's `Tunn::new` takes as its index.
    pub fn get(self) -> u32 {
        self.0
    }
}

/// The routing-relevant header fields of a WireGuard message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packet {
    Init { sender: SessionIdx },
    Response { sender: SessionIdx, receiver: SessionIdx },
    Cookie { receiver: SessionIdx },
    Data { receiver: SessionIdx },
}

fn idx(b: &[u8], off: usize) -> Result<SessionIdx, ParseError> {
    b.get(off..off + 4)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map(|b| SessionIdx(u32::from_le_bytes(b)))
        .ok_or(ParseError::TooShort)
}

/// Parse and size-check a datagram. Never panics.
pub fn parse(b: &[u8]) -> Result<Packet, ParseError> {
    if b.len() < 4 {
        return Err(ParseError::TooShort);
    }
    if b[1..4] != [0, 0, 0] {
        return Err(ParseError::BadReserved);
    }
    let bad_length = ParseError::BadLength { kind: b[0], len: b.len() };
    let exact = |n: usize| if b.len() == n { Ok(()) } else { Err(bad_length) };
    match b[0] {
        1 => {
            exact(INIT_LEN)?;
            Ok(Packet::Init { sender: idx(b, 4)? })
        }
        2 => {
            exact(RESP_LEN)?;
            Ok(Packet::Response { sender: idx(b, 4)?, receiver: idx(b, 8)? })
        }
        3 => {
            exact(COOKIE_LEN)?;
            Ok(Packet::Cookie { receiver: idx(b, 4)? })
        }
        4 if b.len() < DATA_MIN_LEN => Err(bad_length),
        4 => Ok(Packet::Data { receiver: idx(b, 4)? }),
        t => Err(ParseError::BadType(t)),
    }
}

pub type Mac1Key = [u8; 32];

/// mac1 key = BLAKE2s-256("mac1----" || recipient_pubkey).
pub fn mac1_key(pubkey: &[u8; 32]) -> Mac1Key {
    let mut h = Blake2s256::new();
    h.update(b"mac1----");
    h.update(pubkey);
    h.finalize().into()
}

/// True if `pkt` is an initiation or response whose mac1 was made for the
/// holder of the pubkey behind `key`. Constant-time comparison.
pub fn mac1_matches(key: &Mac1Key, pkt: &[u8]) -> bool {
    let off = match (pkt.first(), pkt.len()) {
        (Some(1), INIT_LEN) => INIT_MAC1_OFF,
        (Some(2), RESP_LEN) => RESP_MAC1_OFF,
        _ => return false,
    };
    let Ok(mut mac) = <Blake2sMac<U16> as KeyInit>::new_from_slice(key) else {
        return false;
    };
    mac.update(&pkt[..off]);
    mac.verify_slice(&pkt[off..off + 16]).is_ok()
}
