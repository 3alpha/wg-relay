//! WireGuard wire format: header parsing and mac1 checks. Payloads stay opaque.

use blake2::digest::{KeyInit, Mac, consts::U16};
use blake2::{Blake2s256, Blake2sMac, Digest};

pub const INIT_LEN: usize = 148;
pub const RESP_LEN: usize = 92;
pub const COOKIE_LEN: usize = 64;
pub const DATA_MIN_LEN: usize = 32;
/// Offset of mac1 = number of bytes the MAC covers.
const INIT_MAC1_OFF: usize = 116;
const RESP_MAC1_OFF: usize = 60;

/// The routing-relevant header fields of a WireGuard message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packet {
    Init { sender: u32 },
    Response { sender: u32, receiver: u32 },
    Cookie { receiver: u32 },
    Data { receiver: u32 },
}

impl Packet {
    /// The index chosen by the *recipient* of this message, if any.
    pub fn receiver(&self) -> Option<u32> {
        match *self {
            Packet::Init { .. } => None,
            Packet::Response { receiver, .. } | Packet::Cookie { receiver } | Packet::Data { receiver } => {
                Some(receiver)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    BadType,
    BadReserved,
    BadLength,
}

fn le32(b: &[u8], off: usize) -> Result<u32, ParseError> {
    b.get(off..off + 4)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map(u32::from_le_bytes)
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
    let exact = |n: usize| {
        if b.len() == n { Ok(()) } else { Err(ParseError::BadLength) }
    };
    match b[0] {
        1 => {
            exact(INIT_LEN)?;
            Ok(Packet::Init { sender: le32(b, 4)? })
        }
        2 => {
            exact(RESP_LEN)?;
            Ok(Packet::Response { sender: le32(b, 4)?, receiver: le32(b, 8)? })
        }
        3 => {
            exact(COOKIE_LEN)?;
            Ok(Packet::Cookie { receiver: le32(b, 4)? })
        }
        4 if b.len() < DATA_MIN_LEN => Err(ParseError::BadLength),
        4 => Ok(Packet::Data { receiver: le32(b, 4)? }),
        _ => Err(ParseError::BadType),
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
