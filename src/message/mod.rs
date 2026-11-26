//! WireGuard wire format: header parsing and mac1 checks. Payloads stay opaque.

use std::fmt;

use blake2s_simd::Params;
use blake2s_simd::many::{HashManyJob, hash_many};

pub mod error;
pub use error::ParseError;

pub const HANDSHAKE_INITIATION_LEN: usize = 148;
pub const HANDSHAKE_RESPONSE_LEN: usize = 92;
pub const COOKIE_REPLY_LEN: usize = 64;
pub const TRANSPORT_DATA_MIN_LEN: usize = 32;
/// Offset of mac1 = number of bytes the MAC covers.
const HANDSHAKE_INITIATION_MAC1_OFFSET: usize = 116;
const HANDSHAKE_RESPONSE_MAC1_OFFSET: usize = 60;
const MAC1_LEN: usize = 16;
/// Keys tried per SIMD batch: the widest lane count blake2s_simd uses (AVX2).
const MAC1_BATCH: usize = 8;

/// A WireGuard index, as carried in `sender_index` and `receiver_index`. Each
/// side picks one per handshake; later messages to it carry it as `receiver_index`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionIndex(u32);

impl SessionIndex {
    /// The upper 24 bits, which tell whether a registration tunnel owns the index.
    pub fn prefix(self) -> IndexPrefix {
        IndexPrefix(self.0 >> 8)
    }
}

impl fmt::Display for SessionIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}

impl From<u32> for SessionIndex {
    fn from(index: u32) -> Self {
        SessionIndex(index)
    }
}

/// The upper 24 bits of a session index. boringtun numbers a tunnel's
/// sessions `prefix << 8 | counter`, so each prefix covers 256 indexes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IndexPrefix(u32);

impl IndexPrefix {
    /// Build a prefix from any 32-bit value, keeping its low 24 bits.
    pub fn from_bits(bits: u32) -> Self {
        IndexPrefix(bits & 0x00ff_ffff)
    }

    /// The value boringtun's `Tunn::new` takes as its index.
    pub fn get(self) -> u32 {
        self.0
    }
}

/// A WireGuard message's type and the indexes the relay routes by, named as in
/// the WireGuard spec. Types 1 and 2 are handshake messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message {
    HandshakeInitiation { sender_index: SessionIndex },
    HandshakeResponse { sender_index: SessionIndex, receiver_index: SessionIndex },
    CookieReply { receiver_index: SessionIndex },
    TransportData { receiver_index: SessionIndex },
}

impl Message {
    /// The index this message is addressed to; a handshake initiation has none yet.
    pub fn receiver_index(self) -> Option<SessionIndex> {
        match self {
            Message::HandshakeInitiation { .. } => None,
            Message::HandshakeResponse { receiver_index, .. }
            | Message::CookieReply { receiver_index }
            | Message::TransportData { receiver_index } => Some(receiver_index),
        }
    }
}

/// Read the little-endian index at `off`.
fn index(b: &[u8], off: usize) -> Result<SessionIndex, ParseError> {
    b.get(off..off + 4)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map(|b| SessionIndex(u32::from_le_bytes(b)))
        .ok_or(ParseError::TooShort)
}

/// Parse and size-check a datagram as a WireGuard message. Never panics.
pub fn parse(b: &[u8]) -> Result<Message, ParseError> {
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
            exact(HANDSHAKE_INITIATION_LEN)?;
            Ok(Message::HandshakeInitiation { sender_index: index(b, 4)? })
        }
        2 => {
            exact(HANDSHAKE_RESPONSE_LEN)?;
            Ok(Message::HandshakeResponse {
                sender_index: index(b, 4)?,
                receiver_index: index(b, 8)?,
            })
        }
        3 => {
            exact(COOKIE_REPLY_LEN)?;
            Ok(Message::CookieReply { receiver_index: index(b, 4)? })
        }
        4 if b.len() < TRANSPORT_DATA_MIN_LEN => Err(bad_length),
        4 => Ok(Message::TransportData { receiver_index: index(b, 4)? }),
        t => Err(ParseError::BadType(t)),
    }
}

/// The mac1 key of one public key, BLAKE2s-256("mac1----" || pubkey), ready
/// for keyed hashing.
#[derive(Clone)]
pub struct Mac1Key(Params);

impl Mac1Key {
    pub fn new(pubkey: &[u8; 32]) -> Self {
        let key = Params::new().to_state().update(b"mac1----").update(pubkey).finalize();
        Mac1Key(Params::new().hash_length(MAC1_LEN).key(key.as_bytes()).clone())
    }

    /// The mac1 of a message whose first `covered` bytes the MAC protects.
    pub fn mac(&self, covered: &[u8]) -> [u8; MAC1_LEN] {
        let mut out = [0; MAC1_LEN];
        out.copy_from_slice(self.0.hash(covered).as_bytes());
        out
    }

    /// Is `datagram` a handshake message whose mac1 was made for the holder of
    /// this key? Constant-time comparison.
    pub fn matches(&self, datagram: &[u8]) -> bool {
        mac1_parts(datagram).is_some_and(|(covered, tag)| self.0.hash(covered) == *tag)
    }
}

/// Split a handshake message into the bytes mac1 covers and mac1 itself.
fn mac1_parts(datagram: &[u8]) -> Option<(&[u8], &[u8])> {
    let off = match (datagram.first(), datagram.len()) {
        (Some(1), HANDSHAKE_INITIATION_LEN) => HANDSHAKE_INITIATION_MAC1_OFFSET,
        (Some(2), HANDSHAKE_RESPONSE_LEN) => HANDSHAKE_RESPONSE_MAC1_OFFSET,
        _ => return None,
    };
    Some((&datagram[..off], &datagram[off..off + MAC1_LEN]))
}

/// The outcome of looking up the key a handshake message's mac1 was made for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mac1Lookup {
    /// Index of the matching key.
    pub found: Option<usize>,
    /// How many keys were hashed, the cost of the lookup.
    pub tried: usize,
}

/// Find the key `datagram`'s mac1 was made for, hashing several keys at once with SIMD.
pub fn find_mac1(keys: &[Mac1Key], datagram: &[u8]) -> Mac1Lookup {
    let mut lookup = Mac1Lookup { found: None, tried: 0 };
    let Some((covered, tag)) = mac1_parts(datagram) else { return lookup };
    for (n, batch) in keys.chunks(MAC1_BATCH).enumerate() {
        let mut jobs: [Option<HashManyJob<'_>>; MAC1_BATCH] =
            std::array::from_fn(|i| batch.get(i).map(|k| HashManyJob::new(&k.0, covered)));
        hash_many(jobs.iter_mut().flatten());
        lookup.tried += batch.len();
        if let Some(i) = jobs.iter().flatten().position(|j| j.to_hash() == *tag) {
            lookup.found = Some(n * MAC1_BATCH + i);
            break;
        }
    }
    lookup
}
