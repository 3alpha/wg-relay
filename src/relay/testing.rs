//! Datagrams for the relay's unit tests: the right type, size and indexes, zeros elsewhere.

use crate::message;

/// A handshake initiation announcing `sender_index`, with no valid mac1.
pub(super) fn initiation(sender_index: u32) -> Vec<u8> {
    datagram(1, message::HANDSHAKE_INITIATION_LEN, sender_index)
}

/// A handshake response from `sender_index` to `receiver_index`, with no valid mac1.
pub(super) fn response(sender_index: u32, receiver_index: u32) -> Vec<u8> {
    let mut p = datagram(2, message::HANDSHAKE_RESPONSE_LEN, sender_index);
    p[8..12].copy_from_slice(&receiver_index.to_le_bytes());
    p
}

/// A cookie reply for `receiver_index`.
pub(super) fn cookie(receiver_index: u32) -> Vec<u8> {
    datagram(3, message::COOKIE_REPLY_LEN, receiver_index)
}

/// Transport data for `receiver_index`.
pub(super) fn data(receiver_index: u32) -> Vec<u8> {
    datagram(4, 48, receiver_index)
}

/// A message of type `kind` and length `len` carrying `index` as its first index.
fn datagram(kind: u8, len: usize, index: u32) -> Vec<u8> {
    let mut p = vec![0u8; len];
    p[0] = kind;
    p[4..8].copy_from_slice(&index.to_le_bytes());
    p
}
