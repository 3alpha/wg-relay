//! Datagrams for the relay's unit tests: the right type, size and indexes, zeros elsewhere.

use crate::packet;

/// A handshake initiation announcing `sender`, with no valid mac1.
pub(super) fn initiation(sender: u32) -> Vec<u8> {
    message(1, packet::INIT_LEN, sender)
}

/// A handshake response from `sender` to `receiver`, with no valid mac1.
pub(super) fn response(sender: u32, receiver: u32) -> Vec<u8> {
    let mut p = message(2, packet::RESP_LEN, sender);
    p[8..12].copy_from_slice(&receiver.to_le_bytes());
    p
}

/// A cookie reply for `receiver`.
pub(super) fn cookie(receiver: u32) -> Vec<u8> {
    message(3, packet::COOKIE_LEN, receiver)
}

/// Transport data for `receiver`.
pub(super) fn data(receiver: u32) -> Vec<u8> {
    message(4, 48, receiver)
}

/// A message of type `kind` and length `len` carrying `idx` as its first index.
fn message(kind: u8, len: usize, idx: u32) -> Vec<u8> {
    let mut p = vec![0u8; len];
    p[0] = kind;
    p[4..8].copy_from_slice(&idx.to_le_bytes());
    p
}
