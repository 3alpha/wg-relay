#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("datagram shorter than a message header")]
    TooShort,
    #[error("unknown message type {0}")]
    BadType(u8),
    #[error("non-zero reserved bytes")]
    BadReserved,
    #[error("message type {kind} cannot be {len} bytes long")]
    BadLength { kind: u8, len: usize },
}
