#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("invalid base64")]
    Base64(#[from] base64::DecodeError),
    #[error("key must be 32 bytes, got {0}")]
    Length(usize),
}
