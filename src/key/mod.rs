//! Base64 WireGuard keys as they appear in configs and logs.

use std::fmt;
use std::str::FromStr;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use x25519_dalek::{PublicKey, StaticSecret};

pub mod error;
pub use error::KeyError;

fn decode(s: &str) -> Result<[u8; 32], KeyError> {
    let bytes = STANDARD.decode(s.trim())?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| KeyError::Length(bytes.len()))
}

/// A peer's X25519 public key; displays as base64.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct PeerKey([u8; 32]);

impl PeerKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for PeerKey {
    fn from(bytes: [u8; 32]) -> Self {
        PeerKey(bytes)
    }
}

impl From<PublicKey> for PeerKey {
    fn from(pk: PublicKey) -> Self {
        PeerKey(pk.to_bytes())
    }
}

impl From<PeerKey> for PublicKey {
    fn from(k: PeerKey) -> Self {
        PublicKey::from(k.0)
    }
}

impl FromStr for PeerKey {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        decode(s).map(PeerKey)
    }
}

impl TryFrom<String> for PeerKey {
    type Error = KeyError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl fmt::Display for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&STANDARD.encode(self.0))
    }
}

impl fmt::Debug for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerKey({self})")
    }
}

/// The relay's own X25519 private key; never printed.
#[derive(Clone, Deserialize)]
#[serde(try_from = "String")]
pub struct PrivateKey(StaticSecret);

impl PrivateKey {
    pub fn secret(&self) -> &StaticSecret {
        &self.0
    }

    pub fn public_key(&self) -> PeerKey {
        PublicKey::from(&self.0).into()
    }
}

impl FromStr for PrivateKey {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        decode(s).map(|b| PrivateKey(StaticSecret::from(b)))
    }
}

impl TryFrom<String> for PrivateKey {
    type Error = KeyError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey([REDACTED])")
    }
}
