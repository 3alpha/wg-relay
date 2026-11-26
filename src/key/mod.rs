//! Base64 WireGuard keys as they appear in configs and logs.

use std::fmt;
use std::str::FromStr;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use x25519_dalek::StaticSecret;

pub mod error;
pub use error::KeyError;

fn decode(s: &str) -> Result<[u8; 32], KeyError> {
    let bytes = STANDARD.decode(s.trim())?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| KeyError::Length(bytes.len()))
}

/// A peer's X25519 public key; displays as base64.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        PublicKey(bytes)
    }
}

impl From<x25519_dalek::PublicKey> for PublicKey {
    fn from(pk: x25519_dalek::PublicKey) -> Self {
        PublicKey(pk.to_bytes())
    }
}

impl From<PublicKey> for x25519_dalek::PublicKey {
    fn from(k: PublicKey) -> Self {
        x25519_dalek::PublicKey::from(k.0)
    }
}

impl FromStr for PublicKey {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        decode(s).map(PublicKey)
    }
}

impl TryFrom<String> for PublicKey {
    type Error = KeyError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&STANDARD.encode(self.0))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
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

    pub fn public_key(&self) -> PublicKey {
        x25519_dalek::PublicKey::from(&self.0).into()
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
