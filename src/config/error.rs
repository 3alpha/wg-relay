use std::fmt;

use super::Gate;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("invalid base64")]
    Base64(#[from] base64::DecodeError),
    #[error("key must be 32 bytes, got {0}")]
    Length(usize),
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read file")]
    Read(#[from] std::io::Error),
    #[error("invalid toml")]
    Parse(#[from] toml::de::Error),
    #[error("invalid private_key")]
    PrivateKey(#[source] KeyError),
    #[error("invalid pubkey for {name}")]
    Pubkey {
        name: String,
        #[source]
        source: KeyError,
    },
    #[error("invalid handshake_rate_per_ip {value:?}")]
    Rate { value: String },
    #[error("at least one [[server]] is required")]
    NoServer,
    #[error("{name} uses the relay's own key")]
    RelayKeyReused { name: String },
    #[error("{name} has the same pubkey as another peer")]
    DuplicatePubkey { name: String },
    #[error("duplicate name {name}")]
    DuplicateName { name: String },
    #[error("client {client} lists unknown server {server:?}")]
    UnknownServer { client: String, server: String },
}

/// A valid but probably unintended setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigWarning {
    NoClients { gate: Gate },
    ClientWithoutServers { name: String },
}

impl fmt::Display for ConfigWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigWarning::NoClients { gate } => {
                write!(f, "client_gate = {gate:?} but no [[client]] entries, so no client can connect")
            }
            ConfigWarning::ClientWithoutServers { name } => {
                write!(f, "client {name} may not reach any server")
            }
        }
    }
}
