#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RateError {
    #[error("missing unit, expected \"<n>/s\" or \"<n>/m\"")]
    MissingUnit,
    #[error("invalid number {0:?}")]
    Number(String),
    #[error("unknown unit {0:?}")]
    Unit(String),
    #[error("rate must be positive")]
    NotPositive,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read file")]
    Read(#[from] std::io::Error),
    #[error("invalid toml")]
    Parse(#[from] toml::de::Error),
    #[error("at least one [[peer]] is required")]
    NoPeer,
    #[error("{name} uses the relay's own key")]
    RelayKeyReused { name: String },
    #[error("{name} has the same pubkey as another peer")]
    DuplicatePubkey { name: String },
    #[error("duplicate name {name}")]
    DuplicateName { name: String },
    #[error("workers must be between 1 and {max}, got {got}")]
    Workers { got: usize, max: usize },
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    #[error("missing port, expected \"<host>:<port>\"")]
    MissingPort,
    #[error("invalid port {0:?}")]
    Port(String),
    #[error("invalid host {0:?}, expected a hostname, an IPv4 address or [IPv6]")]
    Host(String),
}
