use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::config::ConfigError;

/// Why the relay could not start or stopped, in the order things happen.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("invalid config {path}")]
    Config {
        path: PathBuf,
        #[source]
        source: ConfigError,
    },
    #[error("failed to bind {addr}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to set up batched I/O on {addr}")]
    Offload {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to start the async runtime")]
    Runtime {
        #[source]
        source: std::io::Error,
    },
    #[error("failed to start forwarding thread {index}")]
    WorkerSpawn {
        index: usize,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to install the {signal} handler")]
    Signal {
        signal: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("forwarding thread {index} failed")]
    WorkerFailed {
        index: usize,
        #[source]
        source: std::io::Error,
    },
    #[error("forwarding thread {index} panicked")]
    WorkerPanicked { index: usize },
    #[error("forwarding thread {index} exited unexpectedly")]
    WorkerExited { index: usize },
}

/// Display an error followed by its `source()` chain, joined with ": ".
pub struct Report<'a>(pub &'a dyn Error);

impl fmt::Display for Report<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let mut source = self.0.source();
        while let Some(e) = source {
            write!(f, ": {e}")?;
            source = e.source();
        }
        Ok(())
    }
}
