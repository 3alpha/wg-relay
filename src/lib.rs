//! wg-relay: a pubkey-routed relay for unmodified WireGuard peers behind NAT.
#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod key;
pub mod packet;
pub mod relay;
pub mod tables;
