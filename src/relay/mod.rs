//! The relay state machine: registration tunnels plus opaque forwarding.
//!
//! `Relay::handle` does no I/O: it returns a `Verdict` for the datagram and
//! queues the registration tunnels' output for `drain_tx_queue`. Inside, the
//! data plane decides what it can from established sessions alone and hands
//! the rest to the control plane, which owns everything that changes.
//! Several threads can run the relay at once, each with its own `Relay` from
//! `Relay::share`: the data plane is read without a lock, the control plane
//! is locked for each datagram it decides.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use tracing::debug;

use crate::config::Config;
use crate::key::PublicKey;

mod control_plane;
mod data_plane;
mod metrics;
mod snapshot;
#[cfg(test)]
mod testing;
mod verdict;

use control_plane::ControlPlane;
pub use control_plane::{LIMITS, TICK_INTERVAL};
use data_plane::{DataPlane, Triage};
pub use metrics::{ControlMetrics, Metrics, TunnelError};
pub use snapshot::{ControlSnapshot, Limits, PeerSnapshot};
use verdict::Accepted;
pub use verdict::{DropReason, Verdict};

/// One thread's handle on the relay.
pub struct Relay {
    data_plane: Arc<DataPlane>,
    control_plane: Arc<Mutex<ControlPlane>>,
    /// What the data plane decided on this thread, and its socket errors.
    local_metrics: Metrics,
}

impl Relay {
    /// Build the relay for `config`, with nothing registered yet.
    pub fn new(config: &Config) -> Self {
        let control_plane = ControlPlane::new(config);
        Relay {
            data_plane: control_plane.data_plane(),
            control_plane: Arc::new(Mutex::new(control_plane)),
            local_metrics: Metrics::default(),
        }
    }

    /// Another handle on the same relay, with counters of its own, for another thread.
    pub fn share(&self) -> Self {
        Relay {
            data_plane: Arc::clone(&self.data_plane),
            control_plane: Arc::clone(&self.control_plane),
            local_metrics: Metrics::default(),
        }
    }

    /// Lock the control plane. A thread that panicked holding it ends the
    /// process anyway, so its state is used as it is.
    fn control_plane(&self) -> MutexGuard<'_, ControlPlane> {
        self.control_plane.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The relay's own public key.
    pub fn public_key(&self) -> PublicKey {
        self.control_plane().public_key()
    }

    /// How many configured peers the config has.
    pub fn peer_count(&self) -> usize {
        self.control_plane().peer_count()
    }

    /// How many sessions, pending or established, the relay holds.
    pub fn session_count(&self) -> usize {
        self.control_plane().session_count()
    }

    /// This handle's counters and the control plane's, merged.
    pub fn metrics(&self) -> Metrics {
        let mut all = self.local_metrics.clone();
        all += self.control_plane().metrics();
        all
    }

    /// The control plane's counters, session counts and configured peers,
    /// copied out in one hold of its lock; this handle's own counters are not included.
    pub fn snapshot(&self, now: Instant) -> ControlSnapshot {
        self.control_plane().snapshot(now)
    }

    /// What the data plane decided on this handle's thread, and its socket errors.
    pub fn local_metrics(&self) -> &Metrics {
        &self.local_metrics
    }

    /// Where `key` is currently registered, if anywhere.
    pub fn registered_endpoint(&self, key: &PublicKey, now: Instant) -> Option<SocketAddr> {
        self.control_plane().registered_endpoint(key, now)
    }

    /// Hand over the datagrams the registration tunnels want to send.
    pub fn drain_tx_queue(&self) -> Vec<(SocketAddr, Vec<u8>)> {
        self.control_plane().drain_tx_queue()
    }

    /// Count a failed receive on the caller's socket.
    pub fn record_rx_error(&mut self) {
        self.local_metrics.rx_errors += 1;
    }

    /// Count a datagram the caller failed to send.
    pub fn record_tx_error(&mut self) {
        self.local_metrics.tx_errors += 1;
    }

    /// Decide one datagram, counting and logging the outcome: the data plane
    /// first, then the control plane for what the data plane hands over.
    pub fn handle(&mut self, src: SocketAddr, datagram: &[u8], now: Instant) -> Verdict {
        let metrics = &mut self.local_metrics;
        match self.data_plane.triage(src, datagram, now) {
            Triage::Forward(dst) => {
                record_verdict(metrics, src, datagram, Ok(Accepted::Forward(dst)))
            }
            Triage::Drop(reason) => record_verdict(metrics, src, datagram, Err(reason)),
            Triage::ToControl(message) => self.control_plane().handle(src, datagram, message, now),
        }
    }

    /// Run the registration tunnels' timers and expire soft state, at most once
    /// per `TICK_INTERVAL` however many threads offer a tick.
    pub fn tick(&self, now: Instant) {
        self.control_plane().tick(now);
    }

    /// Apply a (re)loaded config. Removed peers lose their registrations, and
    /// every session routed to them, immediately.
    pub fn reload(&self, config: &Config) {
        self.control_plane().reload(config);
    }
}

/// Turn a datagram's outcome into its `Verdict`, counting it and logging a drop.
fn record_verdict(
    metrics: &mut Metrics,
    src: SocketAddr,
    datagram: &[u8],
    outcome: Result<Accepted, DropReason>,
) -> Verdict {
    let verdict = Verdict::from(outcome);
    metrics.record(verdict, datagram);
    if let Verdict::Drop(reason) = verdict {
        debug!(%reason, %src, "reject");
    }
    verdict
}
