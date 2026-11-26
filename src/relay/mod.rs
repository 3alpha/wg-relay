//! The relay state machine: registration tunnels plus opaque forwarding.
//!
//! `Relay::handle` does no I/O: it returns a `Verdict` for the datagram and
//! queues the registration tunnels' output for `take_outbox`. Inside, the
//! forwarding half decides what it can from established sessions alone and
//! hands the rest to the control half, which owns everything that changes.
//! Several threads can run the relay at once, each with its own `Relay` from
//! `Relay::share`: the forwarding half is read without a lock, the control
//! half is locked for each datagram it decides.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use tracing::debug;

use crate::config::Config;
use crate::key::PeerKey;

mod control;
mod forwarder;
mod metrics;
mod reason;
#[cfg(test)]
mod testing;

use control::Control;
pub use control::TICK_INTERVAL;
use forwarder::{Forwarder, Triage};
pub use metrics::Metrics;
use reason::Accepted;
pub use reason::{Reason, Verdict};

/// One thread's handle on the relay.
pub struct Relay {
    forwarder: Arc<Forwarder>,
    control: Arc<Mutex<Control>>,
    /// What the forwarding half decided on this thread, and its socket errors.
    counters: Metrics,
}

impl Relay {
    /// Build the relay for `cfg`, with nothing registered yet.
    pub fn new(cfg: &Config) -> Self {
        let control = Control::new(cfg);
        Relay {
            forwarder: control.forwarder(),
            control: Arc::new(Mutex::new(control)),
            counters: Metrics::default(),
        }
    }

    /// Another handle on the same relay, with counters of its own, for another thread.
    pub fn share(&self) -> Self {
        Relay {
            forwarder: Arc::clone(&self.forwarder),
            control: Arc::clone(&self.control),
            counters: Metrics::default(),
        }
    }

    /// Lock the control half. A thread that panicked holding it ends the
    /// process anyway, so its state is used as it is.
    fn control(&self) -> MutexGuard<'_, Control> {
        self.control.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The relay's own public key.
    pub fn public_key(&self) -> PeerKey {
        self.control().public_key()
    }

    /// How many listed peers the config has.
    pub fn peer_count(&self) -> usize {
        self.control().peer_count()
    }

    /// How many sessions, pending or established, the relay holds.
    pub fn session_count(&self) -> usize {
        self.control().session_count()
    }

    /// This handle's counters and the control half's, merged.
    pub fn metrics(&self) -> Metrics {
        let mut all = self.counters.clone();
        all += self.control().metrics();
        all
    }

    /// What the forwarding half decided on this handle's thread, and its socket errors.
    pub fn counters(&self) -> &Metrics {
        &self.counters
    }

    /// Where `key` is currently registered, if anywhere.
    pub fn registered_addr(&self, key: &PeerKey, now: Instant) -> Option<SocketAddr> {
        self.control().registered_addr(key, now)
    }

    /// Hand over the datagrams the registration tunnels want to send.
    pub fn take_outbox(&self) -> Vec<(SocketAddr, Vec<u8>)> {
        self.control().take_outbox()
    }

    /// Count a failed receive on the caller's socket.
    pub fn record_recv_error(&mut self) {
        self.counters.recv_errors += 1;
    }

    /// Count a datagram the caller failed to send.
    pub fn record_send_error(&mut self) {
        self.counters.send_errors += 1;
    }

    /// Decide one datagram, counting and logging the outcome: the forwarding
    /// half first, then the control half for what the forwarding half hands over.
    pub fn handle(&mut self, src: SocketAddr, datagram: &[u8], now: Instant) -> Verdict {
        match self.forwarder.triage(src, datagram, now) {
            Triage::Forward(dst) => settle(&mut self.counters, src, Ok(Accepted::Forward(dst))),
            Triage::Drop(reason) => settle(&mut self.counters, src, Err(reason)),
            Triage::ToControl(message) => self.control().handle(src, datagram, message, now),
        }
    }

    /// Run the registration tunnels' timers and expire soft state, at most once
    /// per `TICK_INTERVAL` however many threads offer a tick.
    pub fn tick(&self, now: Instant) {
        self.control().tick(now);
    }

    /// Apply a (re)loaded config. Removed peers lose their registrations, and
    /// every session routed to them, immediately.
    pub fn reload(&self, cfg: &Config) {
        self.control().reload(cfg);
    }
}

/// Turn a datagram's outcome into its `Verdict`, counting it and logging a drop.
fn settle(metrics: &mut Metrics, src: SocketAddr, outcome: Result<Accepted, Reason>) -> Verdict {
    let verdict = Verdict::from(outcome);
    metrics.record(verdict);
    if let Verdict::Drop(reason) = verdict {
        debug!(%reason, %src, "reject");
    }
    verdict
}
