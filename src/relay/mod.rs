//! The relay state machine: registration tunnels plus opaque forwarding.
//!
//! `Relay::handle` does no I/O: it returns a `Verdict` for the datagram and
//! queues the relay's own tunnel output for `take_outbox`. Inside, the
//! forwarding half decides what it can from open sessions alone and hands the
//! rest to the control half, which owns everything that changes.

use std::net::SocketAddr;
use std::time::Instant;

use tracing::debug;

use crate::config::Config;
use crate::key::PeerKey;

mod control;
mod forwarder;
mod metrics;
mod reason;

use control::Control;
use forwarder::Lookup;
pub use metrics::Metrics;
use reason::Accepted;
pub use reason::{Reason, Verdict};

pub struct Relay {
    control: Control,
    /// What the forwarding half decided, and socket errors: the counters each
    /// forwarding worker will own.
    counters: Metrics,
}

impl Relay {
    pub fn new(cfg: &Config) -> Self {
        Relay { control: Control::new(cfg), counters: Metrics::default() }
    }

    pub fn public_key(&self) -> PeerKey {
        self.control.public_key()
    }

    pub fn peer_count(&self) -> usize {
        self.control.peer_count()
    }

    pub fn session_count(&self) -> usize {
        self.control.session_count()
    }

    /// Both halves' counters, merged.
    pub fn metrics(&self) -> Metrics {
        let mut all = self.counters.clone();
        all += self.control.metrics();
        all
    }

    /// Where `key` is currently registered, if anywhere.
    pub fn registered_addr(&self, key: &PeerKey, now: Instant) -> Option<SocketAddr> {
        self.control.registered_addr(key, now)
    }

    /// Hand over the datagrams the relay's own tunnels want to send.
    pub fn take_outbox(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        self.control.take_outbox()
    }

    /// Count a datagram the caller failed to send.
    pub fn record_send_error(&mut self) {
        self.counters.send_errors += 1;
    }

    /// Count a failed receive on the caller's socket.
    pub fn record_recv_error(&mut self) {
        self.counters.recv_errors += 1;
    }

    /// Process one datagram, counting and logging the outcome: the forwarding
    /// half first, the control half for what is not the forwarding half's.
    pub fn handle(&mut self, src: SocketAddr, pkt: &[u8], now: Instant) -> Verdict {
        let outcome = match self.control.forwarder().lookup(src, pkt, now) {
            Ok(Lookup::NotMine(packet)) => return self.control.handle(src, pkt, packet, now),
            Ok(Lookup::Forward(dst)) => Ok(Accepted::Forward(dst)),
            Err(reason) => Err(reason),
        };
        settle(&mut self.counters, src, outcome)
    }

    /// Run relay tunnel timers and expire soft state. Call a few times a second.
    pub fn tick(&mut self, now: Instant) {
        self.control.tick(now);
    }

    /// Apply a (re)loaded config. Removed peers lose their registrations, and
    /// every session routed to them, immediately.
    pub fn reload(&mut self, cfg: &Config) {
        self.control.reload(cfg);
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
