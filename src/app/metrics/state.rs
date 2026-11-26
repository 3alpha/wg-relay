//! Sessions against their limits, garbage collection, reloads and build facts.

use wg_relay::relay::{ControlSnapshot, LIMITS};

use super::encoder::Encoder;
use super::{Scrape, unix};

/// Encode the session table and the relay's lifecycle from `scrape`.
pub(super) fn encode(enc: &mut Encoder, scrape: &Scrape) {
    sessions(enc, &scrape.snapshot.control, scrape.snapshot.total.pending_evicted);
    lifecycle(enc, scrape);
}

fn sessions(enc: &mut Encoder, control: &ControlSnapshot, pending_evicted: u64) {
    let c = &control.counters;
    let established = control.sessions.saturating_sub(control.pending);
    enc.gauge(
        "wg_relay_sessions",
        "Session entries by state, including expired ones not yet collected.",
    )
    .sample(&[("state", "pending")], control.pending)
    .sample(&[("state", "established")], established);
    enc.gauge(
        "wg_relay_sessions_max",
        "Most session entries in the table, pending or established.",
    )
    .value(LIMITS.sessions);
    enc.gauge("wg_relay_pending_sessions_max", "Most pending session entries in the table.")
        .value(LIMITS.pending);
    enc.gauge("wg_relay_peer_sessions_max", "Most session entries routed to one configured peer.")
        .value(LIMITS.sessions_per_peer);
    enc.gauge(
        "wg_relay_peer_pending_sessions_max",
        "Most pending session entries per configured peer; a new one evicts the oldest.",
    )
    .value(LIMITS.pending_per_peer);
    enc.counter(
        "wg_relay_sessions_expired_total",
        "Sessions removed at the end of their lifetime; pending ones are half-open handshakes.",
    )
    .sample(&[("state", "pending")], c.sessions_expired_pending)
    .sample(&[("state", "established")], c.sessions_expired_established);
    enc.counter(
        "wg_relay_pending_sessions_evicted_total",
        "Pending sessions evicted by a newer initiation to the same configured peer.",
    )
    .value(pending_evicted);
    enc.counter(
        "wg_relay_sessions_revoked_total",
        "Sessions removed by a reload because their configured peer was removed.",
    )
    .value(c.sessions_revoked);
    enc.counter(
        "wg_relay_sessions_roamed_total",
        "Session entries rewritten because their configured peer moved to a new endpoint.",
    )
    .value(c.sessions_roamed);
    enc.counter(
        "wg_relay_gc_runs_total",
        "Garbage collection passes; they remove expired sessions and registrations.",
    )
    .value(c.gc_runs);
}

fn lifecycle(enc: &mut Encoder, scrape: &Scrape) {
    let reloads = &scrape.reloads;
    enc.counter("wg_relay_config_reloads_total", "Config reloads (SIGHUP), by result.")
        .sample(&[("result", "success")], reloads.succeeded)
        .sample(&[("result", "failure")], reloads.failed);
    enc.gauge(
        "wg_relay_config_last_reload_successful",
        "Whether the last reload succeeded; 1 before any reload.",
    )
    .value(reloads.last_successful);
    enc.gauge(
        "wg_relay_config_last_reload_success_timestamp_seconds",
        "When the config was last applied, at startup or by a reload.",
    )
    .value(unix(reloads.last_success));
    enc.gauge("wg_relay_workers", "Forwarding threads.").value(scrape.snapshot.workers.len());
    enc.gauge("wg_relay_build_info", "The running build; always 1.")
        .sample(&[("version", env!("CARGO_PKG_VERSION"))], 1u64);
}
