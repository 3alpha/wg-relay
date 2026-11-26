//! The cost of unauthenticated handshakes: rate limiting, work budgets, mac1
//! scans and registration attempts, where floods and CPU abuse show up.

use wg_relay::relay::{ControlSnapshot, LIMITS, TunnelError};

use super::encoder::Encoder;

/// Encode the handshake limits and work counters from `control`.
pub(super) fn encode(enc: &mut Encoder, control: &ControlSnapshot, handshake_rate_per_sec: f64) {
    rate_limit(enc, control, handshake_rate_per_sec);
    budgets(enc, control);
    registration(enc, control);
}

fn rate_limit(enc: &mut Encoder, control: &ControlSnapshot, handshake_rate_per_sec: f64) {
    enc.gauge(
        "wg_relay_handshake_rate_per_source",
        "Handshake initiations per second each source (IPv4 address or IPv6 /64) may send.",
    )
    .value(handshake_rate_per_sec);
    enc.gauge(
        "wg_relay_rate_limit_buckets_used",
        "Per-source rate-limit buckets some source has used since startup; never freed.",
    )
    .value(control.rate_limit_buckets_used);
    enc.gauge(
        "wg_relay_rate_limit_buckets",
        "Per-source rate-limit buckets; sources hashed to the same one share it.",
    )
    .value(control.rate_limit_buckets);
}

fn budgets(enc: &mut Encoder, control: &ControlSnapshot) {
    let c = &control.counters;
    enc.gauge(
        "wg_relay_forwarding_budget_checks_per_second",
        "Mac1 checks per second the forwarding budget allows.",
    )
    .value(LIMITS.forwarding_work_per_sec);
    enc.gauge(
        "wg_relay_registration_budget_checks_per_second",
        "Mac1 checks per second the registration budget allows; one attempt costs 400.",
    )
    .value(LIMITS.registration_work_per_sec);
    enc.gauge(
        "wg_relay_handshake_budget_remaining_checks",
        "Mac1 checks each handshake budget would allow now; at or below 0 it drops initiations.",
    )
    .sample(&[("budget", "forwarding")], control.forwarding_budget_remaining)
    .sample(&[("budget", "registration")], control.registration_budget_remaining);
    enc.counter(
        "wg_relay_mac1_scans_total",
        "Scans of the configured peers' mac1 keys to find a forwarded initiation's destination.",
    )
    .value(c.mac1_scans);
    enc.counter(
        "wg_relay_mac1_checks_total",
        "Mac1 keys hashed: every key a scan tried, plus the relay's own key once per initiation.",
    )
    .value(c.mac1_checks);
}

fn registration(enc: &mut Encoder, control: &ControlSnapshot) {
    let c = &control.counters;
    enc.counter(
        "wg_relay_registration_initiations_total",
        "Initiations to the relay itself that passed the rate limit, by whether a registration \
         tunnel took them.",
    )
    .sample(&[("result", "accepted")], c.registration_initiations_accepted)
    .sample(&[("result", "rejected")], c.registration_initiations_rejected);
    enc.counter(
        "wg_relay_registration_key_exchanges_total",
        "X25519 operations spent identifying the senders of registration initiations.",
    )
    .value(c.registration_key_exchanges);
    let mut errors = enc.counter(
        "wg_relay_tunnel_errors_total",
        "Datagrams a registration tunnel refused, by kind of error.",
    );
    for kind in TunnelError::ALL {
        errors.sample(&[("error", &kind.to_string())], c.tunnel_errors(kind));
    }
    enc.counter(
        "wg_relay_tunnel_cookie_replies_sent_total",
        "Cookie replies the registration tunnels sent because they were under load.",
    )
    .value(c.tunnel_cookie_replies);
}
