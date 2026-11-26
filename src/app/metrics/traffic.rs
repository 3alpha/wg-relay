//! Datagram, byte, message and socket counters, in total and per forwarding thread.

use wg_relay::message::MessageType;
use wg_relay::relay::{DropReason, Metrics};

use super::encoder::Encoder;
use crate::app::workers::Snapshot;

/// Encode the traffic counters of `snapshot`.
pub(super) fn encode(enc: &mut Encoder, snapshot: &Snapshot) {
    totals(enc, &snapshot.total);
    messages(enc, &snapshot.total);
    planes(enc, snapshot);
    per_worker(enc, &snapshot.workers);
}

/// Who decided each datagram: the data plane, lock-free on its thread, or the
/// control plane, under its lock. A rising control share means handshake or junk pressure.
fn planes(enc: &mut Encoder, snapshot: &Snapshot) {
    let data: u64 = snapshot.workers.iter().map(|m| m.rx).sum();
    enc.counter(
        "wg_relay_datagrams_decided_total",
        "Datagrams by the plane that decided them: data (lock-free) or control (under its lock).",
    )
    .sample(&[("plane", "data")], data)
    .sample(&[("plane", "control")], snapshot.control.metrics.rx);
}

fn totals(enc: &mut Encoder, m: &Metrics) {
    enc.counter("wg_relay_datagrams_received_total", "UDP datagrams received.").value(m.rx);
    enc.counter("wg_relay_received_bytes_total", "UDP payload bytes received.").value(m.rx_bytes);
    enc.counter("wg_relay_datagrams_forwarded_total", "Datagrams forwarded unchanged.")
        .value(m.forwarded);
    enc.counter("wg_relay_forwarded_bytes_total", "UDP payload bytes forwarded.")
        .value(m.forwarded_bytes);
    enc.counter(
        "wg_relay_datagrams_delivered_locally_total",
        "Datagrams taken by the relay's registration tunnels.",
    )
    .value(m.tunnel_rx);
    enc.counter(
        "wg_relay_delivered_locally_bytes_total",
        "UDP payload bytes taken by the relay's registration tunnels.",
    )
    .value(m.tunnel_rx_bytes);
    let mut dropped =
        enc.counter("wg_relay_datagrams_dropped_total", "Datagrams dropped, by reason.");
    for r in DropReason::ALL {
        dropped.sample(&[("reason", &r.to_string())], m.rejected(*r));
    }
    enc.counter("wg_relay_dropped_bytes_total", "UDP payload bytes dropped.")
        .value(m.dropped_bytes);
    enc.counter(
        "wg_relay_tunnel_datagrams_sent_total",
        "Datagrams the registration tunnels sent: handshake responses, keepalives, ping replies.",
    )
    .value(m.tunnel_tx);
    enc.counter(
        "wg_relay_tunnel_sent_bytes_total",
        "UDP payload bytes the registration tunnels sent.",
    )
    .value(m.tunnel_tx_bytes);
    enc.counter("wg_relay_socket_errors_total", "Failed socket receives and sends.")
        .sample(&[("direction", "receive")], m.rx_errors)
        .sample(&[("direction", "send")], m.tx_errors);
}

fn messages(enc: &mut Encoder, m: &Metrics) {
    let mut received = enc.counter(
        "wg_relay_messages_received_total",
        "Received datagrams that parsed as a WireGuard message, by message type.",
    );
    for t in MessageType::ALL {
        received.sample(&[("type", &t.to_string())], m.messages_received(t));
    }
    let mut forwarded =
        enc.counter("wg_relay_messages_forwarded_total", "Messages forwarded, by message type.");
    for t in MessageType::ALL {
        forwarded.sample(&[("type", &t.to_string())], m.messages_forwarded(t));
    }
}

/// Per thread, only what its data plane decided: datagrams it handed to the
/// control plane are counted in the totals, not here.
fn per_worker(enc: &mut Encoder, workers: &[Metrics]) {
    let names: Vec<String> = (0..workers.len()).map(|i| i.to_string()).collect();
    let each = |enc: &mut Encoder, name, help, get: fn(&Metrics) -> u64| {
        let mut family = enc.counter(name, help);
        for (worker, m) in names.iter().zip(workers) {
            family.sample(&[("worker", worker)], get(m));
        }
    };
    each(
        enc,
        "wg_relay_worker_datagrams_total",
        "Datagrams the data plane decided on this forwarding thread.",
        |m| m.rx,
    );
    each(
        enc,
        "wg_relay_worker_bytes_total",
        "UDP payload bytes the data plane decided on this forwarding thread.",
        |m| m.rx_bytes,
    );
    each(
        enc,
        "wg_relay_worker_datagrams_forwarded_total",
        "Datagrams the data plane forwarded on this forwarding thread.",
        |m| m.forwarded,
    );
    each(
        enc,
        "wg_relay_worker_forwarded_bytes_total",
        "UDP payload bytes the data plane forwarded on this forwarding thread.",
        |m| m.forwarded_bytes,
    );
    let mut errors = enc.counter(
        "wg_relay_worker_socket_errors_total",
        "Failed socket receives and sends on this forwarding thread.",
    );
    for (worker, m) in names.iter().zip(workers) {
        errors.sample(&[("worker", worker), ("direction", "receive")], m.rx_errors);
        errors.sample(&[("worker", worker), ("direction", "send")], m.tx_errors);
    }
}
