//! Configured peers: registrations, and per peer its registration, sessions
//! and the initiations aimed at it, so a flood against one server stands out.

use std::time::Duration;

use wg_relay::relay::{ControlSnapshot, PeerSnapshot};

use super::encoder::Encoder;

/// Encode the registration counters and every configured peer, given the time since the epoch.
pub(super) fn encode(enc: &mut Encoder, control: &ControlSnapshot, now: Duration) {
    registrations(enc, control);
    each_peer(enc, &control.peers, now);
}

fn registrations(enc: &mut Encoder, control: &ControlSnapshot) {
    let c = &control.counters;
    let registered = control.peers.iter().filter(|p| p.registered).count();
    enc.gauge("wg_relay_configured_peers", "Configured peers.").value(control.peers.len());
    enc.gauge("wg_relay_registered_peers", "Configured peers with a live registration.")
        .value(registered);
    enc.gauge(
        "wg_relay_reserved_prefixes",
        "Index prefixes reserved for registration tunnels, one per configured peer.",
    )
    .value(control.reserved_prefixes);
    enc.counter(
        "wg_relay_registrations_total",
        "Registrations: new for a peer that was not registered, roamed for one that moved.",
    )
    .sample(&[("kind", "new")], c.registrations)
    .sample(&[("kind", "roamed")], c.registrations_roamed);
    enc.counter("wg_relay_registrations_expired_total", "Registrations that timed out.")
        .value(c.registrations_expired);
}

fn each_peer(enc: &mut Encoder, peers: &[PeerSnapshot], now: Duration) {
    let mut family =
        enc.gauge("wg_relay_peer_registered", "Whether the configured peer is registered.");
    for p in peers {
        family.sample(&[("peer", &p.name)], p.registered);
    }
    let mut family = enc.gauge(
        "wg_relay_peer_last_authenticated_timestamp_seconds",
        "When the configured peer last authenticated on its registration tunnel.",
    );
    for p in peers {
        if let Some(age) = p.since_authenticated {
            family.sample(&[("peer", &p.name)], now.saturating_sub(age));
        }
    }
    let mut family = enc.gauge(
        "wg_relay_peer_sessions",
        "Session entries routed to the configured peer, by state.",
    );
    for p in peers {
        family.sample(&[("peer", &p.name), ("state", "pending")], p.pending);
        let established = p.sessions.saturating_sub(p.pending);
        family.sample(&[("peer", &p.name), ("state", "established")], established);
    }
    let mut family = enc.counter(
        "wg_relay_peer_initiations_total",
        "Initiations whose mac1 named the configured peer, forwarded or dropped after the scan, \
         since it was configured.",
    );
    for p in peers {
        family.sample(&[("peer", &p.name), ("result", "forwarded")], p.initiations_forwarded);
        family.sample(&[("peer", &p.name), ("result", "dropped")], p.initiations_dropped);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_each_configured_peer_exactly() {
        let peer = |name: &str, registered, since_authenticated, forwarded, dropped| PeerSnapshot {
            name: name.into(),
            registered,
            since_authenticated,
            sessions: 5,
            pending: 1,
            initiations_forwarded: forwarded,
            initiations_dropped: dropped,
        };
        let peers = [
            peer("home", true, Some(Duration::from_secs(10)), 7, 2),
            peer("o\"ffice", false, None, 0, 9),
        ];
        let mut enc = Encoder::default();
        each_peer(&mut enc, &peers, Duration::from_secs(2_000));
        assert_eq!(
            enc.finish(),
            "# HELP wg_relay_peer_registered Whether the configured peer is registered.\n\
             # TYPE wg_relay_peer_registered gauge\n\
             wg_relay_peer_registered{peer=\"home\"} 1\n\
             wg_relay_peer_registered{peer=\"o\\\"ffice\"} 0\n\
             # HELP wg_relay_peer_last_authenticated_timestamp_seconds When the configured peer \
             last authenticated on its registration tunnel.\n\
             # TYPE wg_relay_peer_last_authenticated_timestamp_seconds gauge\n\
             wg_relay_peer_last_authenticated_timestamp_seconds{peer=\"home\"} 1990\n\
             # HELP wg_relay_peer_sessions Session entries routed to the configured peer, by state.\n\
             # TYPE wg_relay_peer_sessions gauge\n\
             wg_relay_peer_sessions{peer=\"home\",state=\"pending\"} 1\n\
             wg_relay_peer_sessions{peer=\"home\",state=\"established\"} 4\n\
             wg_relay_peer_sessions{peer=\"o\\\"ffice\",state=\"pending\"} 1\n\
             wg_relay_peer_sessions{peer=\"o\\\"ffice\",state=\"established\"} 4\n\
             # HELP wg_relay_peer_initiations_total Initiations whose mac1 named the configured \
             peer, forwarded or dropped after the scan, since it was configured.\n\
             # TYPE wg_relay_peer_initiations_total counter\n\
             wg_relay_peer_initiations_total{peer=\"home\",result=\"forwarded\"} 7\n\
             wg_relay_peer_initiations_total{peer=\"home\",result=\"dropped\"} 2\n\
             wg_relay_peer_initiations_total{peer=\"o\\\"ffice\",result=\"forwarded\"} 0\n\
             wg_relay_peer_initiations_total{peer=\"o\\\"ffice\",result=\"dropped\"} 9\n"
        );
    }
}
