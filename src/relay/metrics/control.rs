use std::fmt;

use boringtun::noise::errors::WireGuardError;

/// Counters only the control plane keeps, under its lock: session and
/// registration lifecycles and the cost of unauthenticated handshakes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ControlMetrics {
    /// Pending sessions that reached the end of their lifetime unanswered:
    /// half-open handshakes, the main sign of an initiation flood.
    pub sessions_expired_pending: u64,
    /// Established sessions that reached the end of their lifetime.
    pub sessions_expired_established: u64,
    /// Sessions removed by a reload because their configured peer was.
    pub sessions_revoked: u64,
    /// Session entries rewritten because a configured peer roamed.
    pub sessions_roamed: u64,
    /// Configured peers that registered while not registered.
    pub registrations: u64,
    /// Registered configured peers that moved to a new endpoint.
    pub registrations_roamed: u64,
    /// Registrations that timed out.
    pub registrations_expired: u64,
    /// Registration initiations a registration tunnel took.
    pub registration_initiations_accepted: u64,
    /// Registration initiations dropped: budget, unknown key or failed authentication.
    pub registration_initiations_rejected: u64,
    /// X25519 operations spent identifying the sender of a registration initiation.
    pub registration_key_exchanges: u64,
    /// Scans of the configured peers' mac1 keys for forwarded initiations.
    pub mac1_scans: u64,
    /// Mac1 keys hashed: every key a scan tried, and the relay's own key once per initiation.
    pub mac1_checks: u64,
    /// Cookie replies the registration tunnels sent because they were under load.
    pub tunnel_cookie_replies: u64,
    /// Garbage collection passes over the registry and the session table.
    pub gc_runs: u64,
    tunnel_errors: [u64; TunnelError::ALL.len()],
}

impl ControlMetrics {
    /// How many datagrams a registration tunnel refused with an error of `kind`.
    pub fn tunnel_errors(&self, kind: TunnelError) -> u64 {
        self.tunnel_errors[kind.index()]
    }

    /// Count a datagram a registration tunnel refused.
    pub(crate) fn record_tunnel_error(&mut self, e: &WireGuardError) {
        self.tunnel_errors[TunnelError::from(e).index()] += 1;
    }
}

/// Why a registration tunnel refused a datagram, grouped from boringtun's errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelError {
    /// A replayed or stale handshake timestamp or data counter.
    Replay,
    /// A MAC, AEAD tag or key that does not check out.
    Authentication,
    /// No session matches: an unknown index, an expired session, an unexpected message.
    Session,
    /// The tunnel's own handshake rate limit.
    UnderLoad,
    /// Anything else, such as a malformed packet.
    Other,
}

impl TunnelError {
    pub const ALL: [TunnelError; 5] = [
        TunnelError::Replay,
        TunnelError::Authentication,
        TunnelError::Session,
        TunnelError::UnderLoad,
        TunnelError::Other,
    ];

    fn index(self) -> usize {
        match self {
            TunnelError::Replay => 0,
            TunnelError::Authentication => 1,
            TunnelError::Session => 2,
            TunnelError::UnderLoad => 3,
            TunnelError::Other => 4,
        }
    }
}

impl From<&WireGuardError> for TunnelError {
    fn from(e: &WireGuardError) -> Self {
        match e {
            WireGuardError::InvalidTai64nTimestamp
            | WireGuardError::InvalidCounter
            | WireGuardError::DuplicateCounter => TunnelError::Replay,
            WireGuardError::InvalidMac
            | WireGuardError::InvalidAeadTag
            | WireGuardError::WrongKey => TunnelError::Authentication,
            WireGuardError::WrongIndex
            | WireGuardError::NoCurrentSession
            | WireGuardError::ConnectionExpired
            | WireGuardError::UnexpectedPacket => TunnelError::Session,
            WireGuardError::UnderLoad => TunnelError::UnderLoad,
            WireGuardError::DestinationBufferTooSmall
            | WireGuardError::IncorrectPacketLength
            | WireGuardError::WrongPacketType
            | WireGuardError::WrongTai64nTimestamp
            | WireGuardError::InvalidPacket
            | WireGuardError::LockFailed => TunnelError::Other,
        }
    }
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TunnelError::Replay => "replay",
            TunnelError::Authentication => "authentication",
            TunnelError::Session => "session",
            TunnelError::UnderLoad => "under_load",
            TunnelError::Other => "other",
        })
    }
}

impl fmt::Display for ControlMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "half_open_expired={} established_expired={} sessions_revoked={} sessions_roamed={} \
             registrations={} registrations_roamed={} registrations_expired={} \
             registration_initiations_accepted={} registration_initiations_rejected={} \
             mac1_scans={} mac1_checks={} tunnel_cookie_replies={} gc_runs={}",
            self.sessions_expired_pending,
            self.sessions_expired_established,
            self.sessions_revoked,
            self.sessions_roamed,
            self.registrations,
            self.registrations_roamed,
            self.registrations_expired,
            self.registration_initiations_accepted,
            self.registration_initiations_rejected,
            self.mac1_scans,
            self.mac1_checks,
            self.tunnel_cookie_replies,
            self.gc_runs,
        )?;
        for kind in TunnelError::ALL.iter().filter(|k| self.tunnel_errors(**k) > 0) {
            write!(f, " tunnel_error.{kind}={}", self.tunnel_errors(*kind))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_tunnel_errors_and_logs_only_those_seen() {
        let mut m = ControlMetrics::default();
        m.record_tunnel_error(&WireGuardError::DuplicateCounter);
        m.record_tunnel_error(&WireGuardError::InvalidTai64nTimestamp);
        m.record_tunnel_error(&WireGuardError::InvalidMac);
        let counts = TunnelError::ALL.map(|k| m.tunnel_errors(k));
        assert_eq!(counts, [2, 1, 0, 0, 0]);
        let line = m.to_string();
        assert!(line.ends_with(" gc_runs=0 tunnel_error.replay=2 tunnel_error.authentication=1"));
    }
}
