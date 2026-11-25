use std::fmt;
use std::net::SocketAddr;

use crate::packet::ParseError;
use crate::tables::Refusal;

// Generates the enum, its `ALL` list and its `Display` names from one table,
// so a new reason cannot be added without a counter name.
macro_rules! reasons {
    ($($v:ident => $s:literal),* $(,)?) => {
        /// Why a datagram was dropped. Each has its own counter.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Reason { $($v),* }
        impl Reason {
            pub const ALL: &'static [Reason] = &[$(Reason::$v),*];
            pub const COUNT: usize = Self::ALL.len();
        }
        impl fmt::Display for Reason {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(match self { $(Reason::$v => $s),* })
            }
        }
    };
}

reasons! {
    InvalidSource => "invalid_source",
    Malformed => "malformed",
    RateLimited => "rate_limited",
    HandshakeBudget => "handshake_budget",
    RegistrationBudget => "registration_budget",
    ReservedIndex => "reserved_index",
    NoMac1Match => "no_mac1_match",
    PeerNotRegistered => "peer_not_registered",
    Loop => "loop",
    TooManyPending => "too_many_pending",
    TooManySessions => "too_many_sessions",
    PeerQuota => "peer_quota",
    IndexInUse => "index_in_use",
    UnknownIndex => "unknown_index",
    WrongSource => "wrong_source",
    SessionNotPending => "session_not_pending",
    SessionNotOpen => "session_not_open",
    UnknownKey => "registration_unknown_key",
    TunnelAuth => "tunnel_auth_failed",
}

/// What happened to one datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Send the datagram, unchanged, to this address.
    Forward(SocketAddr),
    /// Handled by the relay's own registration tunnel.
    Consumed,
    Drop(Reason),
}

/// What became of a datagram that was not dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Accepted {
    /// Send it, unchanged, to this address.
    Forward(SocketAddr),
    /// Handled by the relay's own registration tunnel.
    Consumed,
}

impl From<Result<Accepted, Reason>> for Verdict {
    fn from(outcome: Result<Accepted, Reason>) -> Self {
        match outcome {
            Ok(Accepted::Forward(dst)) => Verdict::Forward(dst),
            Ok(Accepted::Consumed) => Verdict::Consumed,
            Err(reason) => Verdict::Drop(reason),
        }
    }
}

impl From<ParseError> for Reason {
    fn from(_: ParseError) -> Self {
        Reason::Malformed
    }
}

impl From<Refusal> for Reason {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::IndexInUse => Reason::IndexInUse,
            Refusal::PeerQuota => Reason::PeerQuota,
            Refusal::Full => Reason::TooManySessions,
        }
    }
}
