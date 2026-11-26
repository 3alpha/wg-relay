use std::fmt;
use std::net::SocketAddr;

use crate::packet::ParseError;
use crate::tables::Refusal;

// Generates the enum, its `ALL` list and its `Display` names from one table,
// so a new reason cannot be added without a counter name. In the order the
// relay checks them: the forwarding half's checks, the per-source limit, then
// registration, forwarded initiations and the session lookups.
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
    RegistrationBudget => "registration_budget",
    RegistrationUnknownKey => "registration_unknown_key",
    TunnelAuthFailed => "tunnel_auth_failed",
    ReservedIndex => "reserved_index",
    TooManySessions => "too_many_sessions",
    TooManyPending => "too_many_pending",
    ForwardingBudget => "forwarding_budget",
    NoMac1Match => "no_mac1_match",
    PeerQuota => "peer_quota",
    PeerNotRegistered => "peer_not_registered",
    Loop => "loop",
    IndexInUse => "index_in_use",
    UnknownIndex => "unknown_index",
    WrongSource => "wrong_source",
    SessionNotPending => "session_not_pending",
}

/// What happened to one datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Send it, unchanged, to this address.
    Forward(SocketAddr),
    /// Taken by a listed peer's registration tunnel with the relay.
    Consumed,
    Drop(Reason),
}

/// What became of a datagram that was not dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Accepted {
    /// Send it, unchanged, to this address.
    Forward(SocketAddr),
    /// Taken by a listed peer's registration tunnel with the relay.
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
