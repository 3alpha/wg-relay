use std::fmt;
use std::net::SocketAddr;

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
    Malformed => "malformed",
    RateLimited => "rate_limited",
    ReservedIndex => "reserved_index",
    NoMac1Match => "no_mac1_match",
    PeerNotRegistered => "peer_not_registered",
    Loop => "loop",
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

impl From<Result<SocketAddr, Reason>> for Verdict {
    fn from(r: Result<SocketAddr, Reason>) -> Self {
        match r {
            Ok(dst) => Verdict::Forward(dst),
            Err(reason) => Verdict::Drop(reason),
        }
    }
}
