//! Soft state: registry, session table and the established-session view it
//! keeps for forwarding, per-source rate limiter, work budgets.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

mod accounting;
mod bucket;
mod budget;
mod established;
mod rate_limit;
mod registry;
mod session;
mod sessions;

pub use budget::WorkBudget;
pub use established::{EstablishedSessions, Route};
pub use rate_limit::RateLimiter;
pub use registry::Registry;
pub use session::{Session, SessionState};
pub use sessions::{InsertError, SessionLimits, SessionTable};

/// Lifetime of a registration from the last datagram that authenticated on
/// the configured peer's registration tunnel.
pub const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(180);
/// Lifetime of a pending entry: a forwarded handshake is answered within
/// WireGuard's 5 s retry timer or abandoned.
pub const PENDING_TIMEOUT: Duration = Duration::from_secs(10);
/// Lifetime of an established entry from the handshake that established it,
/// however much traffic it carries: WireGuard never uses a key older than 180 s
/// (`REJECT_AFTER_TIME`), and the 20 s on top cover the round trip.
pub const ESTABLISHED_TIMEOUT: Duration = Duration::from_secs(200);

/// Maps smaller than this are never shrunk, to avoid reallocating for nothing.
const SHRINK_MIN_CAPACITY: usize = 1024;

fn live(at: Instant, now: Instant, timeout: Duration) -> bool {
    now.saturating_duration_since(at) < timeout
}

/// Give memory back once a map is mostly empty, e.g. after a flood:
/// `HashMap` never shrinks on its own.
fn shrink_if_sparse<K: Eq + Hash, V>(map: &mut HashMap<K, V>) {
    if map.capacity() > SHRINK_MIN_CAPACITY && map.capacity() > 4 * map.len() {
        map.shrink_to(2 * map.len());
    }
}
