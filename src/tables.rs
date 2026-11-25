//! Soft-state tables: registry, session table, per-IP rate limiter.

use crate::key::PeerKey;
use crate::packet::{IdxPrefix, SessionIdx};
use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

pub const REGISTRY_TTL: Duration = Duration::from_secs(180);
pub const SESSION_TTL: Duration = Duration::from_secs(200);
/// A handshake is answered within WireGuard's 5 s retry timer or abandoned.
pub const PENDING_TTL: Duration = Duration::from_secs(10);

/// Rate-limit buckets, a power of two. Fixed, so spoofed sources cannot grow memory.
const RATE_SLOTS: usize = 1 << 16;
/// Maps smaller than this are never shrunk, to avoid reallocating for nothing.
const SHRINK_MIN_CAPACITY: usize = 1024;

fn live(at: Instant, now: Instant, ttl: Duration) -> bool {
    now.saturating_duration_since(at) < ttl
}

/// Give memory back once a map is mostly empty, e.g. after a flood:
/// `HashMap` never shrinks on its own.
fn shrink_if_sparse<K: Eq + std::hash::Hash, V>(map: &mut HashMap<K, V>) {
    if map.capacity() > SHRINK_MIN_CAPACITY && map.capacity() > 4 * map.len() {
        map.shrink_to(2 * map.len());
    }
}

/// key -> (address, last authenticated packet), plus the reverse map. Only
/// written after a packet authenticates on that key's relay tunnel.
pub struct Registry {
    ttl: Duration,
    by_key: HashMap<PeerKey, (SocketAddr, Instant)>,
    by_addr: HashMap<SocketAddr, PeerKey>,
}

impl Registry {
    pub fn new(ttl: Duration) -> Self {
        Registry { ttl, by_key: HashMap::new(), by_addr: HashMap::new() }
    }

    /// Record that `k` authenticated from `addr`. Returns `Some(previous)` if
    /// the address changed (new registration or roaming).
    pub fn update(
        &mut self,
        k: PeerKey,
        addr: SocketAddr,
        now: Instant,
    ) -> Option<Option<SocketAddr>> {
        let old = self.by_key.insert(k, (addr, now)).map(|(a, _)| a);
        if old == Some(addr) {
            return None;
        }
        if let Some(o) = old {
            self.by_addr.remove(&o);
        }
        // An address belongs to at most one key: the newest claimant wins.
        if let Some(prev) = self.by_addr.insert(addr, k)
            && prev != k
        {
            tracing::warn!(%addr, "address moved between registered keys");
            self.by_key.remove(&prev);
        }
        Some(old)
    }

    pub fn addr(&self, k: &PeerKey, now: Instant) -> Option<SocketAddr> {
        self.by_key.get(k).filter(|(_, t)| live(*t, now, self.ttl)).map(|(a, _)| *a)
    }

    pub fn remove(&mut self, k: &PeerKey) -> bool {
        let Some((a, _)) = self.by_key.remove(k) else { return false };
        self.by_addr.remove(&a);
        true
    }

    pub fn keys(&self) -> Vec<PeerKey> {
        self.by_key.keys().copied().collect()
    }

    /// Drop stale entries, returning the expired keys.
    pub fn expire(&mut self, now: Instant) -> Vec<PeerKey> {
        let gone: Vec<PeerKey> = self
            .by_key
            .iter()
            .filter(|(_, (_, t))| !live(*t, now, self.ttl))
            .map(|(k, _)| *k)
            .collect();
        for k in &gone {
            self.remove(k);
        }
        gone
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Initiation forwarded, response not yet accepted: only cookie replies pass.
    Pending,
    /// Handshake complete: data passes.
    Open,
}

/// Forwarding state for one session index (the receiver_idx of later packets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    /// Where packets carrying this index are sent.
    pub dest: SocketAddr,
    /// The only address allowed to send packets carrying this index.
    pub expected_src: SocketAddr,
    pub state: SessionState,
    pub last_seen: Instant,
    /// The listed peer the session was routed to; removing it revokes the session.
    pub peer: PeerKey,
}

impl Session {
    /// The initiator's index after its initiation was forwarded.
    pub fn pending(
        dest: SocketAddr,
        expected_src: SocketAddr,
        peer: PeerKey,
        now: Instant,
    ) -> Self {
        Session { dest, expected_src, state: SessionState::Pending, last_seen: now, peer }
    }

    /// The responder's index after its response was accepted.
    pub fn open(dest: SocketAddr, expected_src: SocketAddr, peer: PeerKey, now: Instant) -> Self {
        Session { state: SessionState::Open, ..Self::pending(dest, expected_src, peer, now) }
    }
}

/// Idle lifetimes per session state.
#[derive(Debug, Clone, Copy)]
struct Ttls {
    open: Duration,
    pending: Duration,
}

impl Ttls {
    fn live(self, s: &Session, now: Instant) -> bool {
        let ttl = match s.state {
            SessionState::Open => self.open,
            SessionState::Pending => self.pending,
        };
        live(s.last_seen, now, ttl)
    }
}

pub struct SessionTable {
    ttls: Ttls,
    map: HashMap<SessionIdx, Session>,
    /// Entries in the `Pending` state, live or not yet swept.
    pending: usize,
}

impl SessionTable {
    pub fn new(open_ttl: Duration, pending_ttl: Duration) -> Self {
        SessionTable {
            ttls: Ttls { open: open_ttl, pending: pending_ttl },
            map: HashMap::new(),
            pending: 0,
        }
    }

    /// Insert unless a live entry for a different address pair owns the index,
    /// so nobody can take over an index someone else is using. Returns whether
    /// the entry was stored.
    pub fn insert(&mut self, idx: SessionIdx, s: Session) -> bool {
        let ttls = self.ttls;
        let taken = self.map.get(&idx).is_some_and(|old| {
            (old.dest, old.expected_src) != (s.dest, s.expected_src) && ttls.live(old, s.last_seen)
        });
        if taken {
            return false;
        }
        if let Some(old) = self.map.insert(idx, s) {
            self.pending -= usize::from(old.state == SessionState::Pending);
        }
        self.pending += usize::from(s.state == SessionState::Pending);
        true
    }

    pub fn get(&self, idx: SessionIdx, now: Instant) -> Option<Session> {
        self.map.get(&idx).filter(|s| self.ttls.live(s, now)).copied()
    }

    /// The live session at `idx`, for checking and refreshing in one lookup.
    pub fn get_mut(&mut self, idx: SessionIdx, now: Instant) -> Option<&mut Session> {
        let ttls = self.ttls;
        self.map.get_mut(&idx).filter(|s| ttls.live(s, now))
    }

    /// Mark a pending index open once the response is accepted.
    pub fn open(&mut self, idx: SessionIdx, now: Instant) {
        if let Some(s) = self.map.get_mut(&idx) {
            self.pending -= usize::from(s.state == SessionState::Pending);
            s.last_seen = now;
            s.state = SessionState::Open;
        }
    }

    /// A registered peer moved: rewrite its address in every session.
    pub fn migrate(&mut self, old: SocketAddr, new: SocketAddr) {
        for s in self.map.values_mut() {
            if s.dest == old {
                s.dest = new;
            }
            if s.expected_src == old {
                s.expected_src = new;
            }
        }
    }

    /// Keep only matching sessions; returns how many were removed.
    pub fn retain(&mut self, mut keep: impl FnMut(&Session) -> bool) -> usize {
        let (before, mut pending_gone) = (self.map.len(), 0);
        self.map.retain(|_, s| {
            let kept = keep(s);
            pending_gone += usize::from(!kept && s.state == SessionState::Pending);
            kept
        });
        self.pending -= pending_gone;
        shrink_if_sparse(&mut self.map);
        before - self.map.len()
    }

    pub fn expire(&mut self, now: Instant) -> usize {
        let ttls = self.ttls;
        self.retain(|s| ttls.live(s, now))
    }

    /// Is any index with these upper 24 bits in use?
    pub fn has_prefix(&self, prefix: IdxPrefix) -> bool {
        self.map.keys().any(|i| i.prefix() == prefix)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// How many sessions await a response.
    pub fn pending(&self) -> usize {
        self.pending
    }
}

/// Tokens earned at a steady rate, up to a cap.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn full(burst: f64, now: Instant) -> Self {
        Bucket { tokens: burst, last: now }
    }

    /// Add the tokens earned since the last refill.
    fn refill(&mut self, now: Instant, per_sec: f64, burst: f64) {
        let earned = now.saturating_duration_since(self.last).as_secs_f64() * per_sec;
        self.tokens = (self.tokens + earned).min(burst);
        self.last = now;
    }
}

/// Token buckets per source, for handshake initiations: an IPv4 address or
/// an IPv6 /64, the smallest block a single host usually gets. Sources are
/// hashed with a random key into a fixed number of buckets, so memory stays
/// constant however many sources (spoofed or not) appear; sources that share a
/// bucket share its allowance.
pub struct RateLimiter {
    burst: f64,
    per_sec: f64,
    hasher: RandomState,
    /// `None` is a bucket nobody has used yet, i.e. a full one.
    buckets: Vec<Option<Bucket>>,
}

impl RateLimiter {
    /// The burst is two seconds' worth of tokens (at least one).
    pub fn new(per_sec: f64) -> Self {
        RateLimiter {
            burst: (per_sec * 2.0).max(1.0),
            per_sec,
            hasher: RandomState::new(),
            buckets: vec![None; RATE_SLOTS],
        }
    }

    pub fn set_rate(&mut self, per_sec: f64) {
        (self.per_sec, self.burst) = (per_sec, (per_sec * 2.0).max(1.0));
    }

    fn slot(&self, ip: IpAddr) -> usize {
        let source = match ip {
            IpAddr::V4(a) => (4, u64::from(a.to_bits())),
            IpAddr::V6(a) => (6, (a.to_bits() >> 64) as u64),
        };
        self.hasher.hash_one(source) as usize % RATE_SLOTS
    }

    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        let (per_sec, burst) = (self.per_sec, self.burst);
        let slot = self.slot(ip);
        let b = self.buckets[slot].get_or_insert(Bucket::full(burst, now));
        b.refill(now, per_sec, burst);
        let ok = b.tokens >= 1.0;
        if ok {
            b.tokens -= 1.0;
        }
        ok
    }
}

/// Global budget for CPU work spent on unauthenticated handshakes, so a flood
/// of them cannot starve forwarding. Work is charged once it is done, so the
/// budget can go into debt by one handshake; the burst is one second's worth.
pub struct WorkBudget {
    per_sec: f64,
    bucket: Option<Bucket>,
}

impl WorkBudget {
    pub fn new(per_sec: f64) -> Self {
        WorkBudget { per_sec, bucket: None }
    }

    /// Is there budget left for more work?
    pub fn available(&mut self, now: Instant) -> bool {
        let b = self.bucket.get_or_insert(Bucket::full(self.per_sec, now));
        b.refill(now, self.per_sec, self.per_sec);
        b.tokens > 0.0
    }

    /// Charge work already done.
    pub fn spend(&mut self, work: usize) {
        if let Some(b) = &mut self.bucket {
            b.tokens -= work as f64;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn key(n: u8) -> PeerKey {
        [n; 32].into()
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn idx(i: u32) -> SessionIdx {
        i.into()
    }

    fn pending(dest: &str, src: &str, t: Instant) -> Session {
        Session::pending(addr(dest), addr(src), key(1), t)
    }

    fn open(dest: &str, src: &str, t: Instant) -> Session {
        Session::open(addr(dest), addr(src), key(1), t)
    }

    fn table() -> SessionTable {
        SessionTable::new(SESSION_TTL, PENDING_TTL)
    }

    #[test]
    fn session_expires_after_ttl_unless_touched() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(idx(42), open("192.0.2.1:1", "192.0.2.2:2", t0));
        assert!(t.get(idx(42), t0 + secs(199)).is_some());
        assert_eq!(t.get(idx(42), t0 + secs(200)), None);
        t.get_mut(idx(42), t0 + secs(150)).unwrap().last_seen = t0 + secs(150);
        assert!(t.get(idx(42), t0 + secs(300)).is_some());
        assert_eq!(t.expire(t0 + secs(349)), 0);
        assert_eq!(t.expire(t0 + secs(351)), 1);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn pending_session_expires_sooner_than_open() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(idx(1), pending("192.0.2.1:1", "192.0.2.2:2", t0));
        t.insert(idx(2), open("192.0.2.1:1", "192.0.2.2:2", t0));
        assert!(t.get(idx(1), t0 + secs(9)).is_some());
        assert_eq!(t.get(idx(1), t0 + secs(10)), None);
        assert!(t.get_mut(idx(1), t0 + secs(10)).is_none());
        assert_eq!(t.expire(t0 + secs(10)), 1);
        assert!(t.get(idx(2), t0 + secs(10)).is_some());
    }

    #[test]
    fn open_marks_session_open_and_refreshes_it() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(idx(42), pending("192.0.2.1:1", "192.0.2.2:2", t0));
        t.open(idx(42), t0 + secs(1));
        assert_eq!(
            t.get(idx(42), t0 + secs(1)),
            Some(open("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1)))
        );
    }

    #[test]
    fn insert_refuses_live_index_of_another_pair_but_replaces_same_pair_or_stale() {
        let t0 = Instant::now();
        let mut t = table();
        assert!(t.insert(idx(7), open("192.0.2.1:1", "192.0.2.2:2", t0)));
        assert!(t.insert(idx(7), open("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1))), "same pair");
        assert!(!t.insert(idx(7), pending("192.0.2.3:3", "192.0.2.4:4", t0 + secs(2))));
        assert_eq!(
            t.get(idx(7), t0 + secs(2)),
            Some(open("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1)))
        );
        assert!(t.insert(idx(7), pending("192.0.2.5:5", "192.0.2.6:6", t0 + secs(500))), "stale");
        assert_eq!(t.get(idx(7), t0 + secs(500)).map(|s| s.dest), Some(addr("192.0.2.5:5")));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn session_migrate_rewrites_both_directions() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(idx(0x00ab_cd01), pending("192.0.2.1:1", "192.0.2.2:2", t0));
        t.insert(idx(0x0011_2201), pending("192.0.2.2:2", "192.0.2.1:1", t0));
        t.migrate(addr("192.0.2.1:1"), addr("192.0.2.9:9"));
        assert_eq!(t.get(idx(0x00ab_cd01), t0).map(|s| s.dest), Some(addr("192.0.2.9:9")));
        assert_eq!(t.get(idx(0x0011_2201), t0).map(|s| s.expected_src), Some(addr("192.0.2.9:9")));
        assert_eq!(t.retain(|s| s.dest.port() == 9), 1);
    }

    #[test]
    fn has_prefix_matches_upper_24_bits_only() {
        let mut t = table();
        t.insert(idx(0x00ab_cd01), pending("192.0.2.1:1", "192.0.2.2:2", Instant::now()));
        assert!(t.has_prefix(idx(0x00ab_cdff).prefix()));
        assert!(!t.has_prefix(idx(0x00ab_ce01).prefix()));
    }

    #[test]
    fn registry_tracks_roaming_conflicts_and_expiry() {
        let t0 = Instant::now();
        let (a1, a2) = (addr("192.0.2.10:1000"), addr("192.0.2.10:1001"));
        let mut r = Registry::new(REGISTRY_TTL);
        assert_eq!(r.update(key(0), a1, t0), Some(None));
        assert_eq!(r.update(key(0), a1, t0), None, "unchanged address");
        assert_eq!(r.update(key(0), a2, t0), Some(Some(a1)), "roamed");
        assert_eq!(r.addr(&key(0), t0), Some(a2));
        assert_eq!(r.update(key(1), a2, t0), Some(None));
        assert_eq!(
            (r.addr(&key(0), t0), r.addr(&key(1), t0)),
            (None, Some(a2)),
            "newest claimant owns address"
        );
        assert_eq!(r.addr(&key(1), t0 + secs(179)), Some(a2));
        assert_eq!(r.addr(&key(1), t0 + secs(180)), None);
        assert_eq!(r.expire(t0 + secs(181)), vec![key(1)]);
        r.update(key(3), a1, t0);
        assert!(r.remove(&key(3)));
        assert!(!r.remove(&key(3)));
        assert_eq!(r.addr(&key(3), t0), None);
    }

    #[test]
    fn work_budget_allows_one_overdraft_then_refills() {
        let t0 = Instant::now();
        let mut b = WorkBudget::new(10.0);
        let spent: Vec<bool> = (0..5)
            .map(|_| {
                let ok = b.available(t0);
                if ok {
                    b.spend(3);
                }
                ok
            })
            .collect();
        assert_eq!(spent, [true, true, true, true, false], "10 -> 7 -> 4 -> 1 -> -2");
        assert!(!b.available(t0 + Duration::from_millis(100)), "-1");
        assert!(b.available(t0 + Duration::from_millis(300)), "+1");
        b.spend(1000);
        assert!(b.available(t0 + secs(200)), "refills up to the burst");
        b.spend(10);
        assert!(!b.available(t0 + secs(200)), "burst is one second's worth");
    }

    #[test]
    fn rate_limiter_has_two_second_burst_per_source() {
        let t0 = Instant::now();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let mut l = RateLimiter::new(1.5);
        assert!((0..3).all(|_| l.allow(ip, t0)), "burst of 3");
        assert!(!l.allow(ip, t0));
        // Any other source in a different bucket is unaffected.
        let other = (2..=255)
            .map(|n| IpAddr::from([192, 0, 2, n]))
            .find(|o| l.slot(*o) != l.slot(ip))
            .unwrap();
        assert!(l.allow(other, t0), "per-source buckets");
        assert!(l.allow(ip, t0 + secs(1)));
        assert!(!l.allow(ip, t0 + secs(1)));
    }

    #[test]
    fn rate_limiter_groups_ipv6_by_slash_64() {
        let l = RateLimiter::new(1.0);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(l.slot(ip("2001:db8:1:2::1")), l.slot(ip("2001:db8:1:2:ffff::9")));
        let others = (3..200).map(|n| ip(&format!("2001:db8:1:{n:x}::1")));
        assert!(others.into_iter().any(|o| l.slot(o) != l.slot(ip("2001:db8:1:2::1"))));
    }

    #[test]
    fn session_table_counts_pending_through_every_transition() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(idx(1), pending("192.0.2.1:1", "192.0.2.2:2", t0));
        t.insert(idx(2), pending("192.0.2.1:1", "192.0.2.2:2", t0));
        t.insert(idx(3), open("192.0.2.1:1", "192.0.2.2:2", t0));
        assert_eq!(t.pending(), 2);
        t.insert(idx(1), pending("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1)));
        assert_eq!(t.pending(), 2, "replacing a pending entry");
        assert!(!t.insert(idx(1), pending("192.0.2.3:3", "192.0.2.4:4", t0)), "refused");
        assert_eq!(t.pending(), 2);
        t.open(idx(2), t0);
        t.open(idx(2), t0);
        assert_eq!(t.pending(), 1, "opened once");
        assert_eq!(t.expire(t0 + secs(30)), 1);
        assert_eq!(t.pending(), 0, "expired");
        t.insert(idx(4), pending("192.0.2.1:1", "192.0.2.2:2", t0));
        assert_eq!(t.retain(|s| s.state == SessionState::Open), 1);
        assert_eq!(t.pending(), 0, "removed by retain");
    }

    #[test]
    fn session_table_gives_memory_back_after_a_flood() {
        let t0 = Instant::now();
        let mut t = table();
        for i in 0..100_000 {
            t.insert(idx(i), pending("192.0.2.1:1", "192.0.2.2:2", t0));
        }
        let peak = t.map.capacity();
        t.insert(idx(1 << 31), open("192.0.2.1:1", "192.0.2.2:2", t0 + secs(5)));
        assert_eq!(t.expire(t0 + secs(11)), 100_000);
        assert!(t.map.capacity() < peak / 50, "{} of {peak}", t.map.capacity());
        assert_eq!((t.len(), t.pending()), (1, 0));
    }
}
