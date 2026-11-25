//! Soft-state tables: registry, session table, per-source rate limiter, work budgets.

use crate::key::PeerKey;
use crate::packet::{IdxPrefix, SessionIdx};
use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, RandomState};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

pub const REGISTRY_TTL: Duration = Duration::from_secs(180);
/// Lifetime of an open entry from the handshake that opened it, however much
/// traffic it carries: WireGuard never uses a key older than 180 s
/// (`REJECT_AFTER_TIME`), and the 20 s on top cover the round trip.
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

    /// Is `addr` where some listed peer is currently registered?
    pub fn is_registered(&self, addr: SocketAddr, now: Instant) -> bool {
        self.by_addr.get(&addr).is_some_and(|k| self.addr(k, now) == Some(addr))
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
    /// When the entry entered its current state; its lifetime runs from here.
    pub since: Instant,
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
        Session { dest, expected_src, state: SessionState::Pending, since: now, peer }
    }

    /// The responder's index after its response was accepted.
    pub fn open(dest: SocketAddr, expected_src: SocketAddr, peer: PeerKey, now: Instant) -> Self {
        Session { state: SessionState::Open, ..Self::pending(dest, expected_src, peer, now) }
    }
}

/// Fixed lifetimes per session state, counted from `Session::since`.
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
        live(s.since, now, ttl)
    }
}

/// Size limits of the session table.
#[derive(Debug, Clone, Copy)]
pub struct SessionLimits {
    /// Most entries one listed peer may have pending; beyond it, its oldest goes.
    pub pending_per_peer: usize,
    /// Most entries, pending or open, routed to one listed peer.
    pub per_peer: usize,
    /// Most entries in the whole table.
    pub total: usize,
}

/// Why the session table refused an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A live entry of another address pair, or a live open entry, holds the index.
    IndexInUse,
    /// The entry's listed peer is at `SessionLimits::per_peer`.
    PeerQuota,
    /// The table is at `SessionLimits::total`.
    Full,
}

pub struct SessionTable {
    ttls: Ttls,
    limits: SessionLimits,
    map: HashMap<SessionIdx, Session>,
    /// Entries in the `Pending` state, live or not yet swept.
    pending: usize,
    /// Each listed peer's pending indexes, oldest first, so a flood aimed at one
    /// peer evicts its own entries instead of crowding out other peers.
    pending_by_peer: HashMap<PeerKey, VecDeque<SessionIdx>>,
    /// Entries of any state, live or not yet swept, per listed peer.
    count_by_peer: HashMap<PeerKey, usize>,
}

/// Count one entry fewer for `peer`, dropping its counter at zero.
fn uncount(counts: &mut HashMap<PeerKey, usize>, peer: &PeerKey) {
    if let Some(n) = counts.get_mut(peer) {
        *n -= 1;
        if *n == 0 {
            counts.remove(peer);
        }
    }
}

impl SessionTable {
    pub fn new(open_ttl: Duration, pending_ttl: Duration, limits: SessionLimits) -> Self {
        SessionTable {
            ttls: Ttls { open: open_ttl, pending: pending_ttl },
            limits,
            map: HashMap::new(),
            pending: 0,
            pending_by_peer: HashMap::new(),
            count_by_peer: HashMap::new(),
        }
    }

    /// Insert unless a live entry for a different address pair owns the index,
    /// so nobody can take over an index someone else is using, or a live open
    /// entry does, so re-sending its initiation cannot reset or extend it. A
    /// pending entry over its peer's pending quota evicts that peer's oldest
    /// pending entry, which is returned.
    pub fn insert(&mut self, idx: SessionIdx, s: Session) -> Result<Option<SessionIdx>, Refusal> {
        let old = self.map.get(&idx).copied();
        if let Some(old) = old
            && self.ttls.live(&old, s.since)
            && (old.state == SessionState::Open
                || (old.dest, old.expected_src) != (s.dest, s.expected_src))
        {
            return Err(Refusal::IndexInUse);
        }
        let peer_grows = old.is_none_or(|o| o.peer != s.peer);
        if peer_grows && self.peer_at_quota(&s.peer) {
            return Err(Refusal::PeerQuota);
        }
        if old.is_none() && self.is_full() {
            return Err(Refusal::Full);
        }
        self.map.insert(idx, s);
        if let Some(old) = old {
            self.forget_pending(idx, &old);
            uncount(&mut self.count_by_peer, &old.peer);
        }
        *self.count_by_peer.entry(s.peer).or_default() += 1;
        let mut evicted = None;
        if s.state == SessionState::Pending {
            self.pending += 1;
            let queue = self.pending_by_peer.entry(s.peer).or_default();
            queue.push_back(idx);
            while queue.len() > self.limits.pending_per_peer {
                let Some(oldest) = queue.pop_front() else { break };
                if let Some(gone) = self.map.remove(&oldest) {
                    self.pending -= 1;
                    uncount(&mut self.count_by_peer, &gone.peer);
                    evicted = Some(oldest);
                }
            }
        }
        Ok(evicted)
    }

    /// Account for `old`, just replaced or opened at `idx`, leaving the pending state.
    fn forget_pending(&mut self, idx: SessionIdx, old: &Session) {
        if old.state != SessionState::Pending {
            return;
        }
        self.pending -= 1;
        if let Some(queue) = self.pending_by_peer.get_mut(&old.peer) {
            if let Some(i) = queue.iter().position(|q| *q == idx) {
                queue.remove(i);
            }
            if queue.is_empty() {
                self.pending_by_peer.remove(&old.peer);
            }
        }
    }

    pub fn get(&self, idx: SessionIdx, now: Instant) -> Option<Session> {
        self.map.get(&idx).filter(|s| self.ttls.live(s, now)).copied()
    }

    /// Mark a pending index open once the response is accepted; its open
    /// lifetime starts now.
    pub fn open(&mut self, idx: SessionIdx, now: Instant) {
        let Some(s) = self.map.get_mut(&idx) else { return };
        let old = *s;
        s.since = now;
        s.state = SessionState::Open;
        self.forget_pending(idx, &old);
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
        let counts = &mut self.count_by_peer;
        self.map.retain(|_, s| {
            let kept = keep(s);
            if !kept {
                pending_gone += usize::from(s.state == SessionState::Pending);
                uncount(counts, &s.peer);
            }
            kept
        });
        self.pending -= pending_gone;
        if pending_gone > 0 {
            let map = &self.map;
            self.pending_by_peer.retain(|peer, queue| {
                queue.retain(|i| {
                    map.get(i).is_some_and(|s| s.state == SessionState::Pending && s.peer == *peer)
                });
                !queue.is_empty()
            });
            shrink_if_sparse(&mut self.pending_by_peer);
        }
        shrink_if_sparse(&mut self.count_by_peer);
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

    /// Would a new entry for `peer` exceed its quota?
    pub fn peer_at_quota(&self, peer: &PeerKey) -> bool {
        self.count_by_peer.get(peer).is_some_and(|n| *n >= self.limits.per_peer)
    }

    /// Would a new index exceed the table's cap?
    pub fn is_full(&self) -> bool {
        self.map.len() >= self.limits.total
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
        // A dual-stack socket reports IPv4 sources as `::ffff:a.b.c.d`, whose /64 is
        // all zeros: unmapped, each IPv4 source keeps its own bucket.
        let source = match ip.to_canonical() {
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

/// Budget for CPU work spent on unauthenticated handshakes, so a flood of
/// them cannot starve forwarding. Work is charged once it is done, so the
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

    const UNLIMITED: SessionLimits =
        SessionLimits { pending_per_peer: usize::MAX, per_peer: usize::MAX, total: usize::MAX };

    fn table() -> SessionTable {
        SessionTable::new(SESSION_TTL, PENDING_TTL, UNLIMITED)
    }

    /// Do the per-peer counts match the entries, with no zero counters left?
    fn counts_exact(t: &SessionTable) -> bool {
        let mut want: HashMap<PeerKey, usize> = HashMap::new();
        for s in t.map.values() {
            *want.entry(s.peer).or_default() += 1;
        }
        want == t.count_by_peer
    }

    /// The pending indexes of peer `n`, oldest first.
    fn queue(t: &SessionTable, n: u8) -> Vec<SessionIdx> {
        t.pending_by_peer.get(&key(n)).map(|q| q.iter().copied().collect()).unwrap_or_default()
    }

    #[test]
    fn open_session_expires_a_fixed_time_after_it_opened() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(idx(42), open("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.insert(idx(43), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.open(idx(43), t0 + secs(5));
        assert!(t.get(idx(42), t0 + secs(199)).is_some());
        assert_eq!(t.get(idx(42), t0 + secs(200)), None);
        assert!(t.get(idx(43), t0 + secs(204)).is_some(), "counted from opening");
        assert_eq!(t.expire(t0 + secs(200)), 1);
        assert_eq!(t.expire(t0 + secs(205)), 1);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn pending_session_expires_sooner_than_open() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(idx(1), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.insert(idx(2), open("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        assert!(t.get(idx(1), t0 + secs(9)).is_some());
        assert_eq!(t.get(idx(1), t0 + secs(10)), None);
        assert_eq!(t.expire(t0 + secs(10)), 1);
        assert!(t.get(idx(2), t0 + secs(10)).is_some());
    }

    #[test]
    fn open_marks_session_open_and_starts_its_lifetime() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(idx(42), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.open(idx(42), t0 + secs(1));
        assert_eq!(
            t.get(idx(42), t0 + secs(1)),
            Some(open("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1)))
        );
    }

    #[test]
    fn insert_refuses_live_open_index_or_another_pairs_but_replaces_own_pending_or_stale() {
        let t0 = Instant::now();
        let mut t = table();
        assert_eq!(t.insert(idx(6), pending("192.0.2.1:1", "192.0.2.2:2", t0)), Ok(None));
        let resent = pending("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1));
        assert_eq!(t.insert(idx(6), resent), Ok(None), "re-sent initiation");
        assert_eq!(t.get(idx(6), t0 + secs(10)), Some(resent));

        assert_eq!(t.insert(idx(7), open("192.0.2.1:1", "192.0.2.2:2", t0)), Ok(None));
        // Neither the same pair nor another may reset or take over a live open entry.
        let same = [
            open("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1)),
            pending("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1)),
        ];
        for s in same {
            assert_eq!(t.insert(idx(7), s), Err(Refusal::IndexInUse), "same pair");
        }
        let other = pending("192.0.2.3:3", "192.0.2.4:4", t0 + secs(2));
        assert_eq!(t.insert(idx(7), other), Err(Refusal::IndexInUse));
        assert_eq!(t.get(idx(7), t0 + secs(2)), Some(open("192.0.2.1:1", "192.0.2.2:2", t0)));
        assert_eq!(t.get(idx(7), t0 + SESSION_TTL), None, "still expires on time");
        let late = pending("192.0.2.5:5", "192.0.2.6:6", t0 + SESSION_TTL);
        assert_eq!(t.insert(idx(7), late), Ok(None), "stale");
        assert_eq!(t.get(idx(7), t0 + SESSION_TTL).map(|s| s.dest), Some(addr("192.0.2.5:5")));
        assert_eq!(t.len(), 2);
        assert!(counts_exact(&t));
    }

    #[test]
    fn session_migrate_rewrites_both_directions() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(idx(0x00ab_cd01), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.insert(idx(0x0011_2201), pending("192.0.2.2:2", "192.0.2.1:1", t0)).unwrap();
        t.migrate(addr("192.0.2.1:1"), addr("192.0.2.9:9"));
        assert_eq!(t.get(idx(0x00ab_cd01), t0).map(|s| s.dest), Some(addr("192.0.2.9:9")));
        assert_eq!(t.get(idx(0x0011_2201), t0).map(|s| s.expected_src), Some(addr("192.0.2.9:9")));
        assert_eq!(t.retain(|s| s.dest.port() == 9), 1);
    }

    #[test]
    fn has_prefix_matches_upper_24_bits_only() {
        let mut t = table();
        t.insert(idx(0x00ab_cd01), pending("192.0.2.1:1", "192.0.2.2:2", Instant::now())).unwrap();
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
        assert!(r.is_registered(a1, t0 + secs(179)));
        assert!(!r.is_registered(a1, t0 + secs(180)), "expired");
        assert!(!r.is_registered(a2, t0), "address of an expired registration");
        assert!(r.remove(&key(3)));
        assert!(!r.is_registered(a1, t0));
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
    fn rate_limiter_keys_v4_mapped_sources_as_ipv4() {
        let l = RateLimiter::new(1.0);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(l.slot(ip("::ffff:192.0.2.1")), l.slot(ip("192.0.2.1")));
        let others = (2..=255).map(|n| ip(&format!("::ffff:192.0.2.{n}")));
        assert!(others.into_iter().any(|o| l.slot(o) != l.slot(ip("::ffff:192.0.2.1"))));
    }

    #[test]
    fn pending_over_quota_evicts_that_peers_oldest_only() {
        let t0 = Instant::now();
        let limits = SessionLimits { pending_per_peer: 2, ..UNLIMITED };
        let mut t = SessionTable::new(SESSION_TTL, PENDING_TTL, limits);
        let for_peer = |n: u8, port: u16| {
            Session::pending(addr(&format!("192.0.2.1:{port}")), addr("192.0.2.9:9"), key(n), t0)
        };
        assert_eq!(t.insert(idx(1), for_peer(1, 1)), Ok(None));
        assert_eq!(t.insert(idx(2), for_peer(1, 2)), Ok(None));
        assert_eq!(t.insert(idx(10), for_peer(2, 10)), Ok(None));
        assert_eq!(t.insert(idx(11), for_peer(2, 11)), Ok(None));
        assert_eq!(t.insert(idx(3), for_peer(1, 3)), Ok(Some(idx(1))));
        assert_eq!(t.get(idx(1), t0), None, "peer 1's oldest went");
        assert_eq!((queue(&t, 1), queue(&t, 2)), (vec![idx(2), idx(3)], vec![idx(10), idx(11)]));
        assert_eq!((t.pending(), t.len()), (4, 4));

        // An opened entry no longer counts, so the next one evicts nothing.
        t.open(idx(2), t0);
        assert_eq!(t.insert(idx(4), for_peer(1, 4)), Ok(None));
        assert!(t.get(idx(2), t0).is_some() && t.get(idx(3), t0).is_some());
        assert_eq!((queue(&t, 1), t.pending()), (vec![idx(3), idx(4)], 4));

        // Re-sending a pending index moves it to the back instead of duplicating it.
        assert_eq!(t.insert(idx(3), for_peer(1, 3)), Ok(None));
        assert_eq!(t.insert(idx(5), for_peer(1, 5)), Ok(Some(idx(4))));
        assert_eq!(t.get(idx(4), t0), None);
        assert_eq!((queue(&t, 1), t.pending()), (vec![idx(3), idx(5)], 4));

        // Opened, expired and removed entries leave the queues, and empty queues go.
        let opened = Session::open(addr("192.0.2.1:5"), addr("192.0.2.9:9"), key(1), t0);
        assert_eq!(t.insert(idx(5), opened), Ok(None));
        assert!(counts_exact(&t));
        assert_eq!((queue(&t, 1), t.pending()), (vec![idx(3)], 3));
        assert_eq!(t.retain(|s| s.peer != key(2)), 2);
        assert_eq!((queue(&t, 2), t.pending()), (vec![], 1));
        assert_eq!(t.expire(t0 + PENDING_TTL), 1);
        assert_eq!((t.pending(), t.pending_by_peer.len()), (0, 0));
        assert_eq!(t.len(), 2, "the open entries");
        assert!(counts_exact(&t));
    }

    #[test]
    fn session_table_counts_pending_through_every_transition() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(idx(1), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.insert(idx(2), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.insert(idx(3), open("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        assert_eq!(t.pending(), 2);
        t.insert(idx(1), pending("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1))).unwrap();
        assert_eq!(t.pending(), 2, "replacing a pending entry");
        let other = pending("192.0.2.3:3", "192.0.2.4:4", t0);
        assert_eq!(t.insert(idx(1), other), Err(Refusal::IndexInUse), "refused");
        assert_eq!(t.pending(), 2);
        t.open(idx(2), t0);
        t.open(idx(2), t0);
        assert_eq!(t.pending(), 1, "opened once");
        assert_eq!(t.expire(t0 + secs(30)), 1);
        assert_eq!(t.pending(), 0, "expired");
        t.insert(idx(4), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        assert_eq!(t.retain(|s| s.state == SessionState::Open), 1);
        assert_eq!(t.pending(), 0, "removed by retain");
    }

    #[test]
    fn session_table_gives_memory_back_after_a_flood() {
        let t0 = Instant::now();
        let mut t = table();
        for i in 0..100_000 {
            t.insert(idx(i), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        }
        let peak = t.map.capacity();
        t.insert(idx(1 << 31), open("192.0.2.1:1", "192.0.2.2:2", t0 + secs(5))).unwrap();
        assert_eq!(t.expire(t0 + secs(11)), 100_000);
        assert!(t.map.capacity() < peak / 50, "{} of {peak}", t.map.capacity());
        assert_eq!((t.len(), t.pending()), (1, 0));
    }

    #[test]
    fn peer_quota_counts_pending_and_open_and_spares_other_peers() {
        let t0 = Instant::now();
        let limits = SessionLimits { pending_per_peer: 2, per_peer: 3, total: usize::MAX };
        let mut t = SessionTable::new(SESSION_TTL, PENDING_TTL, limits);
        let s = |n: u8, port: u16, state: SessionState| Session {
            state,
            ..Session::pending(addr(&format!("192.0.2.1:{port}")), addr("192.0.2.9:9"), key(n), t0)
        };
        let (p, o) = (SessionState::Pending, SessionState::Open);
        t.insert(idx(1), s(1, 1, o)).unwrap();
        t.insert(idx(2), s(1, 2, p)).unwrap();
        t.insert(idx(3), s(1, 3, p)).unwrap();
        assert!(t.peer_at_quota(&key(1)) && !t.peer_at_quota(&key(2)));
        // At quota, a new index is refused, even one that would only evict.
        assert_eq!(t.insert(idx(4), s(1, 4, p)), Err(Refusal::PeerQuota));
        assert_eq!(t.insert(idx(4), s(1, 4, o)), Err(Refusal::PeerQuota));
        assert_eq!(t.get(idx(2), t0).map(|s| s.state), Some(p), "nothing evicted");
        // Replacing one of its own entries does not grow it, and another peer is unaffected.
        assert_eq!(t.insert(idx(3), s(1, 3, p)), Ok(None));
        assert_eq!(t.insert(idx(10), s(2, 10, o)), Ok(None));
        // A stale entry of peer 1 taken over by peer 2 moves the count.
        assert_eq!(t.insert(idx(1), s(2, 1, p)), Err(Refusal::IndexInUse), "live");
        let late = Session { since: t0 + SESSION_TTL, ..s(2, 1, p) };
        assert_eq!(t.insert(idx(1), late), Ok(None), "stale");
        assert!(counts_exact(&t));
        assert!(!t.peer_at_quota(&key(1)) && t.count_by_peer[&key(2)] == 2);
        // Expiry and retain free quota.
        assert_eq!(t.expire(t0 + PENDING_TTL), 2);
        assert!(counts_exact(&t));
        assert_eq!(t.retain(|s| s.peer != key(2)), 2);
        assert!(counts_exact(&t) && t.count_by_peer.is_empty() && t.len() == 0);
    }

    #[test]
    fn total_cap_refuses_new_indexes_but_not_replacements() {
        let t0 = Instant::now();
        let limits = SessionLimits { pending_per_peer: 1, per_peer: usize::MAX, total: 3 };
        let mut t = SessionTable::new(SESSION_TTL, PENDING_TTL, limits);
        let for_peer = |n: u8, port: u16| {
            Session::pending(addr(&format!("192.0.2.1:{port}")), addr("192.0.2.9:9"), key(n), t0)
        };
        for n in 1..=3 {
            t.insert(idx(u32::from(n)), for_peer(n, 1)).unwrap();
        }
        assert!(t.is_full());
        assert_eq!(t.insert(idx(4), for_peer(4, 4)), Err(Refusal::Full));
        assert_eq!(t.insert(idx(1), for_peer(1, 1)), Ok(None), "replacement");
        // A peer at its pending quota still cannot add an index to a full table.
        assert_eq!(t.insert(idx(5), for_peer(1, 5)), Err(Refusal::Full));
        assert_eq!(t.get(idx(1), t0).map(|s| s.dest), Some(addr("192.0.2.1:1")));
        assert_eq!(t.expire(t0 + PENDING_TTL), 3);
        assert_eq!(t.insert(idx(4), for_peer(4, 4)), Ok(None), "room after expiry");
        assert!(counts_exact(&t));
    }

    #[test]
    fn pending_eviction_keeps_peer_counts_exact() {
        let t0 = Instant::now();
        let limits = SessionLimits { pending_per_peer: 2, per_peer: 4, total: usize::MAX };
        let mut t = SessionTable::new(SESSION_TTL, PENDING_TTL, limits);
        let mut evicted = 0;
        for i in 0..100 {
            let s = Session::pending(addr("192.0.2.1:1"), addr("192.0.2.9:9"), key(1), t0);
            evicted += usize::from(t.insert(idx(i), s).unwrap().is_some());
        }
        assert_eq!((evicted, t.len(), t.count_by_peer[&key(1)]), (98, 2, 2));
        assert!(!t.peer_at_quota(&key(1)), "evictions free quota");
        assert!(counts_exact(&t));
    }
}
