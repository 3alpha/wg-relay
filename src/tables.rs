//! Soft-state tables: registry, session table, per-IP rate limiter.

use crate::key::PeerKey;
use crate::packet::{IdxPrefix, SessionIdx};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

pub const REGISTRY_TTL: Duration = Duration::from_secs(180);
pub const SESSION_TTL: Duration = Duration::from_secs(200);

fn live(at: Instant, now: Instant, ttl: Duration) -> bool {
    now.saturating_duration_since(at) < ttl
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
    pub fn update(&mut self, k: PeerKey, addr: SocketAddr, now: Instant) -> Option<Option<SocketAddr>> {
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

    pub fn key_at(&self, addr: SocketAddr, now: Instant) -> Option<PeerKey> {
        let k = *self.by_addr.get(&addr)?;
        self.addr(&k, now).map(|_| k)
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
        let gone: Vec<PeerKey> =
            self.by_key.iter().filter(|(_, (_, t))| !live(*t, now, self.ttl)).map(|(k, _)| *k).collect();
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
    /// The server end, and the client end once known; used to revoke on reload.
    pub server: PeerKey,
    pub client: Option<PeerKey>,
}

impl Session {
    /// The initiator's index after its initiation was forwarded.
    pub fn pending(
        dest: SocketAddr,
        expected_src: SocketAddr,
        server: PeerKey,
        client: Option<PeerKey>,
        now: Instant,
    ) -> Self {
        Session { dest, expected_src, state: SessionState::Pending, last_seen: now, server, client }
    }

    /// The responder's index after its response was accepted.
    pub fn open(
        dest: SocketAddr,
        expected_src: SocketAddr,
        server: PeerKey,
        client: Option<PeerKey>,
        now: Instant,
    ) -> Self {
        Session { state: SessionState::Open, ..Self::pending(dest, expected_src, server, client, now) }
    }
}

pub struct SessionTable {
    ttl: Duration,
    map: HashMap<SessionIdx, Session>,
}

impl SessionTable {
    pub fn new(ttl: Duration) -> Self {
        SessionTable { ttl, map: HashMap::new() }
    }

    /// Insert, overwriting any existing entry (newest wins). Returns true on a
    /// collision with a live entry for a different address pair.
    pub fn insert(&mut self, idx: SessionIdx, s: Session) -> bool {
        let collided = matches!(self.map.insert(idx, s), Some(old)
            if (old.dest, old.expected_src) != (s.dest, s.expected_src) && live(old.last_seen, s.last_seen, self.ttl));
        if collided {
            tracing::warn!(%idx, dest = %s.dest, "session index collision, keeping newest");
        }
        collided
    }

    pub fn get(&self, idx: SessionIdx, now: Instant) -> Option<Session> {
        self.map.get(&idx).filter(|s| live(s.last_seen, now, self.ttl)).copied()
    }

    /// Refresh `last_seen` after forwarding a packet on this index.
    pub fn touch(&mut self, idx: SessionIdx, now: Instant) {
        if let Some(s) = self.map.get_mut(&idx) {
            s.last_seen = now;
        }
    }

    /// Mark a pending index open once the response is accepted, recording the
    /// client if the response identified it.
    pub fn open(&mut self, idx: SessionIdx, now: Instant, client: Option<PeerKey>) {
        if let Some(s) = self.map.get_mut(&idx) {
            s.last_seen = now;
            s.state = SessionState::Open;
            s.client = s.client.or(client);
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
        let before = self.map.len();
        self.map.retain(|_, s| keep(s));
        before - self.map.len()
    }

    pub fn expire(&mut self, now: Instant) -> usize {
        let ttl = self.ttl;
        self.retain(|s| live(s.last_seen, now, ttl))
    }

    /// Is any index with these upper 24 bits in use?
    pub fn has_prefix(&self, prefix: IdxPrefix) -> bool {
        self.map.keys().any(|i| i.prefix() == prefix)
    }

    pub fn clients(&self) -> HashSet<PeerKey> {
        self.map.values().filter_map(|s| s.client).collect()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
}

/// Token bucket per source IP, for handshake initiations.
pub struct RateLimiter {
    burst: f64,
    per_sec: f64,
    buckets: HashMap<IpAddr, (f64, Instant)>,
}

impl RateLimiter {
    /// The burst is two seconds' worth of tokens (at least one).
    pub fn new(per_sec: f64) -> Self {
        RateLimiter { burst: (per_sec * 2.0).max(1.0), per_sec, buckets: HashMap::new() }
    }

    pub fn set_rate(&mut self, per_sec: f64) {
        (self.per_sec, self.burst) = (per_sec, (per_sec * 2.0).max(1.0));
    }

    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        let (tokens, last) = self.buckets.entry(ip).or_insert((self.burst, now));
        let refill = now.saturating_duration_since(*last).as_secs_f64() * self.per_sec;
        *tokens = (*tokens + refill).min(self.burst);
        *last = now;
        let ok = *tokens >= 1.0;
        if ok {
            *tokens -= 1.0;
        }
        ok
    }

    /// Forget sources whose bucket would be full again by now.
    pub fn prune(&mut self, now: Instant) {
        let full_after = self.burst / self.per_sec;
        self.buckets.retain(|_, (_, last)| now.saturating_duration_since(*last).as_secs_f64() < full_after);
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
        Session::pending(addr(dest), addr(src), key(1), None, t)
    }

    #[test]
    fn session_expires_after_ttl_unless_touched() {
        let t0 = Instant::now();
        let mut t = SessionTable::new(SESSION_TTL);
        t.insert(idx(42), pending("192.0.2.1:1", "192.0.2.2:2", t0));
        assert!(t.get(idx(42), t0 + secs(199)).is_some());
        assert_eq!(t.get(idx(42), t0 + secs(200)), None);
        t.touch(idx(42), t0 + secs(150));
        assert!(t.get(idx(42), t0 + secs(300)).is_some());
        assert_eq!(t.expire(t0 + secs(349)), 0);
        assert_eq!(t.expire(t0 + secs(351)), 1);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn open_marks_session_open_and_records_client() {
        let t0 = Instant::now();
        let mut t = SessionTable::new(SESSION_TTL);
        t.insert(idx(42), pending("192.0.2.1:1", "192.0.2.2:2", t0));
        t.open(idx(42), t0 + secs(1), Some(key(7)));
        let expected = Session {
            state: SessionState::Open,
            last_seen: t0 + secs(1),
            client: Some(key(7)),
            ..pending("192.0.2.1:1", "192.0.2.2:2", t0)
        };
        assert_eq!(t.get(idx(42), t0 + secs(1)), Some(expected));
        assert_eq!(t.clients(), HashSet::from([key(7)]));
    }

    #[test]
    fn session_collision_keeps_newest_and_ignores_same_pair_or_stale() {
        let t0 = Instant::now();
        let mut t = SessionTable::new(SESSION_TTL);
        assert!(!t.insert(idx(7), pending("192.0.2.1:1", "192.0.2.2:2", t0)));
        assert!(!t.insert(idx(7), pending("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1))), "same pair");
        assert!(t.insert(idx(7), pending("192.0.2.3:3", "192.0.2.4:4", t0 + secs(2))));
        assert_eq!(t.get(idx(7), t0 + secs(2)).map(|s| s.dest), Some(addr("192.0.2.3:3")));
        assert!(!t.insert(idx(7), pending("192.0.2.5:5", "192.0.2.6:6", t0 + secs(500))), "stale entry");
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn session_migrate_rewrites_both_directions() {
        let t0 = Instant::now();
        let mut t = SessionTable::new(SESSION_TTL);
        t.insert(idx(0x00ab_cd01), pending("192.0.2.1:1", "192.0.2.2:2", t0));
        t.insert(idx(0x0011_2201), pending("192.0.2.2:2", "192.0.2.1:1", t0));
        t.migrate(addr("192.0.2.1:1"), addr("192.0.2.9:9"));
        assert_eq!(t.get(idx(0x00ab_cd01), t0).map(|s| s.dest), Some(addr("192.0.2.9:9")));
        assert_eq!(t.get(idx(0x0011_2201), t0).map(|s| s.expected_src), Some(addr("192.0.2.9:9")));
        assert_eq!(t.retain(|s| s.dest.port() == 9), 1);
    }

    #[test]
    fn has_prefix_matches_upper_24_bits_only() {
        let mut t = SessionTable::new(SESSION_TTL);
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
        assert_eq!(r.key_at(a1, t0), Some(key(0)));
        assert_eq!(r.update(key(0), a2, t0), Some(Some(a1)), "roamed");
        assert_eq!(r.key_at(a1, t0), None);
        assert_eq!(r.update(key(1), a2, t0), Some(None));
        assert_eq!(
            (r.addr(&key(0), t0), r.key_at(a2, t0)),
            (None, Some(key(1))),
            "newest claimant owns address"
        );
        assert_eq!(r.addr(&key(1), t0 + secs(179)), Some(a2));
        assert_eq!(r.key_at(a2, t0 + secs(180)), None);
        assert_eq!(r.expire(t0 + secs(181)), vec![key(1)]);
        r.update(key(3), a1, t0);
        assert!(r.remove(&key(3)));
        assert!(!r.remove(&key(3)));
        assert_eq!(r.key_at(a1, t0), None);
    }

    #[test]
    fn rate_limiter_has_two_second_burst_per_source() {
        let t0 = Instant::now();
        let ip = "192.0.2.1".parse().unwrap();
        let mut l = RateLimiter::new(1.5);
        assert!((0..3).all(|_| l.allow(ip, t0)), "burst of 3");
        assert!(!l.allow(ip, t0));
        assert!(l.allow("192.0.2.2".parse().unwrap(), t0), "per-source buckets");
        assert!(l.allow(ip, t0 + secs(1)));
        assert!(!l.allow(ip, t0 + secs(1)));
    }
}
