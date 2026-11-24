//! Soft-state tables: registry, session table, per-IP rate limiter.

use crate::key::PeerKey;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

pub const REGISTRY_TTL: Duration = Duration::from_secs(180);
pub const SESSION_TTL: Duration = Duration::from_secs(200);

fn live(at: Instant, now: Instant, ttl: Duration) -> bool {
    now.saturating_duration_since(at) < ttl
}

/// key -> (address, last authenticated packet), plus the reverse map. Only
/// written after a packet authenticates on that key's relay tunnel.
pub struct Registry<K> {
    ttl: Duration,
    by_key: HashMap<K, (SocketAddr, Instant)>,
    by_addr: HashMap<SocketAddr, K>,
}

impl<K: Copy + Eq + Hash> Registry<K> {
    pub fn new(ttl: Duration) -> Self {
        Registry { ttl, by_key: HashMap::new(), by_addr: HashMap::new() }
    }

    /// Record that `k` authenticated from `addr`. Returns `Some(previous)` if
    /// the address changed (new registration or roaming).
    pub fn update(&mut self, k: K, addr: SocketAddr, now: Instant) -> Option<Option<SocketAddr>> {
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

    pub fn addr(&self, k: &K, now: Instant) -> Option<SocketAddr> {
        self.by_key.get(k).filter(|(_, t)| live(*t, now, self.ttl)).map(|(a, _)| *a)
    }

    pub fn key_at(&self, addr: SocketAddr, now: Instant) -> Option<K> {
        let k = *self.by_addr.get(&addr)?;
        self.addr(&k, now).map(|_| k)
    }

    pub fn remove(&mut self, k: &K) -> bool {
        let Some((a, _)) = self.by_key.remove(k) else { return false };
        self.by_addr.remove(&a);
        true
    }

    pub fn keys(&self) -> Vec<K> {
        self.by_key.keys().copied().collect()
    }

    /// Drop stale entries, returning the expired keys.
    pub fn expire(&mut self, now: Instant) -> Vec<K> {
        let gone: Vec<K> =
            self.by_key.iter().filter(|(_, (_, t))| !live(*t, now, self.ttl)).map(|(k, _)| *k).collect();
        for k in &gone {
            self.remove(k);
        }
        gone
    }
}

/// Forwarding state for one session index (the receiver_idx of later packets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    /// Where packets carrying this index are sent.
    pub dest: SocketAddr,
    /// The only address allowed to send packets carrying this index.
    pub expected_src: SocketAddr,
    /// Set once the handshake response has been accepted.
    pub open: bool,
    pub last: Instant,
    /// The server end, and the client end once known; used to revoke on reload.
    pub server: PeerKey,
    pub client: Option<PeerKey>,
}

pub struct SessionTable {
    ttl: Duration,
    map: HashMap<u32, Session>,
}

impl SessionTable {
    pub fn new(ttl: Duration) -> Self {
        SessionTable { ttl, map: HashMap::new() }
    }

    /// Insert, overwriting any existing entry (newest wins). Returns true on a
    /// collision with a live entry for a different address pair.
    pub fn insert(&mut self, idx: u32, s: Session) -> bool {
        let collided = matches!(self.map.insert(idx, s), Some(old)
            if (old.dest, old.expected_src) != (s.dest, s.expected_src) && live(old.last, s.last, self.ttl));
        if collided {
            tracing::warn!(idx, dest = %s.dest, "session index collision, keeping newest");
        }
        collided
    }

    pub fn get(&self, idx: u32, now: Instant) -> Option<Session> {
        self.map.get(&idx).filter(|s| live(s.last, now, self.ttl)).copied()
    }

    /// Refresh `last`; optionally mark open and record the client.
    pub fn touch(&mut self, idx: u32, now: Instant, open: bool, client: Option<PeerKey>) {
        if let Some(s) = self.map.get_mut(&idx) {
            s.last = now;
            s.open |= open;
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
        self.retain(|s| live(s.last, now, ttl))
    }

    /// Is any index with these upper 24 bits in use?
    pub fn has_prefix(&self, prefix: u32) -> bool {
        self.map.keys().any(|i| i >> 8 == prefix)
    }

    pub fn clients(&self) -> HashSet<PeerKey> {
        self.map.values().filter_map(|s| s.client).collect()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
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
