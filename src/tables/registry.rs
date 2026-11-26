use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::live;
use crate::key::PublicKey;

/// Where each configured peer is: key -> (endpoint, last authenticated datagram),
/// plus the reverse map. Written only after a datagram authenticates on that
/// peer's registration tunnel.
pub struct Registry {
    timeout: Duration,
    by_key: HashMap<PublicKey, (SocketAddr, Instant)>,
    by_addr: HashMap<SocketAddr, PublicKey>,
}

impl Registry {
    pub fn new(timeout: Duration) -> Self {
        Registry { timeout, by_key: HashMap::new(), by_addr: HashMap::new() }
    }

    /// Record that `k` authenticated from `addr`. Returns `Some(previous)` if
    /// the address changed (new registration or roaming).
    pub fn update(
        &mut self,
        k: PublicKey,
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

    /// The endpoint `k` is registered at, unless its registration has timed out.
    pub fn endpoint(&self, k: &PublicKey, now: Instant) -> Option<SocketAddr> {
        self.by_key.get(k).filter(|(_, t)| live(*t, now, self.timeout)).map(|(a, _)| *a)
    }

    /// When `k` last authenticated, if it has a registration, live or not yet expired.
    pub fn last_authenticated(&self, k: &PublicKey) -> Option<Instant> {
        self.by_key.get(k).map(|(_, t)| *t)
    }

    /// Is `addr` the current endpoint of some configured peer?
    pub fn is_registered(&self, addr: SocketAddr, now: Instant) -> bool {
        self.by_addr.get(&addr).is_some_and(|k| self.endpoint(k, now) == Some(addr))
    }

    /// Keep only the registrations `keep` accepts, given each key and when it
    /// last authenticated; returns the keys removed.
    pub fn retain(&mut self, mut keep: impl FnMut(&PublicKey, Instant) -> bool) -> Vec<PublicKey> {
        let mut gone = Vec::new();
        self.by_key.retain(|k, (addr, seen)| {
            let kept = keep(k, *seen);
            if !kept {
                gone.push((*k, *addr));
            }
            kept
        });
        for (_, addr) in &gone {
            self.by_addr.remove(addr);
        }
        gone.into_iter().map(|(k, _)| k).collect()
    }

    /// Drop expired registrations; returns the keys removed.
    pub fn expire(&mut self, now: Instant) -> Vec<PublicKey> {
        let timeout = self.timeout;
        self.retain(|_, seen| live(seen, now, timeout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::REGISTRATION_TIMEOUT;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn key(n: u8) -> PublicKey {
        [n; 32].into()
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn registry_tracks_roaming_conflicts_and_expiry() {
        let t0 = Instant::now();
        let (a1, a2) = (addr("192.0.2.10:1000"), addr("192.0.2.10:1001"));
        let mut r = Registry::new(REGISTRATION_TIMEOUT);
        assert_eq!(r.update(key(0), a1, t0), Some(None));
        assert_eq!(r.update(key(0), a1, t0), None, "unchanged address");
        assert_eq!(r.update(key(0), a2, t0), Some(Some(a1)), "roamed");
        assert_eq!(r.endpoint(&key(0), t0), Some(a2));
        assert_eq!(r.update(key(1), a2, t0), Some(None));
        assert_eq!(
            (r.endpoint(&key(0), t0), r.endpoint(&key(1), t0)),
            (None, Some(a2)),
            "newest claimant owns address"
        );
        assert_eq!(r.endpoint(&key(1), t0 + secs(179)), Some(a2));
        assert_eq!(r.endpoint(&key(1), t0 + secs(180)), None);
        assert_eq!(r.expire(t0 + secs(181)), vec![key(1)]);
        r.update(key(3), a1, t0);
        assert!(r.is_registered(a1, t0 + secs(179)));
        assert!(!r.is_registered(a1, t0 + secs(180)), "expired");
        assert!(!r.is_registered(a2, t0), "address of an expired registration");
        assert_eq!(r.retain(|k, _| *k != key(3)), vec![key(3)]);
        assert!(!r.is_registered(a1, t0));
        assert_eq!(r.retain(|k, _| *k != key(3)), vec![]);
        assert_eq!(r.endpoint(&key(3), t0), None);
    }
}
