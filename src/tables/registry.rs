use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::live;
use crate::key::PeerKey;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::REGISTRY_TTL;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn key(n: u8) -> PeerKey {
        [n; 32].into()
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
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
}
