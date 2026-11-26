use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::time::Instant;

use super::bucket::TokenBucket;

/// Rate-limit buckets, a power of two. Fixed, so spoofed sources cannot grow memory.
const RATE_LIMIT_BUCKETS: usize = 1 << 16;

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
    buckets: Vec<Option<TokenBucket>>,
}

impl RateLimiter {
    /// The burst is two seconds' worth of tokens (at least one).
    pub fn new(per_sec: f64) -> Self {
        RateLimiter {
            burst: (per_sec * 2.0).max(1.0),
            per_sec,
            hasher: RandomState::new(),
            buckets: vec![None; RATE_LIMIT_BUCKETS],
        }
    }

    pub fn set_rate(&mut self, per_sec: f64) {
        (self.per_sec, self.burst) = (per_sec, (per_sec * 2.0).max(1.0));
    }

    fn bucket(&self, ip: IpAddr) -> usize {
        // A dual-stack socket reports IPv4 sources as `::ffff:a.b.c.d`, whose /64 is
        // all zeros: unmapped, each IPv4 source keeps its own bucket.
        let source = match ip.to_canonical() {
            IpAddr::V4(a) => (4, u64::from(a.to_bits())),
            IpAddr::V6(a) => (6, (a.to_bits() >> 64) as u64),
        };
        self.hasher.hash_one(source) as usize % RATE_LIMIT_BUCKETS
    }

    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        let (per_sec, burst) = (self.per_sec, self.burst);
        let i = self.bucket(ip);
        let b = self.buckets[i].get_or_insert(TokenBucket::full(burst, now));
        b.refill(now, per_sec, burst);
        let ok = b.tokens >= 1.0;
        if ok {
            b.tokens -= 1.0;
        }
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
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
            .find(|o| l.bucket(*o) != l.bucket(ip))
            .unwrap();
        assert!(l.allow(other, t0), "per-source buckets");
        assert!(l.allow(ip, t0 + secs(1)));
        assert!(!l.allow(ip, t0 + secs(1)));
    }

    #[test]
    fn rate_limiter_groups_ipv6_by_slash_64() {
        let l = RateLimiter::new(1.0);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(l.bucket(ip("2001:db8:1:2::1")), l.bucket(ip("2001:db8:1:2:ffff::9")));
        let others = (3..200).map(|n| ip(&format!("2001:db8:1:{n:x}::1")));
        assert!(others.into_iter().any(|o| l.bucket(o) != l.bucket(ip("2001:db8:1:2::1"))));
    }

    #[test]
    fn rate_limiter_keys_v4_mapped_sources_as_ipv4() {
        let l = RateLimiter::new(1.0);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(l.bucket(ip("::ffff:192.0.2.1")), l.bucket(ip("192.0.2.1")));
        let others = (2..=255).map(|n| ip(&format!("::ffff:192.0.2.{n}")));
        assert!(others.into_iter().any(|o| l.bucket(o) != l.bucket(ip("::ffff:192.0.2.1"))));
    }
}
