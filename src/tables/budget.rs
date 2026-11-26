use std::time::Instant;

use super::bucket::TokenBucket;

/// Budget for CPU work spent on unauthenticated handshakes, so a flood of
/// them cannot starve forwarding. Work is charged once it is done, so the
/// budget can go into debt by one handshake; the burst is one second's worth.
pub struct WorkBudget {
    per_sec: f64,
    bucket: Option<TokenBucket>,
}

impl WorkBudget {
    pub fn new(per_sec: f64) -> Self {
        WorkBudget { per_sec, bucket: None }
    }

    /// Is there budget left for more work?
    pub fn available(&mut self, now: Instant) -> bool {
        let b = self.bucket.get_or_insert(TokenBucket::full(self.per_sec, now));
        b.refill(now, self.per_sec, self.per_sec);
        b.tokens > 0.0
    }

    /// Work the budget would allow at `now`; negative while in debt.
    pub fn remaining(&self, now: Instant) -> f64 {
        self.bucket.map_or(self.per_sec, |mut b| {
            b.refill(now, self.per_sec, self.per_sec);
            b.tokens
        })
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
    use std::time::Duration;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
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
        assert_eq!(b.remaining(t0 + secs(200)), 10.0);
        b.spend(10);
        assert!(!b.available(t0 + secs(200)), "burst is one second's worth");
        assert_eq!(b.remaining(t0 + secs(200)), 0.0);
    }
}
