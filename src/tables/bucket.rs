use std::time::Instant;

/// Tokens earned at a steady rate, up to a cap.
#[derive(Debug, Clone, Copy)]
pub(super) struct TokenBucket {
    pub(super) tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub(super) fn full(burst: f64, now: Instant) -> Self {
        TokenBucket { tokens: burst, last: now }
    }

    /// Add the tokens earned since the last refill.
    pub(super) fn refill(&mut self, now: Instant, per_sec: f64, burst: f64) {
        let earned = now.saturating_duration_since(self.last).as_secs_f64() * per_sec;
        self.tokens = (self.tokens + earned).min(burst);
        self.last = now;
    }
}
