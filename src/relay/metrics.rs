use std::fmt;

use super::{Reason, Verdict};

/// Datagram counters, logged periodically and at shutdown.
#[derive(Debug, Default, Clone)]
pub struct Metrics {
    pub rx: u64,
    pub forwarded: u64,
    pub tunnel_rx: u64,
    pub tunnel_tx: u64,
    pub send_errors: u64,
    pub idx_collisions: u64,
    rejects: [u64; Reason::COUNT],
}

impl Metrics {
    pub fn rejected(&self, r: Reason) -> u64 {
        self.rejects[r as usize]
    }

    /// Count one received datagram and its outcome.
    pub(super) fn record(&mut self, verdict: Verdict) {
        self.rx += 1;
        match verdict {
            Verdict::Forward(_) => self.forwarded += 1,
            Verdict::Consumed => self.tunnel_rx += 1,
            Verdict::Drop(r) => self.rejects[r as usize] += 1,
        }
    }
}

impl fmt::Display for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rx={} forwarded={} tunnel_rx={} tunnel_tx={} send_errors={} idx_collisions={}",
            self.rx,
            self.forwarded,
            self.tunnel_rx,
            self.tunnel_tx,
            self.send_errors,
            self.idx_collisions
        )?;
        for r in Reason::ALL.iter().filter(|r| self.rejected(**r) > 0) {
            write!(f, " reject.{r}={}", self.rejected(*r))?;
        }
        Ok(())
    }
}
