use std::fmt;
use std::ops::AddAssign;

use super::{DropReason, Verdict};

/// Datagram counters, logged periodically and at shutdown.
#[derive(Debug, Default, Clone)]
pub struct Metrics {
    pub rx: u64,
    pub forwarded: u64,
    /// Datagrams taken by registration tunnels.
    pub tunnel_rx: u64,
    /// Datagrams the registration tunnels sent: handshake responses, keepalives, ping replies.
    pub tunnel_tx: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    /// Pending sessions evicted by newer forwarded initiations to the same
    /// configured peer; a steady rise means a flood aimed at that peer.
    pub pending_evicted: u64,
    rejects: [u64; DropReason::COUNT],
}

impl Metrics {
    /// How many datagrams were dropped for `r`.
    pub fn rejected(&self, r: DropReason) -> u64 {
        self.rejects[r as usize]
    }

    /// Count one received datagram and its outcome.
    pub(super) fn record(&mut self, verdict: Verdict) {
        self.rx += 1;
        match verdict {
            Verdict::Forward(_) => self.forwarded += 1,
            Verdict::DeliveredLocally => self.tunnel_rx += 1,
            Verdict::Drop(r) => self.rejects[r as usize] += 1,
        }
    }
}

/// Merge counters kept apart, such as each plane's. Destructured, so a new
/// counter cannot be left out.
impl AddAssign<&Metrics> for Metrics {
    fn add_assign(&mut self, other: &Metrics) {
        let Metrics {
            rx,
            forwarded,
            tunnel_rx,
            tunnel_tx,
            rx_errors,
            tx_errors,
            pending_evicted,
            rejects,
        } = other;
        self.rx += rx;
        self.forwarded += forwarded;
        self.tunnel_rx += tunnel_rx;
        self.tunnel_tx += tunnel_tx;
        self.rx_errors += rx_errors;
        self.tx_errors += tx_errors;
        self.pending_evicted += pending_evicted;
        for (mine, theirs) in self.rejects.iter_mut().zip(rejects) {
            *mine += theirs;
        }
    }
}

impl fmt::Display for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rx={} forwarded={} tunnel_rx={} tunnel_tx={} rx_errors={} tx_errors={} \
             pending_evicted={}",
            self.rx,
            self.forwarded,
            self.tunnel_rx,
            self.tunnel_tx,
            self.rx_errors,
            self.tx_errors,
            self.pending_evicted
        )?;
        for r in DropReason::ALL.iter().filter(|r| self.rejected(**r) > 0) {
            write!(f, " reject.{r}={}", self.rejected(*r))?;
        }
        Ok(())
    }
}
