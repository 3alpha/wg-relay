use std::fmt;
use std::ops::AddAssign;

use super::{DropReason, Verdict};
use crate::message::MessageType;

mod control;
pub use control::{ControlMetrics, TunnelError};

/// Datagram counters, logged periodically and at shutdown and exported to
/// Prometheus. Each forwarding thread keeps its own for what its data plane
/// decides, and the control plane its own; nothing here is shared between threads.
#[derive(Debug, Default, Clone)]
pub struct Metrics {
    pub rx: u64,
    pub rx_bytes: u64,
    pub forwarded: u64,
    pub forwarded_bytes: u64,
    /// Datagrams taken by registration tunnels.
    pub tunnel_rx: u64,
    pub tunnel_rx_bytes: u64,
    /// Datagrams the registration tunnels sent: handshake responses, keepalives, ping replies.
    pub tunnel_tx: u64,
    pub tunnel_tx_bytes: u64,
    pub dropped_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    /// Pending sessions evicted by newer forwarded initiations to the same
    /// configured peer; a steady rise means a flood aimed at that peer.
    pub pending_evicted: u64,
    rejects: [u64; DropReason::COUNT],
    /// Received datagrams that parsed as a message, by `MessageType::index`.
    messages_rx: [u64; MessageType::ALL.len()],
    /// Forwarded messages, by `MessageType::index`.
    messages_forwarded: [u64; MessageType::ALL.len()],
}

impl Metrics {
    /// How many datagrams were dropped for `r`.
    pub fn rejected(&self, r: DropReason) -> u64 {
        self.rejects[r as usize]
    }

    /// How many received datagrams parsed as a message of type `t`.
    pub fn messages_received(&self, t: MessageType) -> u64 {
        self.messages_rx[t.index()]
    }

    /// How many messages of type `t` were forwarded.
    pub fn messages_forwarded(&self, t: MessageType) -> u64 {
        self.messages_forwarded[t.index()]
    }

    /// Count one received datagram and its outcome.
    pub(super) fn record(&mut self, verdict: Verdict, datagram: &[u8]) {
        let len = datagram.len() as u64;
        self.rx += 1;
        self.rx_bytes += len;
        // Every verdict but a drop before parsing follows a successful parse,
        // which checked the type byte, so it names the message's type.
        let parsed = match verdict {
            Verdict::Drop(r) => r.after_parse(),
            Verdict::Forward(_) | Verdict::DeliveredLocally => true,
        };
        let kind = MessageType::of(datagram).filter(|_| parsed).map(MessageType::index);
        if let Some(i) = kind {
            self.messages_rx[i] += 1;
        }
        match verdict {
            Verdict::Forward(_) => {
                self.forwarded += 1;
                self.forwarded_bytes += len;
                if let Some(i) = kind {
                    self.messages_forwarded[i] += 1;
                }
            }
            Verdict::DeliveredLocally => {
                self.tunnel_rx += 1;
                self.tunnel_rx_bytes += len;
            }
            Verdict::Drop(r) => {
                self.rejects[r as usize] += 1;
                self.dropped_bytes += len;
            }
        }
    }
}

/// Add each counter of `theirs` to the same one of `mine`.
fn add_each(mine: &mut [u64], theirs: &[u64]) {
    for (m, t) in mine.iter_mut().zip(theirs) {
        *m += t;
    }
}

/// Merge counters kept apart, such as each plane's. Destructured, so a new
/// counter cannot be left out.
impl AddAssign<&Metrics> for Metrics {
    fn add_assign(&mut self, other: &Metrics) {
        let Metrics {
            rx,
            rx_bytes,
            forwarded,
            forwarded_bytes,
            tunnel_rx,
            tunnel_rx_bytes,
            tunnel_tx,
            tunnel_tx_bytes,
            dropped_bytes,
            rx_errors,
            tx_errors,
            pending_evicted,
            rejects,
            messages_rx,
            messages_forwarded,
        } = other;
        self.rx += rx;
        self.rx_bytes += rx_bytes;
        self.forwarded += forwarded;
        self.forwarded_bytes += forwarded_bytes;
        self.tunnel_rx += tunnel_rx;
        self.tunnel_rx_bytes += tunnel_rx_bytes;
        self.tunnel_tx += tunnel_tx;
        self.tunnel_tx_bytes += tunnel_tx_bytes;
        self.dropped_bytes += dropped_bytes;
        self.rx_errors += rx_errors;
        self.tx_errors += tx_errors;
        self.pending_evicted += pending_evicted;
        add_each(&mut self.rejects, rejects);
        add_each(&mut self.messages_rx, messages_rx);
        add_each(&mut self.messages_forwarded, messages_forwarded);
    }
}

impl fmt::Display for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rx={} rx_bytes={} forwarded={} forwarded_bytes={} tunnel_rx={} tunnel_tx={} \
             rx_errors={} tx_errors={} pending_evicted={}",
            self.rx,
            self.rx_bytes,
            self.forwarded,
            self.forwarded_bytes,
            self.tunnel_rx,
            self.tunnel_tx,
            self.rx_errors,
            self.tx_errors,
            self.pending_evicted,
        )?;
        for r in DropReason::ALL.iter().filter(|r| self.rejected(**r) > 0) {
            write!(f, " reject.{r}={}", self.rejected(*r))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn counts_bytes_per_outcome_and_types_only_for_parsed_datagrams() {
        let dst = SocketAddr::from(([192, 0, 2, 1], 1));
        let mut m = Metrics::default();
        m.record(Verdict::Forward(dst), &[4; 40]);
        m.record(Verdict::DeliveredLocally, &[1; 148]);
        m.record(Verdict::Drop(DropReason::UnknownIndex), &[4; 32]);
        m.record(Verdict::Drop(DropReason::Malformed), &[3; 10]);
        m.record(Verdict::Drop(DropReason::InvalidSource), &[4; 32]);
        assert_eq!((m.rx, m.rx_bytes), (5, 262));
        assert_eq!((m.forwarded, m.forwarded_bytes), (1, 40));
        assert_eq!((m.tunnel_rx, m.tunnel_rx_bytes), (1, 148));
        assert_eq!(m.dropped_bytes, 74);
        let received = MessageType::ALL.map(|t| m.messages_received(t));
        assert_eq!(received, [1, 0, 0, 2], "malformed and invalid sources have no type");
        let forwarded = MessageType::ALL.map(|t| m.messages_forwarded(t));
        assert_eq!(forwarded, [0, 0, 0, 1]);
        let mut sum = m.clone();
        sum += &m;
        assert_eq!((sum.rx, sum.messages_received(MessageType::TransportData)), (10, 4));
    }
}
