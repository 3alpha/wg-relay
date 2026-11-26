//! One forwarding thread: it receives a batch, decides each datagram, sends
//! the forwarded ones in GSO runs, offers the relay a timer tick every
//! `TICK_INTERVAL`, and after either sends whatever the control plane queued.

use std::io;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use quinn_udp::Transmit;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{debug, info};
use wg_relay::relay::{Metrics, Relay, TICK_INTERVAL};

use crate::udp::runs::{self, Datagram, Limits, Piece, Plan, Run};
use crate::udp::{Bound, MAX_GSO_BYTES, RecvBatch, Socket};

/// Run one forwarding thread on a runtime of its own until `stop` changes,
/// keeping `counters` at its relay handle's local metrics as of its last wake-up.
pub(super) fn run(
    socket: Bound,
    relay: Relay,
    mut stop: watch::Receiver<bool>,
    counters: &Mutex<Metrics>,
) -> io::Result<()> {
    super::runtime()?.block_on(async {
        let mut worker = Worker { sock: socket.into_async()?, relay };
        let mut batch = Batch::default();
        let mut ticks = tokio::time::interval(TICK_INTERVAL);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            // In this order, so a busy socket can neither delay stopping nor starve the ticks.
            tokio::select! {
                biased;
                _ = stop.changed() => return Ok(()),
                // The time the tick was due, not when it ran: one thread's ticks are
                // then exactly `TICK_INTERVAL` apart, and the relay never skips one.
                due = ticks.tick() => worker.relay.tick(due.into_std()),
                readable = worker.sock.readable() => match readable {
                    Ok(()) => batch.forward(&mut worker).await,
                    Err(e) => worker.recv_failed(&e),
                },
            }
            worker.send_tx_queue().await;
            counters
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone_from(worker.relay.local_metrics());
        }
    })
}

/// One thread's socket and its handle on the relay, which decides the
/// socket's datagrams and counts its failures.
struct Worker {
    sock: Socket,
    relay: Relay,
}

impl Worker {
    /// Send what the registration tunnels queued, whichever thread's datagram
    /// or tick made them: every socket has the same address.
    async fn send_tx_queue(&mut self) {
        for (dst, datagram) in self.relay.drain_tx_queue() {
            let t = Transmit {
                destination: dst,
                ecn: None,
                contents: &datagram,
                segment_size: None,
                src_ip: None,
            };
            self.send(&t).await;
        }
    }

    /// Send one run, keeping its ECN bits. If a GSO send fails (some paths
    /// reject GSO; after `EIO` or `EINVAL` `quinn-udp` stops using it), the
    /// datagrams are sent again one by one, so only those the network itself
    /// refuses are lost.
    async fn send_run(&mut self, contents: &[u8], run: &Run) {
        let segment_size = run.gso_segment_bytes();
        let t =
            Transmit { destination: run.dst, ecn: run.ecn, contents, segment_size, src_ip: None };
        let Some(size) = segment_size else { return self.send(&t).await };
        let gso = self.sock.gso_segments() > 1;
        let Err(e) = self.sock.send(&t).await else { return };
        debug!(dst = %run.dst, segments = run.segments, error = %e, "GSO send failed, resending one by one");
        if gso && self.sock.gso_segments() <= 1 {
            info!(
                "UDP segmentation offload turned off after a failed send, sending one datagram at a time"
            );
        }
        for datagram in contents.chunks(size.max(1)) {
            self.send(&Transmit { contents: datagram, segment_size: None, ..t.clone() }).await;
        }
    }

    /// Send; failures are counted and logged at debug, never fatal, since a
    /// peer can make them happen at packet rate (e.g. an unreachable destination).
    async fn send(&mut self, t: &Transmit<'_>) {
        if let Err(e) = self.sock.send(t).await {
            self.relay.record_tx_error();
            debug!(dst = %t.destination, error = %e, "send failed");
        }
    }

    /// Count a failed receive and log it at debug: whether ICMP errors surface
    /// here depends on the platform and socket options, so a remote host may drive it.
    fn recv_failed(&mut self, e: &io::Error) {
        self.relay.record_rx_error();
        debug!(error = %e, "recv failed");
    }
}

/// One batch's buffers and scratch space, reused so that nothing is allocated per packet.
#[derive(Default)]
struct Batch {
    rx: RecvBatch,
    /// Every datagram of the batch with its verdict, in arrival order.
    datagrams: Vec<Datagram>,
    plan: Plan,
    /// Where a run that spans receive buffers is copied together.
    joined: Vec<u8>,
}

impl Batch {
    /// Receive one batch on `worker` and forward what it holds. Doing one batch
    /// per wake-up and charging the runtime's cooperative budget per buffer
    /// makes the thread yield regularly under load.
    async fn forward(&mut self, worker: &mut Worker) {
        let Batch { rx, datagrams, plan, joined } = self;
        match worker.sock.try_recv(rx) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
            Err(e) => return worker.recv_failed(&e),
        }
        let now = Instant::now();
        datagrams.clear();
        for (buf, (meta, data)) in rx.received().enumerate() {
            for seg in runs::segments(data.len(), meta.stride) {
                let datagram = data.get(seg).unwrap_or_default();
                let verdict = worker.relay.handle(meta.addr, datagram, now);
                datagrams.push(Datagram { buf, len: datagram.len(), verdict, ecn: meta.ecn });
            }
            tokio::task::consume_budget().await;
        }
        let limits = Limits { max_segments: worker.sock.gso_segments(), max_bytes: MAX_GSO_BYTES };
        plan.make(datagrams, limits);
        for run in &plan.runs {
            let pieces = plan.pieces.get(run.pieces.clone()).unwrap_or_default();
            worker.send_run(gather(rx, pieces, joined), run).await;
        }
    }
}

/// The bytes of a run: straight from its receive buffer if it lies in one,
/// else copied together into `joined`.
fn gather<'a>(rx: &'a RecvBatch, pieces: &[Piece], joined: &'a mut Vec<u8>) -> &'a [u8] {
    let bytes = |p: &Piece| rx.data(p.buf).get(p.bytes.clone()).unwrap_or_default();
    if let [one] = pieces {
        return bytes(one);
    }
    joined.clear();
    for p in pieces {
        joined.extend_from_slice(bytes(p));
    }
    joined
}
