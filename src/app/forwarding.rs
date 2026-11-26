//! One forwarding thread: its socket loop receives a batch, decides each
//! datagram, sends the forwarded ones in GSO runs, then whatever the control
//! half queued, and offers the relay a timer tick every `TICK_INTERVAL`.

use std::io;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use quinn_udp::Transmit;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{debug, info};
use wg_relay::relay::{Metrics, Relay, TICK_INTERVAL};

use crate::udp::runs::{self, Datagram, Limits, Plan, Run};
use crate::udp::{Bound, MAX_GSO_BYTES, RecvBatch, Socket};

/// Run one forwarding thread on a runtime of its own until `stop` changes,
/// keeping `counters` at its relay handle's counters as of its last batch.
pub(super) fn run(
    socket: Bound,
    relay: Relay,
    stop: watch::Receiver<bool>,
    counters: &Mutex<Metrics>,
) -> io::Result<()> {
    super::runtime()?.block_on(async {
        SocketLoop::new(socket.register()?, relay).run(stop, counters).await;
        Ok(())
    })
}

/// One thread's socket, its handle on the relay, and its reusable buffers.
struct SocketLoop {
    sock: Socket,
    relay: Relay,
    rx: RecvBatch,
    work: Work,
    gso: bool,
}

impl SocketLoop {
    fn new(sock: Socket, relay: Relay) -> Self {
        let gso = sock.gso_segments() > 1;
        SocketLoop { sock, relay, rx: RecvBatch::default(), work: Work::default(), gso }
    }

    /// Forward batches and offer timer ticks until `stop` changes.
    async fn run(mut self, mut stop: watch::Receiver<bool>, counters: &Mutex<Metrics>) {
        let mut ticks = tokio::time::interval(TICK_INTERVAL);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            // In this order, so a busy socket can neither delay stopping nor starve the ticks.
            tokio::select! {
                biased;
                _ = stop.changed() => return,
                // The time the tick was due, not when it ran: one thread's ticks are
                // then exactly `TICK_INTERVAL` apart, and the relay never skips one.
                due = ticks.tick() => self.on_tick(due.into_std()).await,
                readable = self.sock.readable() => self.on_readable(readable).await,
            }
            counters
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone_from(self.relay.counters());
        }
    }

    /// Act on a timer tick: run the relay's timers, then send what they queued.
    async fn on_tick(&mut self, due: Instant) {
        self.relay.tick(due);
        self.send_outbox().await;
    }

    /// Act on the socket turning readable: forward one batch, then send what
    /// the registration tunnels queued, whichever thread's datagram made them.
    async fn on_readable(&mut self, readable: io::Result<()>) {
        match readable {
            Ok(()) => {
                forward_batch(&self.sock, &mut self.relay, &mut self.rx, &mut self.work).await
            }
            Err(e) => recv_failed(&mut self.relay, &e),
        }
        self.send_outbox().await;
    }

    /// Send the datagrams the registration tunnels want to send.
    async fn send_outbox(&mut self) {
        for (dst, pkt) in self.relay.take_outbox() {
            let t = Transmit {
                destination: dst,
                ecn: None,
                contents: &pkt,
                segment_size: None,
                src_ip: None,
            };
            send(&self.sock, &mut self.relay, &t).await;
        }
        if self.gso && self.sock.gso_segments() <= 1 {
            self.gso = false;
            info!(
                "UDP segmentation offload turned off after a failed send, sending one datagram at a time"
            );
        }
    }
}

/// Scratch space for one batch, reused so that nothing is allocated per packet.
#[derive(Default)]
struct Work {
    /// Every datagram of the batch with its verdict, in arrival order.
    datagrams: Vec<Datagram>,
    plan: Plan,
    /// Where a run that spans receive buffers is copied together.
    joined: Vec<u8>,
}

/// Receive one batch and forward what it holds. Doing one batch per wake-up
/// and charging the runtime's cooperative budget per buffer makes the loop
/// yield regularly under load, so a flood cannot starve timers and signals.
async fn forward_batch(sock: &Socket, relay: &mut Relay, rx: &mut RecvBatch, work: &mut Work) {
    match sock.try_recv(rx) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
        Err(e) => return recv_failed(relay, &e),
    }
    let now = Instant::now();
    work.datagrams.clear();
    for (buf, (meta, data)) in rx.received().enumerate() {
        for seg in runs::segments(data.len(), meta.stride) {
            let pkt = data.get(seg).unwrap_or_default();
            let verdict = relay.handle(meta.addr, pkt, now);
            work.datagrams.push(Datagram { buf, len: pkt.len(), verdict, ecn: meta.ecn });
        }
        tokio::task::consume_budget().await;
    }
    let limits = Limits { max_segments: sock.gso_segments(), max_bytes: MAX_GSO_BYTES };
    work.plan.make(&work.datagrams, limits);
    for run in &work.plan.runs {
        let pieces = work.plan.pieces.get(run.pieces.clone()).unwrap_or_default();
        let contents = match pieces {
            [one] => rx.data(one.buf).get(one.bytes.clone()).unwrap_or_default(),
            _ => {
                work.joined.clear();
                for p in pieces {
                    work.joined
                        .extend_from_slice(rx.data(p.buf).get(p.bytes.clone()).unwrap_or_default());
                }
                &work.joined
            }
        };
        forward(sock, relay, contents, run).await;
    }
}

/// Forward one run, keeping its ECN bits. If a GSO send fails (some paths
/// reject GSO; after `EIO` or `EINVAL` `quinn-udp` stops using it), the
/// datagrams are sent again one by one, so only those the network itself
/// refuses are lost.
async fn forward(sock: &Socket, relay: &mut Relay, contents: &[u8], run: &Run) {
    let segment_size = run.gso_segment_bytes();
    let t = Transmit { destination: run.dst, ecn: run.ecn, contents, segment_size, src_ip: None };
    let Some(size) = segment_size else { return send(sock, relay, &t).await };
    let Err(e) = sock.send(&t).await else { return };
    debug!(dst = %run.dst, segments = run.segments, error = %e, "GSO send failed, resending one by one");
    for pkt in contents.chunks(size.max(1)) {
        send(sock, relay, &Transmit { contents: pkt, segment_size: None, ..t.clone() }).await;
    }
}

/// Send; failures are counted and logged at debug, never fatal, since a peer
/// can make them happen at packet rate (e.g. an unreachable destination).
async fn send(sock: &Socket, relay: &mut Relay, t: &Transmit<'_>) {
    if let Err(e) = sock.send(t).await {
        relay.record_send_error();
        debug!(dst = %t.destination, error = %e, "send failed");
    }
}

/// Counted and at debug: whether ICMP errors surface here depends on the
/// platform and socket options, so a remote host may drive it.
fn recv_failed(relay: &mut Relay, e: &io::Error) {
    relay.record_recv_error();
    debug!(error = %e, "recv failed");
}
