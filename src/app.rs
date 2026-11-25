//! CLI arguments and the socket loop that drives the relay.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Parser;
use quinn_udp::Transmit;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{debug, error, info, warn};
use wg_relay::config::Config;
use wg_relay::error::{AppError, Report};
use wg_relay::relay::Relay;

use crate::udp::runs::{self, Datagram, Limits, Plan, Run};
use crate::udp::{MAX_GSO_BYTES, RecvBatch, Socket};

const TIMER_INTERVAL: Duration = Duration::from_millis(250);
const STATS_INTERVAL: Duration = Duration::from_secs(60);

/// Pubkey-routed WireGuard relay for peers behind NAT.
#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    /// Config file; SIGHUP reloads it.
    #[arg(short, long, env = "WG_RELAY_CONFIG", default_value = "relay.toml")]
    pub config: PathBuf,
    /// Validate the config, print a summary and exit.
    #[arg(long, env = "WG_RELAY_CHECK_CONFIG")]
    pub check_config: bool,
}

/// Load the config, then either print its summary or run the relay.
pub fn run(cli: Cli) -> Result<(), AppError> {
    let cfg = load(&cli.config)?;
    if cli.check_config {
        println!("config OK: {}", cli.config.display());
        print!("{}", cfg.summary());
        return Ok(());
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(AppError::Runtime)?;
    rt.block_on(serve(cfg, cli.config))
}

fn load(path: &Path) -> Result<Config, AppError> {
    Config::load(path).map_err(|source| AppError::Config { path: path.to_owned(), source })
}

async fn serve(cfg: Config, path: PathBuf) -> Result<(), AppError> {
    let sock = Socket::bind(cfg.listen).await?;
    let on = |kind, name| signal(kind).map_err(|source| AppError::Signal { signal: name, source });
    let mut term = on(SignalKind::terminate(), "SIGTERM")?;
    let mut int = on(SignalKind::interrupt(), "SIGINT")?;
    let mut hup = on(SignalKind::hangup(), "SIGHUP")?;
    let mut relay = Relay::new(&cfg);
    info!(
        listen = %cfg.listen,
        pubkey = %relay.public_key(),
        tunnel_ip = %cfg.tunnel_ip,
        handshake_rate = %cfg.handshake_rate,
        peers = relay.peer_count(),
        gro = sock.gro_segments() > 1,
        gso = sock.gso_segments() > 1,
        "wg-relay started"
    );
    debug!(config = ?cfg, "effective config");

    let mut rx = RecvBatch::default();
    let mut work = Work::default();
    let mut gso = sock.gso_segments() > 1;
    let mut timers = tokio::time::interval(TIMER_INTERVAL);
    let mut stats = tokio::time::interval(STATS_INTERVAL);
    loop {
        tokio::select! {
            r = sock.readable() => match r {
                Ok(()) => forward_batch(&sock, &mut relay, &mut rx, &mut work).await,
                Err(e) => recv_failed(&mut relay, &e),
            },
            _ = timers.tick() => relay.tick(Instant::now()),
            _ = stats.tick() => {
                info!(metrics = %relay.metrics(), sessions = relay.session_count(), "stats");
            }
            _ = hup.recv() => match load(&path) {
                Ok(new) if new.listen != cfg.listen => {
                    warn!("changing listen requires a restart");
                    relay.reload(&new);
                }
                Ok(new) => relay.reload(&new),
                Err(e) => error!(error = %Report(&e), "reload failed, keeping current config"),
            },
            _ = int.recv() => break,
            _ = term.recv() => break,
        }
        for (dst, pkt) in relay.take_outbox() {
            let t = Transmit {
                destination: dst,
                ecn: None,
                contents: &pkt,
                segment_size: None,
                src_ip: None,
            };
            send(&sock, &mut relay, &t).await;
        }
        if gso && sock.gso_segments() <= 1 {
            gso = false;
            info!(
                "UDP segmentation offload turned off after a failed send, sending one datagram at a time"
            );
        }
    }
    info!(metrics = %relay.metrics(), "shutting down");
    Ok(())
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
