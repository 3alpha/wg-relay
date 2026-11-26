//! CLI arguments and the threads that drive the relay: the main thread runs
//! the first socket's loop plus timers, stats and signals; the others run
//! the same loop on the other sockets.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Parser;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{debug, error, info, warn};
use wg_relay::config::Config;
use wg_relay::error::{AppError, Report};
use wg_relay::relay::Relay;

use crate::udp;

mod forwarding;
mod workers;

use forwarding::SocketLoop;
use workers::Workers;

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
    serve(cfg, cli.config)
}

fn load(path: &Path) -> Result<Config, AppError> {
    Config::load(path).map_err(|source| AppError::Config { path: path.to_owned(), source })
}

/// Why the main loop ended.
enum Stopped {
    /// SIGINT or SIGTERM.
    Signal,
    /// This forwarding thread ended though none was told to.
    WorkerExited(usize),
}

/// Bind one socket per forwarding thread, start the other threads, run the
/// main loop here, then stop and join them all.
fn serve(cfg: Config, path: PathBuf) -> Result<(), AppError> {
    let sockets = udp::bind_group(cfg.listen, workers::count(&cfg))?;
    let listen = sockets.first.local_addr().unwrap_or(cfg.listen);
    let (gro, gso) = (sockets.first.gro(), sockets.first.gso());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(AppError::Runtime)?;
    let sock = {
        let _runtime = rt.enter();
        sockets.first.register().map_err(main_failed)?
    };
    let relay = Relay::new(&cfg);
    let workers = Workers::start(sockets.others, &relay)?;
    info!(
        %listen,
        pubkey = %relay.public_key(),
        tunnel_ip = %cfg.tunnel_ip,
        handshake_rate = %cfg.handshake_rate,
        peers = relay.peer_count(),
        workers = 1 + workers.len(),
        gro,
        gso,
        "wg-relay started"
    );
    debug!(config = ?cfg, "effective config");

    let mut lp = SocketLoop::new(sock, relay);
    let stopped = rt.block_on(run_main(&mut lp, &workers, &cfg, &path));
    let (mut totals, joined) = workers.stop();
    totals += &lp.relay.metrics();
    info!(metrics = %totals, "shutting down");
    match stopped? {
        Stopped::Signal => joined,
        Stopped::WorkerExited(index) => joined.and(Err(AppError::WorkerExited { index })),
    }
}

/// The main thread's own socket could not join its runtime.
fn main_failed(source: std::io::Error) -> AppError {
    AppError::WorkerFailed { index: 0, source }
}

/// Run the first socket's loop, timers, stats, reload and signals until a
/// signal asks to stop or another forwarding thread ends.
async fn run_main(
    lp: &mut SocketLoop,
    workers: &Workers,
    cfg: &Config,
    path: &Path,
) -> Result<Stopped, AppError> {
    let on = |kind, name| signal(kind).map_err(|source| AppError::Signal { signal: name, source });
    let mut term = on(SignalKind::terminate(), "SIGTERM")?;
    let mut int = on(SignalKind::interrupt(), "SIGINT")?;
    let mut hup = on(SignalKind::hangup(), "SIGHUP")?;
    let mut timers = tokio::time::interval(TIMER_INTERVAL);
    let mut stats = tokio::time::interval(STATS_INTERVAL);
    loop {
        tokio::select! {
            r = lp.sock.readable() => {
                lp.on_readable(r).await;
                continue;
            }
            _ = timers.tick() => {
                lp.relay.tick(Instant::now());
                if let Some(index) = workers.exited() {
                    return Ok(Stopped::WorkerExited(index));
                }
            }
            _ = stats.tick() => {
                let mut all = workers.counters();
                all += &lp.relay.metrics();
                info!(metrics = %all, sessions = lp.relay.session_count(), "stats");
            }
            _ = hup.recv() => reload(&lp.relay, cfg, path),
            _ = int.recv() => return Ok(Stopped::Signal),
            _ = term.recv() => return Ok(Stopped::Signal),
        }
        lp.send_outbox().await;
    }
}

/// Reload the config file, keeping the current one if it is invalid.
fn reload(relay: &Relay, cfg: &Config, path: &Path) {
    let new = match load(path) {
        Ok(new) => new,
        Err(e) => return error!(error = %Report(&e), "reload failed, keeping current config"),
    };
    if new.listen != cfg.listen {
        warn!("changing listen requires a restart");
    }
    if new.workers != cfg.workers {
        warn!("changing workers requires a restart");
    }
    relay.reload(&new);
}
