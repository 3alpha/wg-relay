//! CLI arguments and the main thread, which supervises the forwarding threads:
//! it starts them, handles signals, logs stats, and stops and joins them.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use tokio::runtime::Runtime;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{debug, error, info, warn};
use wg_relay::config::Config;
use wg_relay::error::{AppError, Report};
use wg_relay::relay::Relay;

use crate::udp::{self, Bound};

mod forwarding;
mod workers;

use workers::Workers;

/// How often the main thread checks that every forwarding thread still runs.
const CHECK_INTERVAL: Duration = Duration::from_millis(250);
/// How often the main thread logs every counter.
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
    let config = load(&cli.config)?;
    if cli.check_config {
        println!("config OK: {}", cli.config.display());
        print!("{}", config.summary());
        return Ok(());
    }
    serve(config, cli.config)
}

/// Read and validate the config file at `path`.
fn load(path: &Path) -> Result<Config, AppError> {
    Config::load(path).map_err(|source| AppError::Config { path: path.to_owned(), source })
}

/// Bind one socket per forwarding thread, start the threads, supervise them
/// until a signal or a thread's end, then stop and join them.
fn serve(config: Config, path: PathBuf) -> Result<(), AppError> {
    let (listen, sockets) = udp::bind_group(config.listen, workers::count(&config))?;
    let (gro, gso) = (sockets.iter().all(Bound::gro), sockets.iter().all(Bound::gso));
    let rt = runtime().map_err(|source| AppError::Runtime { source })?;
    let relay = Relay::new(&config);
    let workers = Workers::start(sockets, &relay)?;
    info!(
        %listen,
        pubkey = %relay.public_key(),
        tunnel_ip = %config.tunnel_ip,
        handshake_rate = %config.handshake_rate,
        peers = relay.peer_count(),
        workers = workers.len(),
        gro,
        gso,
        "wg-relay started"
    );
    debug!(?config, "effective config");
    let supervised = rt.block_on(supervise(&relay, &workers, &config, &path));
    let (metrics, joined) = workers.stop();
    info!(metrics = %metrics, "shutting down");
    joined.and(supervised)
}

/// A runtime for one thread: the main thread's signals and timers, or a
/// forwarding thread's socket and ticks.
fn runtime() -> io::Result<Runtime> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()
}

/// Log stats and apply reloads until SIGINT or SIGTERM, or until a
/// forwarding thread ends.
async fn supervise(
    relay: &Relay,
    workers: &Workers,
    config: &Config,
    path: &Path,
) -> Result<(), AppError> {
    let on = |kind, name| signal(kind).map_err(|source| AppError::Signal { signal: name, source });
    let mut hup = on(SignalKind::hangup(), "SIGHUP")?;
    let mut int = on(SignalKind::interrupt(), "SIGINT")?;
    let mut term = on(SignalKind::terminate(), "SIGTERM")?;
    let mut checks = tokio::time::interval(CHECK_INTERVAL);
    let mut stats = tokio::time::interval(STATS_INTERVAL);
    loop {
        tokio::select! {
            _ = checks.tick() => {
                if let Some(index) = workers.exited() {
                    return Err(AppError::WorkerExited { index });
                }
            }
            _ = stats.tick() => {
                info!(metrics = %workers.metrics(), sessions = relay.session_count(), "stats");
            }
            _ = hup.recv() => reload(relay, config, path),
            _ = int.recv() => return Ok(()),
            _ = term.recv() => return Ok(()),
        }
    }
}

/// Reload the config file, keeping the current one if it is invalid.
fn reload(relay: &Relay, config: &Config, path: &Path) {
    let new = match load(path) {
        Ok(new) => new,
        Err(e) => return error!(error = %Report(&e), "reload failed, keeping current config"),
    };
    if new.listen != config.listen {
        warn!("changing listen requires a restart");
    }
    if new.workers != config.workers {
        warn!("changing workers requires a restart");
    }
    relay.reload(&new);
}
