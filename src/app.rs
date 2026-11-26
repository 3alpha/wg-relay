//! CLI arguments, startup and shutdown. The main thread supervises the
//! forwarding threads (`supervisor`): it starts them, handles signals, logs
//! stats, serves metrics, and stops and joins them.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use tokio::runtime::Runtime;
use tracing::{debug, info};
use wg_relay::config::Config;
use wg_relay::error::AppError;
use wg_relay::relay::Relay;

use crate::udp::{self, Bound};

mod forwarding;
mod metrics;
mod supervisor;
mod workers;

use metrics::http::Listener;
use supervisor::Supervisor;
use workers::Workers;

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
    /// Print the [Peer] section configured peers add for the relay, and exit.
    #[arg(long, env = "WG_RELAY_PRINT_PEER", conflicts_with = "check_config")]
    pub print_peer: bool,
    /// Serve Prometheus metrics on this address, overriding metrics_listen in the config.
    #[arg(long, env = "WG_RELAY_METRICS_LISTEN", value_name = "ADDR")]
    pub metrics_listen: Option<SocketAddr>,
}

/// Where the config comes from: the file, and what the command line overrides in it.
struct ConfigSource {
    path: PathBuf,
    metrics_listen: Option<SocketAddr>,
}

impl ConfigSource {
    /// Read and validate the config file, then apply the overrides; at startup and on reload.
    fn load(&self) -> Result<Config, AppError> {
        let path = &self.path;
        let mut config =
            Config::load(path).map_err(|source| AppError::Config { path: path.clone(), source })?;
        config.metrics_listen = self.metrics_listen.or(config.metrics_listen);
        Ok(config)
    }
}

/// Load the config, then print its summary or the relay's `[Peer]` section, or run the relay.
pub fn run(cli: Cli) -> Result<(), AppError> {
    let source = ConfigSource { path: cli.config, metrics_listen: cli.metrics_listen };
    let config = source.load()?;
    if cli.check_config {
        println!("config OK: {}", source.path.display());
        print!("{}", config.summary());
        return Ok(());
    }
    if cli.print_peer {
        print!("{}", config.relay_peer());
        return Ok(());
    }
    serve(config, &source)
}

/// Bind one socket per forwarding thread and the metrics listener, start the
/// threads, supervise them until a signal or a thread's end, then stop and join them.
fn serve(config: Config, source: &ConfigSource) -> Result<(), AppError> {
    let (listen, sockets) = udp::bind_group(config.listen, workers::count(&config))?;
    let metrics = config.metrics_listen.map(Listener::bind).transpose()?;
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
    if let Some(m) = &metrics {
        info!(addr = %m.addr, "serving Prometheus metrics at /metrics");
    }
    debug!(?config, "effective config");
    let supervisor = Supervisor::new(&relay, &workers, &config, source, listen);
    supervisor.print_relay_peer();
    let supervised = rt.block_on(supervisor.run(metrics));
    let (metrics, joined) = workers.stop();
    info!(metrics = %metrics, "shutting down");
    joined.and(supervised)
}

/// A runtime for one thread: the main thread's signals, timers and metrics
/// server, or a forwarding thread's socket and ticks.
fn runtime() -> io::Result<Runtime> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()
}
