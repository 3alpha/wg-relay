//! CLI arguments and the socket loop that drives the relay.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Parser;
use tokio::net::UdpSocket;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{debug, error, info, warn};
use wg_relay::config::Config;
use wg_relay::error::{AppError, Report};
use wg_relay::relay::{Relay, Verdict};

const MAX_DATAGRAM_BYTES: usize = 65536;
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
    let cfg =
        Config::load(path).map_err(|source| AppError::Config { path: path.to_owned(), source })?;
    for w in cfg.warnings() {
        warn!(warning = %w, "config warning");
    }
    Ok(cfg)
}

async fn serve(cfg: Config, path: PathBuf) -> Result<(), AppError> {
    let sock = UdpSocket::bind(cfg.listen)
        .await
        .map_err(|source| AppError::Bind { addr: cfg.listen, source })?;
    let on = |kind, name| signal(kind).map_err(|source| AppError::Signal { signal: name, source });
    let mut term = on(SignalKind::terminate(), "SIGTERM")?;
    let mut hup = on(SignalKind::hangup(), "SIGHUP")?;
    let mut relay = Relay::new(&cfg);
    info!(
        listen = %cfg.listen,
        pubkey = %relay.public_key(),
        tunnel_ip = %cfg.tunnel_ip,
        gate = ?cfg.gate,
        handshake_rate = %cfg.handshake_rate,
        peers = relay.peer_count(),
        "wg-relay started"
    );
    debug!(config = ?cfg, "effective config");

    let mut buf = vec![0u8; MAX_DATAGRAM_BYTES];
    let mut timers = tokio::time::interval(TIMER_INTERVAL);
    let mut stats = tokio::time::interval(STATS_INTERVAL);
    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => match r {
                Ok((n, src)) => {
                    if let Verdict::Forward(dst) = relay.handle(src, &buf[..n], Instant::now()) {
                        send(&sock, &mut relay, &buf[..n], dst).await;
                    }
                }
                Err(e) => warn!(error = %e, "recv failed"),
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
            _ = tokio::signal::ctrl_c() => break,
            _ = term.recv() => break,
        }
        for (dst, pkt) in relay.take_outbox() {
            send(&sock, &mut relay, &pkt, dst).await;
        }
    }
    info!(metrics = %relay.metrics(), "shutting down");
    Ok(())
}

/// Send one datagram; failures are logged and counted, never fatal.
async fn send(sock: &UdpSocket, relay: &mut Relay, pkt: &[u8], dst: SocketAddr) {
    if let Err(e) = sock.send_to(pkt, dst).await {
        relay.record_send_error();
        warn!(%dst, error = %e, "send failed");
    }
}
