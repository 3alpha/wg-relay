//! The main thread's loop: it watches the forwarding threads, logs stats,
//! applies reloads and answers scrapes, until a signal or a thread's end.

use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};

use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use wg_relay::config::{Config, RelayPeer};
use wg_relay::error::{AppError, Report};
use wg_relay::key::PublicKey;
use wg_relay::relay::Relay;

use super::ConfigSource;
use super::metrics::http::{Listener, ScrapeRequest};
use super::metrics::{self, Process, Reloads, Scrape};
use super::workers::Workers;

/// How often the main thread checks that every forwarding thread still runs.
const CHECK_INTERVAL: Duration = Duration::from_millis(250);
/// How often the main thread logs every counter.
const STATS_INTERVAL: Duration = Duration::from_secs(60);
/// Scrape requests waiting for the main thread; the server serves at most 16 connections.
const SCRAPE_QUEUE: usize = 16;

/// The main thread's state while the relay runs.
pub(super) struct Supervisor<'a> {
    relay: &'a Relay,
    workers: &'a Workers,
    source: &'a ConfigSource,
    /// The config the relay started with; changing listen, workers, private_key
    /// or metrics_listen needs a restart.
    started_config: &'a Config,
    /// The config last applied, at startup or by a reload.
    applied: Config,
    /// The relay's key, which only a restart changes.
    public_key: PublicKey,
    /// The address the sockets are bound to.
    listen: SocketAddr,
    /// The `[Peer]` section last printed.
    relay_peer: RelayPeer,
    started: SystemTime,
    reloads: Reloads,
}

impl<'a> Supervisor<'a> {
    /// Supervise `workers`, which run `relay` on sockets bound to `listen`.
    pub(super) fn new(
        relay: &'a Relay,
        workers: &'a Workers,
        config: &'a Config,
        source: &'a ConfigSource,
        listen: SocketAddr,
    ) -> Self {
        let started = SystemTime::now();
        let public_key = config.private_key.public_key();
        let relay_peer =
            RelayPeer::new(public_key, config.public_endpoint.as_ref(), listen, config.tunnel_ip);
        Supervisor {
            relay,
            workers,
            source,
            started_config: config,
            applied: config.clone(),
            public_key,
            listen,
            relay_peer,
            started,
            reloads: Reloads::new(started),
        }
    }

    /// Log the `[Peer]` section as one event whose lines past the first carry
    /// no log prefix, so it can be copied straight into a WireGuard config.
    pub(super) fn print_relay_peer(&self) {
        let hint = if self.relay_peer.has_placeholder() {
            ", with the relay's public address filled in (or set public_endpoint)"
        } else {
            ""
        };
        let block = self.relay_peer.to_string();
        info!("add this to each configured peer's WireGuard config{hint}:\n{}", block.trim_end());
    }

    /// Log stats, apply reloads and answer scrapes until SIGINT or SIGTERM, or
    /// until a forwarding thread ends.
    pub(super) async fn run(mut self, metrics: Option<Listener>) -> Result<(), AppError> {
        let on =
            |kind, name| signal(kind).map_err(|source| AppError::Signal { signal: name, source });
        let mut hup = on(SignalKind::hangup(), "SIGHUP")?;
        let mut int = on(SignalKind::interrupt(), "SIGINT")?;
        let mut term = on(SignalKind::terminate(), "SIGTERM")?;
        let mut scrapes = metrics.map(serve_metrics).transpose()?;
        let mut checks = tokio::time::interval(CHECK_INTERVAL);
        let mut stats = tokio::time::interval(STATS_INTERVAL);
        loop {
            tokio::select! {
                _ = checks.tick() => {
                    if let Some(index) = self.workers.exited() {
                        return Err(AppError::WorkerExited { index });
                    }
                }
                _ = stats.tick() => {
                    let snapshot = self.workers.snapshot(Instant::now());
                    let control = &snapshot.control;
                    info!(
                        metrics = %snapshot.total,
                        control = %control.counters,
                        sessions = control.sessions,
                        "stats"
                    );
                }
                Some(reply) = next_scrape(&mut scrapes) => {
                    // The client may have hung up meanwhile; then nobody wants the text.
                    let _ = reply.send(self.render_metrics());
                }
                _ = hup.recv() => self.reload(),
                _ = int.recv() => return Ok(()),
                _ = term.recv() => return Ok(()),
            }
        }
    }

    /// Render a fresh snapshot for one scrape.
    fn render_metrics(&self) -> String {
        metrics::render(&Scrape {
            snapshot: self.workers.snapshot(Instant::now()),
            handshake_rate_per_sec: self.applied.handshake_rate.per_sec(),
            reloads: self.reloads,
            started: self.started,
            now: SystemTime::now(),
            process: Process::read(),
        })
    }

    /// Reload the config file, keeping the current one if it is invalid, and
    /// print the `[Peer]` section again if the reload changed it.
    fn reload(&mut self) {
        let new = match self.source.load() {
            Ok(new) => new,
            Err(e) => {
                self.reloads.record_failure();
                return error!(error = %Report(&e), "reload failed, keeping current config");
            }
        };
        let started = self.started_config;
        if new.listen != started.listen {
            warn!("changing listen requires a restart");
        }
        if new.workers != started.workers {
            warn!("changing workers requires a restart");
        }
        if new.metrics_listen != started.metrics_listen {
            warn!("changing metrics_listen requires a restart");
        }
        self.relay.reload(&new);
        self.reloads.record_success(SystemTime::now());
        let peer = RelayPeer::new(
            self.public_key,
            new.public_endpoint.as_ref(),
            self.listen,
            new.tunnel_ip,
        );
        self.applied = new;
        if peer != self.relay_peer {
            self.relay_peer = peer;
            self.print_relay_peer();
        }
    }
}

/// Start the metrics server on this runtime; it asks for each scrape's text here.
fn serve_metrics(listener: Listener) -> Result<mpsc::Receiver<ScrapeRequest>, AppError> {
    let (tx, rx) = mpsc::channel(SCRAPE_QUEUE);
    listener.spawn(tx)?;
    Ok(rx)
}

/// The next scrape request, or never if metrics are off.
async fn next_scrape(scrapes: &mut Option<mpsc::Receiver<ScrapeRequest>>) -> Option<ScrapeRequest> {
    match scrapes {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}
