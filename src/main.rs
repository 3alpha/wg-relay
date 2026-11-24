#![forbid(unsafe_code)]

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use wg_relay::config::{Config, Role};
use wg_relay::error::{AppError, Report};
use wg_relay::key::PeerKey;
use wg_relay::relay::{Relay, Verdict};

const USAGE: &str = "usage: wg-relay [-c|--config PATH] [--check-config]\n\
                     PATH defaults to relay.toml; SIGHUP reloads it; log level via RUST_LOG (default info)";

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e @ AppError::Usage { .. }) => {
            eprintln!("{e}\n{USAGE}");
            ExitCode::from(2)
        }
        Err(e) => {
            error!("{}", Report(&e));
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), AppError> {
    let mut path = PathBuf::from("relay.toml");
    let mut check = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--check-config" => check = true,
            "-c" | "--config" => path = args.next().ok_or(AppError::Usage { arg: a })?.into(),
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            _ => return Err(AppError::Usage { arg: a }),
        }
    }
    let cfg = Config::load(&path).map_err(|source| AppError::Config { path: path.clone(), source })?;
    for w in cfg.warnings() {
        warn!("config: {w}");
    }
    if check {
        println!("config OK: {}", path.display());
        println!("listen       {}", cfg.listen);
        println!("relay key    {}", cfg.private_key.public_key());
        println!("tunnel ip    {}", cfg.tunnel_ip);
        println!("client gate  {:?}", cfg.gate);
        println!("init rate    {} per source IP", cfg.handshake_rate);
        let name = |k: &PeerKey| cfg.peers.iter().find(|p| &p.pubkey == k).map_or("?", |p| p.name.as_str());
        for p in &cfg.peers {
            let (role, reach): (_, Vec<&str>) = match &p.role {
                Role::Server => ("server", Vec::new()),
                Role::Client { servers } => ("client", servers.iter().map(name).collect()),
            };
            println!("{role} {:<12} {}  {}", p.name, p.pubkey, reach.join(", "));
        }
        return Ok(());
    }
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(AppError::Runtime)?;
    rt.block_on(serve(cfg, path))
}

async fn serve(cfg: Config, path: PathBuf) -> Result<(), AppError> {
    let sock =
        UdpSocket::bind(cfg.listen).await.map_err(|source| AppError::Bind { addr: cfg.listen, source })?;
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
    let mut buf = vec![0u8; 65536];
    let mut timers = tokio::time::interval(Duration::from_millis(250));
    let mut stats = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => match r {
                Ok((n, src)) => {
                    if let Verdict::Forward(dst) = relay.handle(src, &buf[..n], Instant::now())
                        && let Err(e) = sock.send_to(&buf[..n], dst).await
                    {
                        relay.record_send_error();
                        warn!(%dst, error = %e, "send failed");
                    }
                }
                Err(e) => warn!(error = %e, "recv failed"),
            },
            _ = timers.tick() => relay.tick(Instant::now()),
            _ = stats.tick() => info!(metrics = %relay.metrics(), sessions = relay.session_count(), "stats"),
            _ = hup.recv() => match Config::load(&path) {
                Ok(new) => {
                    if new.listen != cfg.listen {
                        warn!("changing listen requires a restart");
                    }
                    new.warnings().iter().for_each(|w| warn!("config: {w}"));
                    relay.reload(&new);
                }
                Err(e) => error!(error = %Report(&e), "reload failed, keeping current config"),
            },
            _ = tokio::signal::ctrl_c() => break,
            _ = term.recv() => break,
        }
        for (dst, pkt) in relay.take_outbox() {
            if let Err(e) = sock.send_to(&pkt, dst).await {
                relay.record_send_error();
                warn!(%dst, error = %e, "send failed");
            }
        }
    }
    info!(metrics = %relay.metrics(), "shutting down");
    Ok(())
}
