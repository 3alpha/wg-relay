#![forbid(unsafe_code)]

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use wg_relay::config::{Config, Role, encode_key};
use wg_relay::relay::Relay;

const USAGE: &str = "usage: wg-relay [-c|--config PATH] [--check-config]\n\
                     PATH defaults to relay.toml; SIGHUP reloads it; log level via RUST_LOG (default info)";

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
    let mut path = PathBuf::from("relay.toml");
    let mut check = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--check-config" => check = true,
            "-c" | "--config" => match args.next() {
                Some(p) => path = p.into(),
                None => {
                    eprintln!("{USAGE}");
                    return ExitCode::from(2);
                }
            },
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            _ => {
                eprintln!("unknown argument {a}\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let cfg = match Config::load(&path) {
        Ok(c) => c,
        Err(e) => {
            error!("invalid config: {e}");
            return ExitCode::FAILURE;
        }
    };
    for w in cfg.warnings() {
        warn!("config: {w}");
    }
    if check {
        println!("config OK: {}", path.display());
        println!("listen       {}", cfg.listen);
        println!("relay key    {}", encode_key(&cfg.relay_pubkey()));
        println!("tunnel ip    {}", cfg.tunnel_ip);
        println!("client gate  {:?}", cfg.gate);
        println!("init rate    {}/s per source IP", cfg.rate_per_sec);
        let name = |k: &[u8; 32]| cfg.peers.iter().find(|p| &p.pubkey == k).map_or("?", |p| p.name.as_str());
        for p in &cfg.peers {
            let reach: Vec<&str> = p.servers.iter().map(name).collect();
            let role = if p.role == Role::Server { "server" } else { "client" };
            println!("{role} {:<12} {}  {}", p.name, encode_key(&p.pubkey), reach.join(", "));
        }
        return ExitCode::SUCCESS;
    }
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            error!("runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(cfg, path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("fatal: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cfg: Config, path: PathBuf) -> std::io::Result<()> {
    let sock = UdpSocket::bind(cfg.listen).await?;
    let mut relay = Relay::new(&cfg);
    info!(listen = %sock.local_addr()?, pubkey = %relay.public_key_b64(), peers = relay.peer_count(), gate = ?cfg.gate, "wg-relay started");
    let mut buf = vec![0u8; 65536];
    let mut timers = tokio::time::interval(Duration::from_millis(250));
    let mut stats = tokio::time::interval(Duration::from_secs(60));
    let mut term = signal(SignalKind::terminate())?;
    let mut hup = signal(SignalKind::hangup())?;
    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => match r {
                Ok((n, src)) => {
                    if let Some(dst) = relay.handle(src, &buf[..n], Instant::now())
                        && let Err(e) = sock.send_to(&buf[..n], dst).await {
                            relay.metrics.send_errors += 1;
                            warn!(%dst, "send failed: {e}");
                        }
                }
                Err(e) => warn!("recv failed: {e}"),
            },
            _ = timers.tick() => relay.tick(Instant::now()),
            _ = stats.tick() => info!(metrics = %relay.metrics, sessions = relay.sessions.len(), "stats"),
            _ = hup.recv() => match Config::load(&path) {
                Ok(new) => {
                    if new.listen != cfg.listen {
                        warn!("changing listen requires a restart");
                    }
                    new.warnings().iter().for_each(|w| warn!("config: {w}"));
                    relay.reload(&new);
                }
                Err(e) => error!("reload failed, keeping current config: {e}"),
            },
            _ = tokio::signal::ctrl_c() => break,
            _ = term.recv() => break,
        }
        for (dst, pkt) in std::mem::take(&mut relay.outbox) {
            relay.metrics.tunnel_tx += 1;
            if let Err(e) = sock.send_to(&pkt, dst).await {
                relay.metrics.send_errors += 1;
                warn!(%dst, "send failed: {e}");
            }
        }
    }
    info!(metrics = %relay.metrics, "shutting down");
    Ok(())
}
