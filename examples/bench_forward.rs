//! Throughput benchmark: WireGuard data packets through a real wg-relay
//! process on loopback, so changes to the forwarding path can be compared.
//!
//! usage: bench_forward [--bin target/release/wg-relay] [--secs 5] [--senders 4]
//!                      [--sizes 64,1420] [--gso] [--relay-log warn]
//!
//! It starts the relay with a temporary config listing one peer (the server),
//! registers the server through a real handshake with the relay, completes a
//! client-to-server handshake through it, then sends one encrypted data packet
//! over and over from the client socket (the relay does not check counters)
//! and counts what reaches the server socket. Each size is the plaintext
//! length; the datagram adds WireGuard's 16-byte header and 16-byte tag.
//!
//! Loopback is not a NIC: there is no driver GRO, so plain sends reach the
//! relay one datagram per receive. `--gso` sends bursts of up to 64 datagrams
//! with one GSO call instead, which loopback hands to a socket with UDP GRO on
//! as one coalesced buffer, as a NIC's GRO would. Build with
//! `cargo build --release --bins --examples` and run the release build.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use clap::Parser;
use quinn_udp::{EcnCodepoint, RecvMeta, Transmit, UdpSocketState};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

/// Traffic before the measurement window starts, so queues reach steady state.
const WARMUP: Duration = Duration::from_millis(500);
/// How long to wait for any one handshake step.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);
/// How often to resend an unanswered initiation.
const RETRY_INTERVAL: Duration = Duration::from_millis(250);
/// Most datagrams in one GSO send (the kernel's `UDP_MAX_SEGMENTS`).
const GSO_MAX_SEGMENTS: usize = 64;
/// Most bytes in one GSO send: the largest IPv4 UDP payload.
const GSO_MAX_BYTES: usize = 65_507;
const RECV_BUF_BYTES: usize = 65_536;
/// The relay's address for itself inside registration tunnels.
const TUNNEL_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 254);
/// ECN bits on every data packet sent, as WireGuard copies them from the
/// inner packet; the counter checks they survive the relay.
const SENT_ECN: EcnCodepoint = EcnCodepoint::Ect0;

/// Forward WireGuard data packets through a wg-relay process and measure the rate.
#[derive(Debug, Parser)]
struct Args {
    /// The relay binary to benchmark.
    #[arg(long, default_value = "target/release/wg-relay")]
    bin: PathBuf,
    /// Measurement time per size, in seconds.
    #[arg(long, default_value_t = 5)]
    secs: u64,
    /// Threads sending from the client socket; raise it until there is loss,
    /// so that the relay, not the senders, sets the rate.
    #[arg(long, default_value_t = 4)]
    senders: usize,
    /// Plaintext sizes in bytes, comma-separated.
    #[arg(long, value_delimiter = ',', default_value = "64,1420")]
    sizes: Vec<usize>,
    /// Send bursts with GSO, which reach the relay as GRO buffers.
    #[arg(long)]
    gso: bool,
    /// The relay's log filter (`RUST_LOG`); its log goes to stderr.
    #[arg(long, default_value = "warn")]
    relay_log: String,
}

#[derive(Debug, thiserror::Error)]
enum BenchError {
    #[error("socket I/O failed")]
    Io(#[from] io::Error),
    #[error("failed to start {path}")]
    Spawn {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("the relay exited early ({0})")]
    RelayExited(ExitStatus),
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
    #[error("WireGuard could not {0}")]
    Tunnel(&'static str),
    #[error("a size must be between 1 and {max} bytes")]
    Size { max: usize },
}

struct Key {
    sk: StaticSecret,
    pk: PublicKey,
}

fn key() -> Key {
    let sk = StaticSecret::random_from_rng(OsRng);
    let pk = PublicKey::from(&sk);
    Key { sk, pk }
}

fn b64(bytes: [u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn tunn(me: &Key, peer: &Key) -> Tunn {
    Tunn::new(me.sk.clone(), peer.pk, None, None, OsRng.next_u32() >> 8, None)
}

fn initiation(t: &mut Tunn) -> Result<Vec<u8>, BenchError> {
    let mut buf = vec![0u8; 2048];
    match t.format_handshake_initiation(&mut buf, true) {
        TunnResult::WriteToNetwork(p) => Ok(p.to_vec()),
        _ => Err(BenchError::Tunnel("start a handshake")),
    }
}

/// Feed `pkt` to `t` and return the datagram it wants to send back, if any.
fn reply(t: &mut Tunn, pkt: &[u8]) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; RECV_BUF_BYTES];
    match t.decapsulate(None, pkt, &mut buf) {
        TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
        _ => None,
    }
}

fn encrypt(t: &mut Tunn, plain: &[u8]) -> Result<Vec<u8>, BenchError> {
    let mut buf = vec![0u8; RECV_BUF_BYTES];
    match t.encapsulate(plain, &mut buf) {
        TunnResult::WriteToNetwork(p) => Ok(p.to_vec()),
        _ => Err(BenchError::Tunnel("encrypt a data packet")),
    }
}

/// An IPv4 packet of `len` bytes, the plaintext of a data packet.
fn ip_packet(len: usize) -> Vec<u8> {
    let mut p = vec![0u8; len];
    p[0] = 0x45;
    p
}

/// A temporary directory, removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> io::Result<Self> {
        let dir = std::env::temp_dir().join(format!("wg-relay-bench-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(TempDir(dir))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The relay child process, killed when dropped.
struct RelayProcess(Child);

impl RelayProcess {
    fn spawn(bin: &Path, config: &Path, log: &str) -> Result<Self, BenchError> {
        let child = Command::new(bin)
            .arg("--config")
            .arg(config)
            .env("RUST_LOG", log)
            .stdin(Stdio::null())
            .spawn()
            .map_err(|source| BenchError::Spawn { path: bin.to_owned(), source })?;
        Ok(RelayProcess(child))
    }

    fn check_running(&mut self) -> Result<(), BenchError> {
        match self.0.try_wait()? {
            Some(status) => Err(BenchError::RelayExited(status)),
            None => Ok(()),
        }
    }
}

impl Drop for RelayProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A loopback port that was free a moment ago.
fn free_port() -> io::Result<u16> {
    Ok(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?.local_addr()?.port())
}

/// Wait for a datagram on `sock` that `accept` turns into a value, ignoring others.
fn recv_until<T>(
    sock: &UdpSocket,
    deadline: Instant,
    mut accept: impl FnMut(&[u8]) -> Option<T>,
) -> Result<Option<T>, BenchError> {
    let mut buf = vec![0u8; RECV_BUF_BYTES];
    while Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some(v) = accept(&buf[..n]) {
                    return Ok(Some(v));
                }
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(None)
}

/// The three parties and their sockets.
struct World {
    relay_key: Key,
    server_key: Key,
    client_key: Key,
    relay: SocketAddr,
    server: UdpSocket,
    client: UdpSocket,
}

impl World {
    /// Register the server with the relay, then check it with a ping to the
    /// relay's tunnel address, which the relay answers only once registered.
    fn register(&self, process: &mut RelayProcess) -> Result<(), BenchError> {
        let deadline = Instant::now() + STEP_TIMEOUT;
        while Instant::now() < deadline {
            process.check_running()?;
            let mut t = tunn(&self.server_key, &self.relay_key);
            self.server.send_to(&initiation(&mut t)?, self.relay)?;
            let answered = Instant::now() + RETRY_INTERVAL;
            let Some(keepalive) = recv_until(&self.server, answered, |p| reply(&mut t, p))? else {
                continue;
            };
            self.server.send_to(&keepalive, self.relay)?;
            let ping = encrypt(&mut t, &echo_request(TUNNEL_IP))?;
            self.server.send_to(&ping, self.relay)?;
            let mut buf = vec![0u8; RECV_BUF_BYTES];
            let pong = recv_until(&self.server, answered + RETRY_INTERVAL, |p| {
                matches!(t.decapsulate(None, p, &mut buf), TunnResult::WriteToTunnelV4(..))
                    .then_some(())
            })?;
            if pong.is_some() {
                return Ok(());
            }
        }
        Err(BenchError::Timeout("the server to register with the relay"))
    }

    /// Complete a client-to-server handshake through the relay and return the
    /// client's tunnel, ready to encrypt data for the server.
    fn connect(&self) -> Result<Tunn, BenchError> {
        let deadline = Instant::now() + STEP_TIMEOUT;
        while Instant::now() < deadline {
            let (mut c, mut s) = (
                tunn(&self.client_key, &self.server_key),
                tunn(&self.server_key, &self.client_key),
            );
            self.client.send_to(&initiation(&mut c)?, self.relay)?;
            let step = Instant::now() + RETRY_INTERVAL;
            let Some(resp) = recv_until(&self.server, step, |p| reply(&mut s, p))? else {
                continue;
            };
            self.server.send_to(&resp, self.relay)?;
            let Some(keepalive) = recv_until(&self.client, step, |p| reply(&mut c, p))? else {
                continue;
            };
            self.client.send_to(&keepalive, self.relay)?;
            let mut buf = vec![0u8; RECV_BUF_BYTES];
            let confirmed = recv_until(&self.server, step + RETRY_INTERVAL, |p| {
                matches!(s.decapsulate(None, p, &mut buf), TunnResult::Done).then_some(())
            })?;
            if confirmed.is_some() {
                return Ok(c);
            }
        }
        Err(BenchError::Timeout("a client handshake through the relay"))
    }
}

/// An ICMP echo request from 10.99.0.1 to `dst`; only its shape matters.
fn echo_request(dst: Ipv4Addr) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 28, 0, 1, 0, 0, 64, 1, 0, 0, 10, 99, 0, 1];
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(&[8, 0, 0xf7, 0xfe, 0, 1, 0, 0]);
    let sum: u32 = p[..20].chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], c[1]]))).sum();
    let c = !(((sum & 0xffff) + (sum >> 16)) as u16);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p
}

/// What one measurement window saw.
struct Sample {
    sent: u64,
    received: u64,
    ecn_kept: u64,
    elapsed: Duration,
}

/// Count datagrams arriving at the server that are copies of `pkt`.
fn count_received(
    sock: &UdpSocket,
    state: &UdpSocketState,
    pkt: &[u8],
    stop: &AtomicBool,
    counts: &Counts,
) -> io::Result<()> {
    let mut bufs = vec![0u8; quinn_udp::BATCH_SIZE * RECV_BUF_BYTES];
    let mut meta = [RecvMeta::default(); quinn_udp::BATCH_SIZE];
    while !stop.load(Ordering::Relaxed) {
        let mut chunks = bufs.chunks_mut(RECV_BUF_BYTES);
        let mut iovs: [io::IoSliceMut<'_>; quinn_udp::BATCH_SIZE] =
            std::array::from_fn(|_| io::IoSliceMut::new(chunks.next().unwrap_or_default()));
        let n = match state.recv(sock.into(), &mut iovs, &mut meta) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_micros(50));
                continue;
            }
            Err(e) => return Err(e),
        };
        for (m, buf) in meta.iter().zip(bufs.chunks(RECV_BUF_BYTES)).take(n) {
            let data = &buf[..m.len.min(buf.len())];
            let stride = if m.stride == 0 { data.len().max(1) } else { m.stride };
            let matched = data.chunks(stride).filter(|d| *d == pkt).count() as u64;
            counts.received.fetch_add(matched, Ordering::Relaxed);
            if m.ecn == Some(SENT_ECN) {
                counts.ecn_kept.fetch_add(matched, Ordering::Relaxed);
            }
        }
    }
    Ok(())
}

/// Send `pkt` to the relay as fast as possible until stopped.
fn send_loop(
    sock: &UdpSocket,
    state: &UdpSocketState,
    gso: bool,
    relay: SocketAddr,
    pkt: &[u8],
    stop: &AtomicBool,
    sent: &AtomicU64,
) {
    let burst = if gso { (GSO_MAX_BYTES / pkt.len()).clamp(1, GSO_MAX_SEGMENTS) } else { 1 };
    let contents = pkt.repeat(burst);
    let transmit = Transmit {
        destination: relay,
        ecn: Some(SENT_ECN),
        contents: &contents,
        segment_size: Some(pkt.len()),
        src_ip: None,
    };
    while !stop.load(Ordering::Relaxed) {
        // A full send buffer or a refused GSO send is part of the load test.
        if state.try_send(sock.into(), &transmit).is_ok() {
            sent.fetch_add(burst as u64, Ordering::Relaxed);
        }
    }
}

/// What the counter has seen so far.
#[derive(Default)]
struct Counts {
    received: AtomicU64,
    /// Received with the ECN bits they were sent with.
    ecn_kept: AtomicU64,
}

/// Run senders and the counter for one window and report what got through.
fn measure(world: &World, states: &States, pkt: &[u8], args: &Args) -> Result<Sample, BenchError> {
    let stop = AtomicBool::new(false);
    let (sent, counts) = (AtomicU64::new(0), Counts::default());
    let (client, server) = (&world.client, &world.server);
    thread::scope(|s| {
        let counter = s.spawn(|| count_received(server, &states.server, pkt, &stop, &counts));
        for _ in 0..args.senders {
            s.spawn(|| send_loop(client, &states.client, args.gso, world.relay, pkt, &stop, &sent));
        }
        thread::sleep(WARMUP);
        let snapshot = || {
            let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
            (load(&sent), load(&counts.received), load(&counts.ecn_kept), Instant::now())
        };
        let (s0, r0, e0, t0) = snapshot();
        thread::sleep(Duration::from_secs(args.secs));
        let (s1, r1, e1, t1) = snapshot();
        stop.store(true, Ordering::Relaxed);
        let counted = counter.join().unwrap_or(Ok(()));
        counted?;
        Ok(Sample { sent: s1 - s0, received: r1 - r0, ecn_kept: e1 - e0, elapsed: t1 - t0 })
    })
}

/// Batched I/O state for the server and client sockets.
struct States {
    server: UdpSocketState,
    client: UdpSocketState,
}

fn run(args: &Args) -> Result<(), BenchError> {
    let max = GSO_MAX_BYTES - 32 - 16;
    if args.sizes.iter().any(|&s| s == 0 || s > max) {
        return Err(BenchError::Size { max });
    }
    let (relay_key, server_key, client_key) = (key(), key(), key());
    let relay = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()?));
    let dir = TempDir::new()?;
    let config = dir.0.join("relay.toml");
    std::fs::write(
        &config,
        format!(
            "listen = \"{relay}\"\nprivate_key = \"{}\"\nhandshake_rate_per_ip = \"100/s\"\n\
             [[peer]]\nname = \"server\"\npubkey = \"{}\"\n",
            b64(relay_key.sk.to_bytes()),
            b64(server_key.pk.to_bytes()),
        ),
    )?;
    let mut process = RelayProcess::spawn(&args.bin, &config, &args.relay_log)?;
    let world = World {
        relay_key,
        server_key,
        client_key,
        relay,
        server: UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?,
        client: UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?,
    };
    for sock in [&world.server, &world.client] {
        sock.set_read_timeout(Some(Duration::from_millis(20)))?;
    }
    // Both sockets turn non-blocking here; `recv_until` copes with either.
    let states = States {
        server: UdpSocketState::new((&world.server).into())?,
        client: UdpSocketState::new((&world.client).into())?,
    };
    // Room for bursts, so the counter is not what drops packets.
    let _ = states.server.set_recv_buffer_size((&world.server).into(), 16 << 20);
    // Receive timestamps crowd the ECN bits out of `quinn-udp`'s control
    // buffer next to a GRO segment size; the counter needs the ECN bits.
    #[cfg(target_os = "linux")]
    nix::sys::socket::setsockopt(
        &world.server,
        nix::sys::socket::sockopt::ReceiveTimestampns,
        &false,
    )
    .map_err(io::Error::from)?;

    println!(
        "relay {}: {} sender thread(s), {} sends, {} s per size",
        args.bin.display(),
        args.senders,
        if args.gso { "GSO" } else { "plain" },
        args.secs
    );
    println!(
        "{:>9} {:>12} {:>12} {:>9} {:>7} {:>9}",
        "datagram", "sent/s", "forwarded/s", "Mbit/s", "loss", "ECN kept"
    );
    for &size in &args.sizes {
        // A fresh registration and session per size, so long runs never
        // outlive the relay's registration and session lifetimes.
        world.register(&mut process)?;
        let mut client = world.connect()?;
        let pkt = encrypt(&mut client, &ip_packet(size))?;
        let sample = measure(&world, &states, &pkt, args)?;
        process.check_running()?;
        let secs = sample.elapsed.as_secs_f64();
        let pps = sample.received as f64 / secs;
        let share = |part: u64, whole: u64| part as f64 / whole.max(1) as f64 * 100.0;
        println!(
            "{:>7} B {:>12.0} {:>12.0} {:>9.1} {:>6.1}% {:>8.1}%",
            pkt.len(),
            sample.sent as f64 / secs,
            pps,
            pps * pkt.len() as f64 * 8.0 / 1e6,
            (100.0 - share(sample.received, sample.sent)).max(0.0),
            share(sample.ecn_kept, sample.received),
        );
        // Let the queues drain before the next size.
        thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(&Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprint!("error: {e}");
            let mut source = std::error::Error::source(&e);
            while let Some(s) = source {
                eprint!(": {s}");
                source = s.source();
            }
            eprintln!();
            ExitCode::FAILURE
        }
    }
}
