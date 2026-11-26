//! The real binary with metrics on: startup output, `/metrics` over HTTP, reloads.
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test setup panics on failure")]

mod common;
use common::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long to wait for the relay to log a line or for a counter to show up.
const WAIT: Duration = Duration::from_secs(10);

/// A relay process whose log lines arrive on `log`, killed when dropped.
struct RelayProcess {
    child: Child,
    log: mpsc::Receiver<String>,
    /// Every line logged so far, and how many of them `wait_for` has passed.
    seen: Vec<String>,
    cursor: usize,
    dir: PathBuf,
}

impl RelayProcess {
    fn start(config: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("wg-relay-metrics-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("relay.toml"), config).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_wg-relay"))
            .arg("-c")
            .arg(dir.join("relay.toml"))
            .env("RUST_LOG", "info")
            .env_remove("WG_RELAY_METRICS_LISTEN")
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, log) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        RelayProcess { child, log, seen: Vec::new(), cursor: 0, dir }
    }

    /// Wait for the next log line containing `needle`, after the last one found; returns it.
    fn wait_for(&mut self, needle: &str) -> String {
        let deadline = Instant::now() + WAIT;
        loop {
            while let Some(line) = self.seen.get(self.cursor) {
                self.cursor += 1;
                if line.contains(needle) {
                    return line.clone();
                }
            }
            let left = deadline.saturating_duration_since(Instant::now());
            let line = self.log.recv_timeout(left).unwrap_or_else(|_| {
                panic!("no log line with {needle:?}; saw:\n{}", self.seen.join("\n"))
            });
            self.seen.push(line);
        }
    }

    /// The `[Peer]` section logged at startup: the lines after the one announcing it.
    fn relay_peer_block(&mut self) -> String {
        self.wait_for("add this to each configured peer's WireGuard config");
        (0..6).map(|_| self.wait_for("") + "\n").collect()
    }

    fn signal(&self, name: &str) {
        let pid = self.child.id().to_string();
        assert!(Command::new("kill").args(["-s", name, &pid]).status().unwrap().success());
    }
}

impl Drop for RelayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The address after `field=` in a log line.
fn addr_field(line: &str, field: &str) -> SocketAddr {
    let start = line.find(&format!("{field}=")).unwrap() + field.len() + 1;
    line[start..].split_whitespace().next().unwrap().parse().unwrap()
}

/// Send one HTTP request and return the whole response.
fn http(addr: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn scrape(addr: SocketAddr) -> String {
    http(addr, "GET /metrics HTTP/1.1\r\nHost: relay\r\n\r\n")
}

/// Scrape until a line equal to `line` shows up.
fn wait_for_sample(addr: SocketAddr, line: &str) -> String {
    let deadline = Instant::now() + WAIT;
    loop {
        let body = scrape(addr);
        if body.lines().any(|l| l == line) {
            return body;
        }
        assert!(Instant::now() < deadline, "{line:?} never appeared in:\n{body}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn serves_metrics_and_prints_the_relay_peer_section() {
    let (r, main) = (key(), key());
    let extra = "listen = \"127.0.0.1:0\"\nmetrics_listen = \"127.0.0.1:0\"\nworkers = 2\n\
                 public_endpoint = \"relay.example.com:51820\"\n";
    let config = head(&r, extra) + &peer("main", &main);
    let mut relay = RelayProcess::start(&config);
    let listen = addr_field(&relay.wait_for("wg-relay started"), "listen");
    let metrics = addr_field(&relay.wait_for("serving Prometheus metrics"), "addr");
    assert_eq!(
        relay.relay_peer_block(),
        format!(
            "[Peer]\n\
             # wg-relay: registration tunnel only\n\
             PublicKey           = {}\n\
             Endpoint            = relay.example.com:51820\n\
             AllowedIPs          = 10.99.0.254/32\n\
             PersistentKeepalive = 25\n",
            r.id()
        )
    );

    let response = scrape(metrics);
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"), "{headers}");
    assert!(
        headers.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8"),
        "{headers}"
    );
    assert!(headers.contains(&format!("Content-Length: {}", body.len())), "{headers}");
    for line in [
        concat!("wg_relay_build_info{version=\"", env!("CARGO_PKG_VERSION"), "\"} 1"),
        "wg_relay_workers 2",
        "wg_relay_configured_peers 1",
        "wg_relay_registered_peers 0",
        "wg_relay_peer_registered{peer=\"main\"} 0",
        "wg_relay_datagrams_dropped_total{reason=\"malformed\"} 0",
        "wg_relay_config_reloads_total{result=\"success\"} 0",
        "wg_relay_config_last_reload_successful 1",
        "# TYPE wg_relay_datagrams_received_total counter",
        "wg_relay_sessions_expired_total{state=\"pending\"} 0",
        "wg_relay_tunnel_errors_total{error=\"replay\"} 0",
        "wg_relay_peer_initiations_total{peer=\"main\",result=\"dropped\"} 0",
        "wg_relay_reserved_prefixes 1",
        "wg_relay_rate_limit_buckets 65536",
    ] {
        assert!(body.lines().any(|l| l == line), "{line:?} missing from:\n{body}");
    }
    assert!(!body.contains(&r.id().to_string()), "no keys in the metrics");

    // A datagram counts in the totals, and in one forwarding thread's own counters.
    UdpSocket::bind("127.0.0.1:0").unwrap().send_to(&[9; 20], listen).unwrap();
    let body = wait_for_sample(metrics, "wg_relay_datagrams_dropped_total{reason=\"malformed\"} 1");
    assert!(body.lines().any(|l| l == "wg_relay_received_bytes_total 20"), "{body}");
    let data_plane = "wg_relay_datagrams_decided_total{plane=\"data\"} 1";
    assert!(body.lines().any(|l| l == data_plane), "malformed is the data plane's: {body}");
    let per_worker: u64 = body
        .lines()
        .filter(|l| l.starts_with("wg_relay_worker_datagrams_total{"))
        .map(|l| l.rsplit(' ').next().unwrap().parse::<u64>().unwrap())
        .sum();
    assert_eq!(per_worker, 1);

    // Other paths and methods.
    assert!(http(metrics, "GET / HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 404 Not Found\r\n"));
    let post = http(metrics, "POST /metrics HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
    assert!(post.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"), "{post}");
    let head_only = http(metrics, "HEAD /metrics HTTP/1.1\r\n\r\n");
    assert!(head_only.ends_with("\r\n\r\n") && head_only.contains("200 OK"), "{head_only}");

    // A reload that changes the tunnel address prints the new section and counts.
    let changed = head(&r, &format!("{extra}tunnel_ip = \"10.99.0.253\"\n")) + &peer("main", &main);
    std::fs::write(relay.dir.join("relay.toml"), changed).unwrap();
    relay.signal("HUP");
    relay.wait_for("config applied");
    let block = relay.relay_peer_block();
    assert!(block.contains("AllowedIPs          = 10.99.0.253/32\n"), "{block}");
    wait_for_sample(metrics, "wg_relay_config_reloads_total{result=\"success\"} 1");
    std::fs::write(relay.dir.join("relay.toml"), "not toml").unwrap();
    relay.signal("HUP");
    let body = wait_for_sample(metrics, "wg_relay_config_reloads_total{result=\"failure\"} 1");
    assert!(body.lines().any(|l| l == "wg_relay_config_last_reload_successful 0"), "{body}");
}
