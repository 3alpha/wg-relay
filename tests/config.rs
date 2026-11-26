//! Config validation and the `--check-config` flag.
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test setup panics on failure")]

mod common;
use common::*;
use std::process::Command;
use wg_relay::config::{Config, ConfigError, Peer};

#[test]
fn peers_and_defaults() {
    let (r, a, b) = (key(), key(), key());
    let config = Config::parse(&(head(&r, "") + &peer("home", &a) + &peer("office", &b))).unwrap();
    assert_eq!(config.listen.to_string(), "0.0.0.0:51820");
    assert_eq!(config.tunnel_ip.to_string(), "10.99.0.254");
    assert_eq!(config.handshake_rate.per_sec(), 10.0);
    assert_eq!(config.private_key.public_key(), r.id());
    let cores = std::thread::available_parallelism().unwrap().get();
    assert_eq!(config.workers.get(), cores.min(wg_relay::config::MAX_WORKERS), "one per core");
    assert_eq!(
        config.peers,
        vec![
            Peer { name: "home".into(), pubkey: a.id() },
            Peer { name: "office".into(), pubkey: b.id() },
        ]
    );

    assert_eq!((config.public_endpoint, config.metrics_listen), (None, None), "both off");

    let extra = "listen = \"127.0.0.1:5000\"\ntunnel_ip = \"10.0.0.1\"\n\
                 handshake_rate_per_ip = \"60/m\"\nworkers = 3\n\
                 public_endpoint = \"relay.example.com:51820\"\n\
                 metrics_listen = \"127.0.0.1:9586\"\n";
    let config = Config::parse(&(head(&r, extra) + &peer("home", &a))).unwrap();
    assert_eq!(
        (config.listen.to_string(), config.tunnel_ip.to_string(), config.handshake_rate.per_sec()),
        ("127.0.0.1:5000".into(), "10.0.0.1".into(), 1.0)
    );
    assert_eq!(config.workers.get(), 3);
    assert_eq!(config.public_endpoint.unwrap().to_string(), "relay.example.com:51820");
    assert_eq!(config.metrics_listen.unwrap().to_string(), "127.0.0.1:9586");
}

/// Does this error match what a test case expects?
type ErrorCheck = fn(&ConfigError) -> bool;

/// A parse error whose toml message mentions `needle`.
fn toml_error(e: &ConfigError, needle: &str) -> bool {
    matches!(e, ConfigError::Parse(t) if t.message().contains(needle))
}

#[test]
fn rejects_bad_configs_with_exact_errors() {
    let (r, a, b) = (key(), key(), key());
    let cases: Vec<(&str, String, ErrorCheck)> = vec![
        ("no peer", head(&r, ""), |e| matches!(e, ConfigError::NoPeer)),
        (
            "duplicate name",
            head(&r, "") + &peer("a", &a) + &peer("a", &b),
            |e| matches!(e, ConfigError::DuplicateName { name } if name == "a"),
        ),
        (
            "duplicate key",
            head(&r, "") + &peer("a", &a) + &peer("b", &a),
            |e| matches!(e, ConfigError::DuplicatePubkey { name } if name == "b"),
        ),
        (
            "relay's own key",
            head(&r, "") + &peer("me", &r),
            |e| matches!(e, ConfigError::RelayKeyReused { name } if name == "me"),
        ),
        ("removed client_gate", head(&r, "client_gate = \"none\"\n") + &peer("a", &a), |e| {
            toml_error(e, "unknown field `client_gate`")
        }),
        (
            "removed server table",
            head(&r, "") + "[[server]]\nname = \"a\"\npubkey = \"AAAA\"\n",
            |e| toml_error(e, "unknown field `server`"),
        ),
        ("bad rate", head(&r, "handshake_rate_per_ip = \"0/s\"\n") + &peer("a", &a), |e| {
            toml_error(e, "rate must be positive")
        }),
        ("no workers", head(&r, "workers = 0\n") + &peer("a", &a), |e| {
            matches!(e, ConfigError::Workers { got: 0, max: 256 })
        }),
        ("too many workers", head(&r, "workers = 257\n") + &peer("a", &a), |e| {
            matches!(e, ConfigError::Workers { got: 257, max: 256 })
        }),
        ("negative workers", head(&r, "workers = -1\n") + &peer("a", &a), |e| {
            toml_error(e, "invalid value")
        }),
        (
            "endpoint without port",
            head(&r, "public_endpoint = \"relay\"\n") + &peer("a", &a),
            |e| toml_error(e, "missing port"),
        ),
        (
            "unbracketed IPv6 endpoint",
            head(&r, "public_endpoint = \"2001:db8::1:51820\"\n") + &peer("a", &a),
            |e| toml_error(e, "invalid host"),
        ),
        (
            "bad metrics address",
            head(&r, "metrics_listen = \"localhost\"\n") + &peer("a", &a),
            |e| toml_error(e, "invalid socket address"),
        ),
        ("unknown field", head(&r, "") + &peer("a", &a) + "bogus = 1\n", |e| {
            toml_error(e, "unknown field")
        }),
        ("short key", head(&r, "") + "[[peer]]\nname = \"a\"\npubkey = \"AAAA\"\n", |e| {
            toml_error(e, "key must be 32 bytes")
        }),
    ];
    for (case, text, expected) in cases {
        match Config::parse(&text) {
            Ok(_) => panic!("{case}: accepted"),
            Err(e) => assert!(expected(&e), "{case}: wrong error {e:?}"),
        }
    }
}

#[test]
fn check_config_flag() {
    let dir = std::env::temp_dir().join(format!("wg-relay-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (good, bad) = (dir.join("good.toml"), dir.join("bad.toml"));
    std::fs::write(&good, head(&key(), "") + &peer("main", &key())).unwrap();
    std::fs::write(&bad, "listen = 5").unwrap();
    let run = |p: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_wg-relay"))
            .arg("--check-config")
            .arg("-c")
            .arg(p)
            .env_remove("WG_RELAY_METRICS_LISTEN")
            .output()
            .unwrap()
    };
    let ok = run(&good);
    let out = String::from_utf8_lossy(&ok.stdout);
    assert!(ok.status.success() && out.contains("config OK"), "{out}");
    assert!(out.contains("peer main"), "{out}");
    assert!(out.contains("workers      "), "{out}");
    assert!(out.contains("metrics      off"), "{out}");
    assert!(!run(&bad).status.success());

    // The command line and the environment override metrics_listen, IPv6 and wildcards included.
    let summary = |args: &[&str], env: Option<&str>| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_wg-relay"));
        cmd.arg("--check-config").arg("-c").arg(&good).args(args);
        match env {
            Some(v) => cmd.env("WG_RELAY_METRICS_LISTEN", v),
            None => cmd.env_remove("WG_RELAY_METRICS_LISTEN"),
        };
        String::from_utf8(cmd.output().unwrap().stdout).unwrap()
    };
    let flag = summary(&["--metrics-listen", "[::]:9586"], None);
    assert!(flag.contains("metrics      http://[::]:9586/metrics"), "{flag}");
    let env = summary(&[], Some("0.0.0.0:9586"));
    assert!(env.contains("metrics      http://0.0.0.0:9586/metrics"), "{env}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn print_peer_flag_prints_only_the_relay_peer_section() {
    let dir = std::env::temp_dir().join(format!("wg-relay-peer-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (r, p) = (key(), key());
    let run = |extra: &str| {
        let path = dir.join("relay.toml");
        std::fs::write(&path, head(&r, extra) + &peer("main", &p)).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_wg-relay"))
            .arg("--print-peer")
            .arg("-c")
            .arg(&path)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        String::from_utf8(out.stdout).unwrap()
    };
    let expected = |endpoint: &str| {
        format!(
            "[Peer]\n\
             # wg-relay: registration tunnel only\n\
             PublicKey           = {}\n\
             Endpoint            = {endpoint}\n\
             AllowedIPs          = 10.99.0.254/32\n\
             PersistentKeepalive = 25\n",
            r.id()
        )
    };
    let public = "public_endpoint = \"relay.example.com:51820\"\n";
    assert_eq!(run(public), expected("relay.example.com:51820"));
    assert_eq!(run(""), expected("<relay public address>:51820"));
    assert_eq!(run("listen = \"203.0.113.7:4000\"\n"), expected("203.0.113.7:4000"));
    let out = run("tunnel_ip = \"10.1.2.3\"\n");
    assert!(out.contains("AllowedIPs          = 10.1.2.3/32\n"), "{out}");
    assert!(!out.contains("PrivateKey"), "{out}");
    std::fs::remove_dir_all(&dir).ok();
}
