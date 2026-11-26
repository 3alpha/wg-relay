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

    let extra = "listen = \"127.0.0.1:5000\"\ntunnel_ip = \"10.0.0.1\"\n\
                 handshake_rate_per_ip = \"60/m\"\nworkers = 3\n";
    let config = Config::parse(&(head(&r, extra) + &peer("home", &a))).unwrap();
    assert_eq!(
        (config.listen.to_string(), config.tunnel_ip.to_string(), config.handshake_rate.per_sec()),
        ("127.0.0.1:5000".into(), "10.0.0.1".into(), 1.0)
    );
    assert_eq!(config.workers.get(), 3);
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
            .output()
            .unwrap()
    };
    let ok = run(&good);
    let out = String::from_utf8_lossy(&ok.stdout);
    assert!(ok.status.success() && out.contains("config OK"), "{out}");
    assert!(out.contains("peer main"), "{out}");
    assert!(out.contains("workers      "), "{out}");
    assert!(!run(&bad).status.success());
    std::fs::remove_dir_all(&dir).ok();
}
