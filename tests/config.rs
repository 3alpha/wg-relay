//! Config validation and the `--check-config` flag.
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test setup panics on failure")]

mod common;
use common::*;
use std::process::Command;
use wg_relay::config::{Config, ConfigError, Peer};

fn head(r: &Key, extra: &str) -> String {
    format!("private_key = \"{}\"\n{extra}", b64_sk(r))
}
fn peer(name: &str, k: &Key) -> String {
    format!("[[peer]]\nname = \"{name}\"\npubkey = \"{}\"\n", b64(&k.pk))
}

#[test]
fn peers_and_defaults() {
    let (r, a, b) = (key(), key(), key());
    let cfg = Config::parse(&(head(&r, "") + &peer("home", &a) + &peer("office", &b))).unwrap();
    assert_eq!(cfg.listen.to_string(), "0.0.0.0:51820");
    assert_eq!(cfg.tunnel_ip.to_string(), "10.99.0.254");
    assert_eq!(cfg.handshake_rate.per_sec(), 10.0);
    assert_eq!(cfg.private_key.public_key(), r.id());
    assert_eq!(
        cfg.peers,
        vec![
            Peer { name: "home".into(), pubkey: a.id() },
            Peer { name: "office".into(), pubkey: b.id() },
        ]
    );

    let extra =
        "listen = \"127.0.0.1:5000\"\ntunnel_ip = \"10.0.0.1\"\nhandshake_rate_per_ip = \"60/m\"\n";
    let cfg = Config::parse(&(head(&r, extra) + &peer("home", &a))).unwrap();
    assert_eq!(
        (cfg.listen.to_string(), cfg.tunnel_ip.to_string(), cfg.handshake_rate.per_sec()),
        ("127.0.0.1:5000".into(), "10.0.0.1".into(), 1.0)
    );
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
    assert!(!run(&bad).status.success());
    std::fs::remove_dir_all(&dir).ok();
}
