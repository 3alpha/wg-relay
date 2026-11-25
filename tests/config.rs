//! Config validation and the `--check-config` flag.
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test setup panics on failure")]

mod common;
use common::*;
use std::process::Command;
use wg_relay::config::{Config, ConfigError, ConfigWarning, Gate, Role};

fn head(r: &Key, extra: &str) -> String {
    format!("private_key = \"{}\"\ntunnel_ip = \"10.99.0.254\"\n{extra}", b64_sk(r))
}
fn server(name: &str, k: &Key) -> String {
    format!("[[server]]\nname = \"{name}\"\npubkey = \"{}\"\n", b64(&k.pk))
}
fn client(name: &str, k: &Key, servers: &str) -> String {
    format!("[[client]]\nname = \"{name}\"\npubkey = \"{}\"\nservers = [{servers}]\n", b64(&k.pk))
}

#[test]
fn roles_defaults_and_acl() {
    let (r, s1, s2, c) = (key(), key(), key(), key());
    let text = head(&r, "")
        + &server("main", &s1)
        + &server("backup", &s2)
        + &client("laptop", &c, "\"backup\"");
    let cfg = Config::parse(&text).unwrap();
    assert_eq!(cfg.listen.to_string(), "0.0.0.0:51820");
    assert_eq!(cfg.gate, Gate::Response, "the stricter gate is the default");
    assert_eq!(cfg.handshake_rate.per_sec(), 10.0);
    assert_eq!(cfg.private_key.public_key(), r.id());
    let laptop = cfg.peers.iter().find(|p| p.name == "laptop").unwrap();
    assert_eq!(laptop.role, Role::Client { servers: vec![s2.id()] });
    assert!(cfg.warnings().is_empty());

    let cfg = Config::parse(
        &(head(&r, "client_gate = \"none\"\nhandshake_rate_per_ip = \"60/m\"\n")
            + &server("main", &s1)),
    )
    .unwrap();
    assert_eq!((cfg.gate, cfg.handshake_rate.per_sec()), (Gate::None, 1.0));
    assert_eq!(cfg.warnings(), vec![], "clients are optional with gate none");
    let cfg =
        Config::parse(&(head(&r, "client_gate = \"response\"\n") + &server("main", &s1))).unwrap();
    assert_eq!(cfg.warnings(), vec![ConfigWarning::NoClients { gate: Gate::Response }]);
    let lonely = client("lonely", &key(), "");
    let cfg = Config::parse(&(head(&r, "") + &server("main", &s1) + &lonely)).unwrap();
    assert_eq!(cfg.warnings(), vec![ConfigWarning::ClientWithoutServers { name: "lonely".into() }]);
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
        ("no server", head(&r, ""), |e| matches!(e, ConfigError::NoServer)),
        (
            "duplicate name",
            head(&r, "") + &server("a", &a) + &server("a", &b),
            |e| matches!(e, ConfigError::DuplicateName { name } if name == "a"),
        ),
        (
            "duplicate key",
            head(&r, "") + &server("a", &a) + &client("b", &a, "\"a\""),
            |e| matches!(e, ConfigError::DuplicatePubkey { name } if name == "b"),
        ),
        (
            "unknown server",
            head(&r, "") + &server("a", &a) + &client("b", &b, "\"zzz\""),
            |e| matches!(e, ConfigError::UnknownServer { client, server } if client == "b" && server == "zzz"),
        ),
        (
            "relay's own key",
            head(&r, "") + &server("me", &r),
            |e| matches!(e, ConfigError::RelayKeyReused { name } if name == "me"),
        ),
        (
            "client without servers",
            head(&r, "")
                + &server("a", &a)
                + &client("b", &b, "\"a\"").replace("servers = [\"a\"]\n", ""),
            |e| toml_error(e, "missing field `servers`"),
        ),
        ("removed gate", head(&r, "client_gate = \"register\"\n") + &server("a", &a), |e| {
            toml_error(e, "unknown variant")
        }),
        ("bad gate", head(&r, "client_gate = \"strict\"\n") + &server("a", &a), |e| {
            toml_error(e, "unknown variant")
        }),
        ("bad rate", head(&r, "handshake_rate_per_ip = \"0/s\"\n") + &server("a", &a), |e| {
            toml_error(e, "rate must be positive")
        }),
        ("unknown field", head(&r, "") + &server("a", &a) + "bogus = 1\n", |e| {
            toml_error(e, "unknown field")
        }),
        ("short key", head(&r, "") + "[[server]]\nname = \"a\"\npubkey = \"AAAA\"\n", |e| {
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
    let (s, c) = (key(), key());
    std::fs::write(
        &good,
        head(&key(), "") + &server("main", &s) + &client("laptop", &c, "\"main\""),
    )
    .unwrap();
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
    assert!(ok.status.success() && out.contains("config OK") && out.contains("Response"), "{out}");
    assert!(out.contains("client laptop"), "{out}");
    assert!(!run(&bad).status.success());
    std::fs::remove_dir_all(&dir).ok();
}
