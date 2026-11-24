//! Config validation and the `--check-config` flag.
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test setup panics on failure")]

mod common;
use common::*;
use std::process::Command;
use wg_relay::config::{Config, Gate, Role};

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
    let text =
        head(&r, "") + &server("main", &s1) + &server("backup", &s2) + &client("laptop", &c, "\"backup\"");
    let cfg = Config::parse(&text).unwrap();
    assert_eq!(cfg.listen.to_string(), "0.0.0.0:51820");
    assert_eq!(cfg.gate, Gate::Register, "safest gate is the default");
    assert_eq!(cfg.handshake_rate.per_sec(), 10.0);
    assert_eq!(cfg.private_key.public_key(), r.id());
    let laptop = cfg.peers.iter().find(|p| p.name == "laptop").unwrap();
    assert_eq!((laptop.role, laptop.servers.clone()), (Role::Client, vec![s2.id()]));
    assert!(cfg.warnings().is_empty());

    let cfg = Config::parse(
        &(head(&r, "client_gate = \"none\"\nhandshake_rate_per_ip = \"60/m\"\n") + &server("main", &s1)),
    )
    .unwrap();
    assert_eq!((cfg.gate, cfg.handshake_rate.per_sec()), (Gate::None, 1.0));
    assert!(cfg.warnings().is_empty(), "clients are optional with gate none");
    let cfg = Config::parse(&(head(&r, "client_gate = \"response\"\n") + &server("main", &s1))).unwrap();
    assert_eq!(cfg.warnings().len(), 1, "no clients with gate response");
}

#[test]
fn rejects_bad_configs() {
    let (r, a, b) = (key(), key(), key());
    let bad = [
        head(&r, ""),                                                  // no server
        head(&r, "") + &server("a", &a) + &server("a", &b),            // duplicate name
        head(&r, "") + &server("a", &a) + &client("b", &a, "\"a\""),   // duplicate key
        head(&r, "") + &server("a", &a) + &client("b", &b, "\"zzz\""), // unknown server
        head(&r, "") + &server("a", &a) + &client("b", &b, "\"a\"").replace("servers = [\"a\"]\n", ""), // no servers
        head(&r, "client_gate = \"strict\"\n") + &server("a", &a), // bad gate
        head(&r, "handshake_rate_per_ip = \"0/s\"\n") + &server("a", &a), // bad rate
        head(&r, "") + &server("a", &a) + "bogus = 1\n",           // unknown field
        head(&r, "") + "[[server]]\nname = \"a\"\npubkey = \"AAAA\"\n", // short key
        head(&r, "") + &server("me", &r),                          // relay's own key
    ];
    for s in &bad {
        assert!(Config::parse(s).is_err(), "accepted:\n{s}");
    }
}

#[test]
fn check_config_flag() {
    let dir = std::env::temp_dir().join(format!("wg-relay-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (good, bad) = (dir.join("good.toml"), dir.join("bad.toml"));
    let (s, c) = (key(), key());
    std::fs::write(&good, head(&key(), "") + &server("main", &s) + &client("laptop", &c, "\"main\""))
        .unwrap();
    std::fs::write(&bad, "listen = 5").unwrap();
    let run = |p: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_wg-relay")).arg("--check-config").arg("-c").arg(p).output().unwrap()
    };
    let ok = run(&good);
    let out = String::from_utf8_lossy(&ok.stdout);
    assert!(ok.status.success() && out.contains("config OK") && out.contains("Register"), "{out}");
    assert!(out.contains("client laptop"), "{out}");
    assert!(!run(&bad).status.success());
    std::fs::remove_dir_all(&dir).ok();
}
