# wg-relay reference

The exact rules wg-relay follows and its known limitations. For a guided tour with diagrams, read [How wg-relay works](how-it-works.md). For setup, see the [README](../README.md).

## Design

One UDP socket carries two kinds of traffic: registration tunnels with servers, and forwarded traffic between servers and clients.

### Registration (servers only)

Each server lists the relay as a `[Peer]` with `AllowedIPs = <tunnel_ip>/32` and `PersistentKeepalive = 25`. The relay runs one `boringtun::noise::Tunn` per server.

* An initiation whose mac1 is keyed to the **relay's** public key is for the relay. `parse_handshake_anon` decrypts the sender's static key. Keys that are not allowlisted are rejected (`registration_unknown_key`), and so are clients (`client_registration_refused`). A server's initiation goes to its `Tunn`, which performs the full handshake, including replay protection.
* After **every packet that authenticates** on a server's tunnel (data or a keepalive; never a bare initiation, which could be a replay, and never a cookie), the relay sets `registry[server] = src_addr`. If the address changed (roaming), every session table entry using the old address is rewritten. Entries expire after 180 s.
* **The relay's indexes never collide with forwarded sessions.** Each relay tunnel owns a random 24-bit index prefix, so it uses 256 indexes. A new prefix is never one that a live session is using, and any forwarded handshake that picks an index inside a relay prefix is dropped (`reserved_index`), so the peer retries with a new random index. Packets in a relay prefix go only to that relay tunnel.
* The relay answers ICMP echo to `tunnel_ip` (`ping 10.99.0.254` from a server checks its registration).

### Session table

`receiver_idx → { dest_addr, expected_src_addr, open, last_seen }`, plus the server's and (once known) the client's key, which are used to revoke sessions on reload. **Every type 2, 3 and 4 packet must arrive from `expected_src_addr`.** Open entries expire after 200 s idle, pending ones (an initiation without an accepted response) after 10 s. A handshake that picks an index held by a live entry of a different address pair is dropped (`index_in_use`), so nobody can take over an index someone else is using; the peer retries with a new index.

### Forwarding rules

Every initiation is rate-limited per source IP first.

**Type 1, initiation** (`sender_idx` must not be in a relay prefix):

* **mac1 matches a registered server S.** Accepted from any source. The relay records `idx[sender] = {dest: src, expected_src: addr(S), open: false}` and forwards to S.
* **mac1 matches a listed client C** (a server-initiated handshake or rekey). The source must be a registered server S that C may reach, and C's address must be known, i.e. learned from S's last accepted response to C. The relay records `idx[sender]` as pending and forwards to C.
* Otherwise the packet is dropped (`no_mac1_match`). Client keys are only tried when the source is a registered server.

**Type 2, response** (it must match a pending entry and come from its `expected_src`):

* **From a server.** Match mac1 against the listed client keys. A match with a client C that may reach that server opens the session and records `addr[C]`. With no match, the packet is dropped in `response` mode (`response_unknown_client`), and in `none` mode it is forwarded anyway and the session opens.
* **From a client.** mac1 must match the server's key (`response_not_for_server`).
* Either way, the initiator's entry becomes `open` and an open entry is created for the responder's `sender_idx`.

**Types 3 and 4** (cookie reply and data) are forwarded only from `expected_src`. Data requires an `open` session. A cookie reply may also pass on a pending one, so a server under load can answer an initiation.

The relay never sends cookie replies (or anything else) for forwarded traffic. Datagrams are parsed with explicit size checks: exact sizes for types 1–3, at least 32 B for data, and the reserved bytes must be zero. Nothing on the forwarding path can panic. This is covered by a 20 000-case mutation test across both gate modes.

## Rejects and metrics

Every rejected datagram increments a per-reason counter and logs `reject reason=<reason> src=<addr>` at `debug` level. Per-packet logs are kept at debug because otherwise anyone could flood the log. Counters are logged every 60 s and at shutdown, for example `rx=76 forwarded=66 … reject.server_not_registered=1 reject.unknown_index=4`.

| Reason | Meaning |
|---|---|
| `malformed` | wrong size, type or reserved bytes |
| `rate_limited` | the source IP exceeded `handshake_rate_per_ip` |
| `reserved_index` | a forwarded handshake picked an index in the relay's range |
| `no_mac1_match` | the initiation is not for any server or the relay, and either its source is not a registered server or it is not for any listed client |
| `server_not_registered` | the target server has no current registration |
| `acl` | the client may not reach that server |
| `loop` | the initiation came from the target's own address |
| `client_addr_unknown` | server→client initiation, but the client has no accepted response yet |
| `index_in_use` | the handshake's `sender_idx` belongs to a live session of another address pair |
| `unknown_index` | no live session for `receiver_idx` |
| `wrong_source` | the packet is not from the session's `expected_src_addr` |
| `response_unknown_client` | the server answered a key that is not allowlisted for it |
| `response_not_for_server` | the client's response is not keyed to the session's server |
| `session_not_pending` | a response to a handshake that was already answered |
| `session_not_open` | data on a session whose handshake has not completed |
| `registration_unknown_key` | the relay-bound handshake came from a key that is not allowlisted |
| `client_registration_refused` | a client tried to register; only servers register |
| `tunnel_auth_failed` | a registration-tunnel packet failed authentication |

## Reload (SIGHUP)

`relay.toml` is re-read and validated. If it is invalid, the current config stays in effect and an error is logged. Changes to `listen` and `private_key` need a restart. Everything else applies immediately:

* A **removed key** loses every session it is part of, and a removed server also loses its registration and relay tunnel. Its next packet is rejected (`unknown_index`).
* A client whose `servers` list no longer includes a server loses its sessions with that server.
* Switching from `none` to `response` drops open sessions whose client was never identified (unlisted clients).

## Limitations

* **A client that changes network** (Wi-Fi to cellular, NAT rebinding) **loses data until it re-handshakes, about 5–15 s.** Its packets now come from a new address, which no longer matches `expected_src_addr`, so they are dropped (`wrong_source`). WireGuard starts a new handshake on its own once it stops hearing back (keepalive timeout plus rekey timeout), and the new session then works normally. A server that moves re-registers on its next authenticated packet to the relay and its sessions are migrated, but data sent in the meantime is lost.
* **Both modes trust the server's peer list** for authentication, and strangers' handshakes reach the server (it drops them). The relay learns a client's address from the server's response, so an on-path attacker who replays a client's fresh initiation from another address first can make that handshake fail. That is a denial of service only.
* **Unlisted clients (`none` mode)** cannot receive server-initiated handshakes: the relay cannot tell which client such a handshake is for. Clients normally start the handshake and keep it fresh with `PersistentKeepalive`, so this rarely matters. When the server must send first (e.g. right after it restarts), that traffic waits until the client sends something. List a client to give it server-initiated handshakes.
* **WireGuard's cookie defence is weaker behind the relay.** A server under load binds cookies to the sender's address, but it sees every packet coming from the relay, so one cookie obtained through the relay is valid for initiations from any (even spoofed) source. The relay's per-IP rate limit is then the only brake. See [How it works, section 3.5](how-it-works.md#35-under-load-cookies-and-mac2).
* **The per-IP initiation limit is charged before any check**, so someone who can spoof a peer's source IP can use up that peer's budget and delay its handshakes (for a server, including its re-registration).
* **The per-IP initiation limit is shared** by all hosts behind one NAT address. Many distributed sources can still make the relay do X25519 work on the registration path, and send junk handshakes to the server.
* **Two servers cannot register from the same `ip:port`.** The newest claimant wins and a warning is logged.
* **Index collisions** between independent sessions (probability 2⁻³² per pair) make the newer handshake fail once (`index_in_use`); its retry uses a new index.
* **Single-threaded**, with a linear mac1 scan over servers or clients per handshake. That is fine for thousands of keys.
* The ICMP responder is IPv4-only, and metrics are logged rather than exported.

## The namespace integration test

`tests/netns.sh` needs root, the `wireguard` kernel module, `iproute2`, `wireguard-tools`, `iptables`, `tcpdump` and `ping`. Set `MODES="none"` to run a single mode. Without root on the host, a privileged container works:

```sh
cargo build --bins --examples
docker run --rm --privileged -v "$PWD":/src:ro -w /src debian:trixie-slim bash -c \
  'apt-get update -qq && apt-get install -y -qq iproute2 wireguard-tools iptables tcpdump iputils-ping >/dev/null && tests/netns.sh'
```

The test runs a server, two clients the server knows and a stranger. The stranger knows the server's public key but is not one of the server's peers. Each host is behind its own MASQUERADE NAT and runs kernel WireGuard. There are two runs: `none`, where `relay.toml` lists **only the server**, and `response`, where it also lists the two clients. Each run asserts that:

1. the server registers with the relay;
2. both clients ping the server;
3. the stranger gets nothing through. A `tcpdump` on the server's LAN, decrypted offline with the server key by `examples/pcap_check.rs --initiators`, shows its handshakes reach the server, which drops them;
4. pings still work after **client-initiated** rekeys, and in `response` also after a **server-initiated** rekey (the server removes and re-adds a client);
5. in `response`, removing a client from `relay.toml` and sending `SIGHUP` cuts it off immediately, while the other client keeps working;
6. in the relay-side capture, forwarded handshakes cannot be opened with the relay's private key (the server's key opens them), forwarding is byte-identical, and the ping payload never appears on the wire.

## Code layout

| File | Purpose |
|---|---|
| `src/packet/` | wire-format parsing, size checks, mac1, `SessionIdx` |
| `src/tables.rs` | registry, session table, per-IP token bucket |
| `src/relay/` | `Relay::handle` (no I/O); `forward.rs` gate rules, `registration.rs` server tunnels, `reload.rs`, `reason.rs`, `metrics.rs` |
| `src/config/` | `relay.toml` parsing and validation, `Rate`, `--check-config` summary |
| `src/main.rs` | parse the CLI, set up logging, report errors |
| `src/app.rs` | clap `Cli`, tokio socket loop, timers, SIGHUP/SIGTERM |
| `src/key/` | `PeerKey` / `PrivateKey` base64 newtypes |
| `src/error.rs` | `AppError` and the `Report` error-chain printer |
