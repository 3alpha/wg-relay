# wg-relay

A UDP relay that lets **standard, unmodified WireGuard** clients reach a
WireGuard **server that sits behind NAT**. This works with kernel `wg`,
wireguard-go and the mobile apps. Neither side needs a public address or a port
forward. The relay forwards encrypted WireGuard datagrams byte-for-byte. It
never holds client↔server keys, so it cannot read or modify that traffic. It
decides who may talk to whom from the public keys in each handshake's mac1 field
and from addresses it has authenticated.

```
 server ──NAT──┐                       ┌──NAT── client "laptop"
   wg0         │      UDP :51820       │         wg0
   peer relay  ├────►  wg-relay  ◄─────┤   peer server (Endpoint=relay)
   peer laptop─┘   (forwards           ├──NAT── client "phone"
   peer phone      ciphertext only)    │
   (Endpoint=relay for every peer)     └──NAT── stranger (dropped)
```

**New here? Read [How wg-relay works](docs/how-it-works.md)**: a guided tour
with diagrams of every packet path, the state the relay keeps, the client gates,
reload, roaming and the security model.

## Build, run, test

```sh
cargo build --release
./target/release/wg-relay --check-config -c relay.toml   # validate, print roles and warnings
RUST_LOG=info ./target/release/wg-relay -c relay.toml    # RUST_LOG=wg_relay=debug logs every reject
kill -HUP $(pidof wg-relay)                              # reload relay.toml
WG_RELAY_CONFIG=/etc/wg-relay.toml ./target/release/wg-relay   # every flag also reads an env var (see --help)

cargo test                                               # unit and in-process end-to-end tests
cargo build --bins --examples && sudo tests/netns.sh     # namespace integration test, both gate modes
```

`tests/netns.sh` needs root, the `wireguard` kernel module, `iproute2`,
`wireguard-tools`, `iptables`, `tcpdump` and `ping`. Set `MODES="none"` to
run a single mode. Without root on the host, a privileged container works:

```sh
cargo build --bins --examples
docker run --rm --privileged -v "$PWD":/src:ro -w /src debian:trixie-slim bash -c \
  'apt-get update -qq && apt-get install -y -qq iproute2 wireguard-tools iptables tcpdump iputils-ping >/dev/null && tests/netns.sh'
```

The test runs a server, two clients the server knows and a stranger. The
stranger knows the server's public key but is not one of the server's peers.
Each host is behind its own MASQUERADE NAT and runs kernel WireGuard. There are
two runs: `none`, where `relay.toml` lists **only the server**, and `response`,
where it also lists the two clients. Each run asserts that:

1. the server registers with the relay;
2. both clients ping the server;
3. the stranger gets nothing through. A `tcpdump` on the server's LAN, decrypted
   offline with the server key by `examples/pcap_check.rs --initiators`, shows
   its handshakes reach the server, which drops them;
4. pings still work after **client-initiated** rekeys, and in `response` also
   after a **server-initiated** rekey (the server removes and re-adds a client);
5. in `response`, removing a client from `relay.toml` and sending `SIGHUP` cuts
   it off immediately, while the other client keeps working;
6. in the relay-side capture, forwarded handshakes cannot be opened with the
   relay's private key (the server's key opens them), forwarding is
   byte-identical, and the ping payload never appears on the wire.

## Roles and gate modes

```toml
tunnel_ip = "10.99.0.254"
client_gate = "response"        # "none" | "response"  (default: response)
handshake_rate_per_ip = "10/s"  # or "600/m"; the burst is 2 seconds' worth

[[server]]                      # at least one; servers always register
name = "main"
pubkey = "<base64>"

[[client]]                      # optional with "none", required with "response"
name = "laptop"
pubkey = "<base64>"
servers = ["main"]              # which servers this client may reach
```

In both modes anyone may send a handshake to a registered server (rate-limited
per source IP), and clients never talk to the relay directly. The modes differ in
when a session may open:

| `client_gate` | Relay allowlists | Session opens when |
|---|---|---|
| `none` | servers only | the server responds; its own peer list is the only gate |
| `response` | servers and clients | the server's response is for an **allowlisted client permitted to reach that server** |

* **`none`.** The relay checks only that the server is registered. Access
  control is left to the server's peer list, so revoking a client means removing
  it from the server. Any clients you do list also get server-initiated
  handshakes (see Limitations).
* **`response`.** A server's handshake response carries a mac1 keyed to the
  public key of the client the server just authenticated. The relay only lets
  the session open if that key is an allowlisted client allowed to reach that
  server. This adds a second gate on the relay, which you can revoke with SIGHUP
  without touching the server.

In both modes a stranger's initiation reaches the server, which drops it because
the stranger is not one of its peers.

## Design

One UDP socket carries two kinds of traffic.

### Registration (servers only)

Each server lists the relay as a `[Peer]` with `AllowedIPs = <tunnel_ip>/32` and
`PersistentKeepalive = 25`. The relay runs one `boringtun::noise::Tunn` per
server.

* An initiation whose mac1 is keyed to the **relay's** public key is for the
  relay. `parse_handshake_anon` decrypts the sender's static key. Keys that are
  not allowlisted are rejected (`registration_unknown_key`), and so are clients
  (`client_registration_refused`). A server's initiation goes to its `Tunn`,
  which performs the full handshake, including replay protection.
* After **every packet that authenticates** on a server's tunnel (a handshake,
  data or a keepalive, but never a cookie), the relay sets
  `registry[server] = src_addr`. If the address changed (roaming), every session
  table entry using the old address is rewritten. Entries expire after 180 s.
* **The relay's indexes never collide with forwarded sessions.** Each relay
  tunnel owns a random 24-bit index prefix, so it uses 256 indexes. A new prefix
  is never one that a live session is using, and any forwarded handshake that
  picks an index inside a relay prefix is dropped (`reserved_index`), so the peer
  retries with a new random index. Packets in a relay prefix go only to that
  relay tunnel.
* The relay answers ICMP echo to `tunnel_ip` (`ping 10.99.0.254` from a server
  checks its registration).

### Session table

`receiver_idx → { dest_addr, expected_src_addr, open, last_seen }`, plus the
server's and (once known) the client's key, which are used to revoke sessions on
reload. **Every type 2, 3 and 4 packet must arrive from `expected_src_addr`.**
Entries expire after 200 s idle. On an index collision the newest entry wins and
a warning is logged.

### Forwarding rules

Every initiation is rate-limited per source IP first.

**Type 1, initiation** (`sender_idx` must not be in a relay prefix):

* **mac1 matches a registered server S.** Accepted from any source. The relay
  records `idx[sender] = {dest: src, expected_src: addr(S), open: false}` and
  forwards to S.
* **mac1 matches a listed client C** (a server-initiated handshake or rekey). The
  source must be a registered server S that C may reach, and C's address must be
  known, i.e. learned from S's last accepted response to C. The relay records
  `idx[sender]` as pending and forwards to C.
* Otherwise the packet is dropped (`no_mac1_match`).

**Type 2, response** (it must match a pending entry and come from its `expected_src`):

* **From a server.** Match mac1 against the listed client keys. A match with a
  client C that may reach that server opens the session and records `addr[C]`.
  With no match, the packet is dropped in `response` mode
  (`response_unknown_client`), and in `none` mode it is forwarded anyway and the
  session opens.
* **From a client.** mac1 must match the server's key (`response_not_for_server`).
* Either way, the initiator's entry becomes `open` and an open entry is created
  for the responder's `sender_idx`.

**Types 3 and 4** (cookie reply and data) are forwarded only from
`expected_src`. Data requires an `open` session. A cookie reply may also pass on
a pending one, so a server under load can answer an initiation.

The relay never sends cookie replies (or anything else) for forwarded traffic.
Datagrams are parsed with explicit size checks: exact sizes for types 1–3, at
least 32 B for data, and the reserved bytes must be zero. Nothing on the
forwarding path can panic. This is covered by a 20 000-case mutation test across
both gate modes.

### Rejects and metrics

Every rejected datagram increments a per-reason counter and logs
`reject reason=<reason> src=<addr>` at `debug` level. Per-packet logs are kept at
debug because otherwise anyone could flood the log. Counters are logged every
60 s and at shutdown, for example
`rx=76 forwarded=66 … reject.server_not_registered=1 reject.unknown_index=4`.

| Reason | Meaning |
|---|---|
| `malformed` | wrong size, type or reserved bytes |
| `rate_limited` | the source IP exceeded `handshake_rate_per_ip` |
| `reserved_index` | a forwarded handshake picked an index in the relay's range |
| `no_mac1_match` | the initiation is not for any server, client or the relay |
| `server_not_registered` | the target server has no current registration |
| `acl` | the client may not reach that server |
| `loop` | the initiation came from the target's own address |
| `rekey_not_from_server` | a client-addressed initiation came from something other than a registered server |
| `client_addr_unknown` | server→client initiation, but the client has no accepted response yet |
| `unknown_index` | no live session for `receiver_idx` |
| `wrong_source` | the packet is not from the session's `expected_src_addr` |
| `response_unknown_client` | the server answered a key that is not allowlisted for it |
| `response_not_for_server` | the client's response is not keyed to the session's server |
| `session_not_open` | data on a session whose handshake has not completed |
| `registration_unknown_key` | the relay-bound handshake came from a key that is not allowlisted |
| `client_registration_refused` | a client tried to register; only servers register |
| `tunnel_auth_failed` | a registration-tunnel packet failed authentication |

### Reload (SIGHUP)

`relay.toml` is re-read and validated. If it is invalid, the current config stays
in effect and an error is logged. Changes to `listen` and `private_key` need a
restart. Everything else applies immediately:

* A **removed key** loses every session it is part of, and a removed server
  also loses its registration and relay tunnel. Its next packet is rejected (`unknown_index`).
* A client whose `servers` list no longer includes a server loses its sessions
  with that server.
* Switching from `none` to `response` drops open sessions whose client was
  never identified (unlisted clients).

## Node configuration

Every peer on every host uses the relay as its `Endpoint`. Both sides keep a
single wg interface.

**Server** (behind NAT, `10.99.0.1`):

```ini
[Interface]
PrivateKey = <server private key>
Address    = 10.99.0.1/24
ListenPort = 51820            # any port; no port forward needed

# The relay: registration tunnel only
[Peer]
PublicKey           = <relay public key>
Endpoint            = relay.example.com:51820
AllowedIPs          = 10.99.0.254/32
PersistentKeepalive = 25

# One block per client
[Peer]
PublicKey           = <laptop public key>
Endpoint            = relay.example.com:51820
AllowedIPs          = 10.99.0.11/32
PersistentKeepalive = 25
```

**Client** (`10.99.0.11`):

```ini
[Interface]
PrivateKey = <laptop private key>
Address    = 10.99.0.11/32

[Peer]
PublicKey           = <server public key>
Endpoint            = relay.example.com:51820
AllowedIPs          = 10.99.0.1/32      # or the server's LAN / 0.0.0.0/0
PersistentKeepalive = 25
```

Clients do not list the relay as a peer; to them it is just the server's address.

Because all of a host's peers share one endpoint, all its traffic uses one NAT
mapping, which is the mapping its handshakes (and, for a server, its
registration) come from.
WireGuard identifies peers by key and index, not by endpoint, so sharing an
endpoint is fine. Keep `PersistentKeepalive` so NAT mappings and registrations
stay fresh.

## Threat model

**What the relay can never do:** decrypt, forge or modify client↔server traffic.
It holds no session keys, and any change makes the packet fail authentication.
Its private key only opens the registration tunnels, which expose nothing beyond
the relay's own `/32`.

**What the relay (or someone who controls it) sees and can do:**

* **Who talks to whom.** mac1 reveals the target's public key, and the server's
  response reveals the client's key.
* **Timing, sizes and volume** of all traffic, plus every host's public IP and port.
* **Drop, delay or reorder** packets. Replays are rejected by WireGuard. The
  relay can always deny service.

**What it protects against:**

* **Open reflector / amplification.** The relay only sends to addresses taken
  from authenticated server registrations or from a session's handshake. Replies
  are never larger than requests, and forwarded traffic never gets
  relay-generated replies. Unregistered sources reach only the rate-limited
  paths: registration (one X25519 operation) and initiations to servers.
* **Strangers.** Their initiations reach the server, which drops them because
  they are not its peers. In `response` mode the relay additionally refuses to
  open a session unless the server authenticated an allowlisted key.
* **Cross-session injection and spoofed responses.** Every non-initiation packet
  must come from the address recorded for that session and index.
* **Revocation.** Removing a key and sending SIGHUP takes effect at once, without
  waiting for sessions to expire.

## Limitations

* **A client that changes network** (Wi-Fi to cellular, NAT rebinding) **loses
  data until it re-handshakes, about 5–15 s.** Its packets now come from a new
  address, which no longer matches `expected_src_addr`, so they are dropped
  (`wrong_source`). WireGuard starts a new handshake on its own once it stops
  hearing back (keepalive timeout plus rekey timeout), and the new session then
  works normally. A server that moves re-registers on its next authenticated
  packet to the relay and its sessions are migrated, but data sent in the
  meantime is lost.
* **Both modes trust the server's peer list** for authentication, and strangers'
  handshakes reach the server (it drops them). The relay learns a client's address from the server's
  response, so an on-path attacker who replays a client's fresh initiation from
  another address first can make that handshake fail. That is a denial of
  service only.
* **Unlisted clients (`none` mode)** cannot receive server-initiated handshakes:
  the relay cannot tell which client such a handshake is for. Clients normally
  start the handshake and keep it fresh with `PersistentKeepalive`, so this
  rarely matters. When the server must send first (e.g. right after it
  restarts), that traffic waits until the client sends something. List a client
  to give it server-initiated handshakes.
* **The per-IP initiation limit is shared** by all hosts behind one NAT address.
  Many distributed sources can still make the relay do X25519 work on the
  registration path, and send junk handshakes to the server.
* **Two servers cannot register from the same `ip:port`.** The newest claimant wins
  and a warning is logged.
* **Index collisions** between independent sessions (probability 2⁻³² per pair)
  break the older session until its next rekey.
* **Single-threaded**, with a linear mac1 scan over servers or clients per
  handshake. That is fine for thousands of keys.
* The ICMP responder is IPv4-only, and metrics are logged rather than exported.

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
