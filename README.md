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

## Build, run, test

```sh
cargo build --release
./target/release/wg-relay --check-config -c relay.toml   # validate, print roles and warnings
RUST_LOG=info ./target/release/wg-relay -c relay.toml    # RUST_LOG=wg_relay=debug logs every reject
kill -HUP $(pidof wg-relay)                              # reload relay.toml

cargo test                                               # unit and in-process end-to-end tests
cargo build --bins --examples && sudo tests/netns.sh     # namespace integration test, all gate modes
```

`tests/netns.sh` needs root, the `wireguard` kernel module, `iproute2`,
`wireguard-tools`, `iptables`, `tcpdump` and `ping`. Set `MODES="register"` to
run a single mode. Without root on the host, a privileged container works:

```sh
cargo build --bins --examples
docker run --rm --privileged -v "$PWD":/src:ro -w /src debian:trixie-slim bash -c \
  'apt-get update -qq && apt-get install -y -qq iproute2 wireguard-tools iptables tcpdump iputils-ping >/dev/null && tests/netns.sh'
```

The test runs a server, two allowlisted clients and a stranger. The stranger
knows the server's public key but is not allowlisted. Each host is behind its own
MASQUERADE NAT and runs kernel WireGuard. For **each** gate mode the test
asserts that:

1. the server registers (and the clients too, in `register` mode);
2. both allowlisted clients ping the server;
3. the stranger gets nothing through. In `register` mode, a `tcpdump` on the
   server's LAN, decrypted offline with the server key by
   `examples/pcap_check.rs --initiators`, proves that **none of the stranger's
   handshakes reach the server**. In `none` and `response` modes the same check
   finds them, which shows the method works, and the server drops them;
4. pings still work after a **server-initiated** rekey (the server removes and
   re-adds a client) and a **client-initiated** rekey;
5. in `response` and `register` modes, removing a client from `relay.toml` and
   sending `SIGHUP` cuts it off immediately, while the other client keeps working;
6. in the relay-side capture, forwarded handshakes cannot be opened with the
   relay's private key (the server's key opens them), forwarding is
   byte-identical, and the ping payload never appears on the wire.

## Roles and gate modes

```toml
tunnel_ip = "10.99.0.254"
client_gate = "register"        # "none" | "response" | "register"  (default: register)
handshake_rate_per_ip = "10/s"  # or "600/m"; the burst is 2 seconds' worth

[[server]]                      # at least one; servers always register
name = "main"
pubkey = "<base64>"

[[client]]                      # optional with "none", required otherwise
name = "laptop"
pubkey = "<base64>"
servers = ["main"]              # which servers this client may reach
```

| `client_gate` | Who may send a handshake to a server | Session opens when | Client registers with relay |
|---|---|---|---|
| `none` | anyone (rate-limited) | the server responds (to anyone) | no |
| `response` | anyone (rate-limited) | the server's response is for an **allowlisted client permitted to reach that server** | no |
| `register` | only the **registered address** of an allowlisted client permitted to reach that server | as `response`, and the client named in the response must be registered at that address | yes |

* **`none`.** The relay checks only that the server is registered. Access
  control is left to the server's own peer list. Clients that are listed still
  get server-initiated rekeys.
* **`response`.** A server's handshake response carries a mac1 keyed to the
  public key of the client the server just authenticated. The relay only lets
  the session open if that key is an allowlisted client allowed to reach that
  server. No client-side change is needed. However, a stranger's initiation does
  reach the server, which drops it.
* **`register`.** Clients also list the relay as a peer, as servers do. Their
  handshakes are dropped at the relay unless they come from the address where an
  allowlisted client authenticated, so **the server never sees strangers' packets**.

## Design

One UDP socket carries two kinds of traffic.

### Registration (the relay as a WireGuard peer)

Each server, and each client in `register` mode, lists the relay as a `[Peer]`
with `AllowedIPs = <tunnel_ip>/32` and `PersistentKeepalive = 25`. The relay runs
one `boringtun::noise::Tunn` per registrable key.

* An initiation whose mac1 is keyed to the **relay's** public key is for the
  relay. `parse_handshake_anon` decrypts the sender's static key. Keys that are
  not allowlisted are rejected (`registration_unknown_key`), as are clients when
  the gate is not `register` (`client_registration_disabled`). Everything else
  goes to that key's `Tunn`, which performs the full handshake, including replay
  protection.
* After **every packet that authenticates** on a key's tunnel (a handshake, data
  or a keepalive, but never a cookie), the relay sets
  `registry[key] = src_addr`. If the address changed (roaming), every session
  table entry using the old address is rewritten. Entries expire after 180 s.
* **The relay's indexes never collide with forwarded sessions.** Each relay
  tunnel owns a random 24-bit index prefix, so it uses 256 indexes. A new prefix
  is never one that a live session is using, and any forwarded handshake that
  picks an index inside a relay prefix is dropped (`reserved_index`), so the peer
  retries with a new random index. Packets in a relay prefix go only to that
  relay tunnel.
* The relay answers ICMP echo to `tunnel_ip` (`ping 10.99.0.254` checks registration).

### Session table

`receiver_idx → { dest_addr, expected_src_addr, open, last_seen }`, plus the
server's and (once known) the client's key, which are used to revoke sessions on
reload. **Every type 2, 3 and 4 packet must arrive from `expected_src_addr`.**
Entries expire after 200 s idle. On an index collision the newest entry wins and
a warning is logged.

### Forwarding rules

Every initiation is rate-limited per source IP first.

**Type 1, initiation** (`sender_idx` must not be in a relay prefix):

* **mac1 matches a registered server S.** In `none` and `response` modes it is
  accepted from any source. In `register` mode the source must be the
  registered address of an allowlisted client permitted to reach S. The relay
  records `idx[sender] = {dest: src, expected_src: addr(S), open: false}` and
  forwards to S.
* **mac1 matches a client C** (a server-initiated handshake or rekey). The source
  must be a registered server S that C may reach, and C's address must be known:
  its registration in `register` mode, otherwise the address learned from S's
  last accepted response to C. The relay records `idx[sender]` as pending and
  forwards to C.
* Otherwise the packet is dropped (`no_mac1_match`).

**Type 2, response** (it must match a pending entry and come from its `expected_src`):

* **From a server.** Match mac1 against the client keys. A match with a client C
  that may reach that server opens the session and records `addr[C]`. In
  `register` mode, C must also be registered at the session's client address
  (`client_addr_mismatch`). With no match, the packet is dropped in `response` and
  `register` modes (`response_unknown_client`). In `none` mode it is forwarded
  anyway and the session opens.
* **From a client.** mac1 must match the server's key (`response_not_for_server`).
* Either way, the initiator's entry becomes `open` and an open entry is created
  for the responder's `sender_idx`.

**Types 3 and 4** (cookie reply and data) are forwarded only from
`expected_src`. Data requires an `open` session. A cookie reply may also pass on
a pending one, so a server under load can answer an initiation.

The relay never sends cookie replies (or anything else) for forwarded traffic.
Datagrams are parsed with explicit size checks: exact sizes for types 1–3, at
least 32 B for data, and the reserved bytes must be zero. Nothing on the
forwarding path can panic. This is covered by a 30 000-case mutation test across
all gate modes.

### Rejects and metrics

Every rejected datagram increments a per-reason counter and logs
`reject reason=<reason> src=<addr>` at `debug` level. Per-packet logs are kept at
debug because otherwise anyone could flood the log. Counters are logged every
60 s and at shutdown, for example
`rx=86 forwarded=64 … reject.src_not_registered_client=2 reject.registration_unknown_key=2`.

| Reason | Meaning |
|---|---|
| `malformed` | wrong size, type or reserved bytes |
| `rate_limited` | the source IP exceeded `handshake_rate_per_ip` |
| `reserved_index` | a forwarded handshake picked an index in the relay's range |
| `no_mac1_match` | the initiation is not for any server, client or the relay |
| `server_not_registered` | the target server has no current registration |
| `src_not_registered_client` | `register` mode: the initiator is not a registered client |
| `acl` | the client may not reach that server |
| `loop` | the initiation came from the target's own address |
| `rekey_not_from_server` | a client-addressed initiation came from something other than a registered server |
| `client_addr_unknown` | server→client initiation, but the client's address is unknown |
| `unknown_index` | no live session for `receiver_idx` |
| `wrong_source` | the packet is not from the session's `expected_src_addr` |
| `client_addr_mismatch` | `register` mode: the response names a client registered elsewhere |
| `response_unknown_client` | the server answered a key that is not allowlisted for it |
| `response_not_for_server` | the client's response is not keyed to the session's server |
| `session_not_open` | data on a session whose handshake has not completed |
| `registration_unknown_key` | the relay-bound handshake came from a key that is not allowlisted |
| `client_registration_disabled` | a client tried to register while the gate is not `register` |
| `tunnel_auth_failed` | a registration-tunnel packet failed authentication |

### Reload (SIGHUP)

`relay.toml` is re-read and validated. If it is invalid, the current config stays
in effect and an error is logged. Changes to `listen` and `private_key` need a
restart. Everything else applies immediately:

* A **removed key** loses its registration, its relay tunnel and every session
  it is part of. Its next packet is rejected (`unknown_index`).
* A client whose `servers` list no longer includes a server loses its sessions
  with that server.
* Switching the gate away from `register` drops client registrations. Switching
  to `response` or `register` drops open sessions whose client was never
  identified, which can only exist in `none` mode.

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

# Only with client_gate = "register":
[Peer]
PublicKey           = <relay public key>
Endpoint            = relay.example.com:51820
AllowedIPs          = 10.99.0.254/32
PersistentKeepalive = 25
```

Because all of a host's peers share one endpoint, all its traffic uses one NAT
mapping, which is the mapping its registration and handshakes come from.
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
  from authenticated registrations or from a session's handshake. Replies are
  never larger than requests, and forwarded traffic never gets relay-generated
  replies. Unregistered sources reach only the rate-limited paths: registration
  (one X25519 operation) and, in `none` and `response` modes, initiations to
  servers.
* **Strangers.** In `register` mode their packets never reach a server. In
  `response` mode their initiations reach the server, but no session can open
  unless the server itself authenticates an allowlisted key.
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
  works normally. Servers, and clients in `register` mode, re-register on their
  next authenticated packet to the relay and their sessions are migrated, but
  data sent in the meantime is lost.
* **`none` and `response` modes trust the server's peer list** for
  authentication. The relay learns a client's address from the server's
  response, so an on-path attacker who replays a client's fresh initiation from
  another address first can make that handshake fail. That is a denial of
  service only.
* **In `none` mode, unlisted clients** cannot receive server-initiated
  handshakes. Their own keepalives make them rekey, so this rarely matters.
* **The per-IP initiation limit is shared** by all hosts behind one NAT address.
  Many distributed sources can still make the relay do X25519 work on the
  registration path.
* **Two hosts cannot register from the same `ip:port`.** The newest claimant wins
  and a warning is logged.
* **Index collisions** between independent sessions (probability 2⁻³² per pair)
  break the older session until its next rekey.
* **Single-threaded**, with a linear mac1 scan over servers or clients per
  handshake. That is fine for thousands of keys.
* The ICMP responder is IPv4-only, and metrics are logged rather than exported.

## Code layout

| File | Purpose |
|---|---|
| `src/packet.rs` | wire-format parsing, size checks, mac1 |
| `src/tables.rs` | registry, session table, per-IP token bucket |
| `src/relay.rs` | `Relay::handle` (no I/O): gate logic, registration tunnels, reload, reject reasons |
| `src/config.rs` | `relay.toml` parsing and validation |
| `src/main.rs` | CLI, tokio socket loop, timers, SIGHUP/SIGTERM |
