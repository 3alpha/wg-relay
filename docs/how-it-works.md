# How wg-relay works

This document walks through the relay from first principles: the problem, the
small piece of WireGuard it relies on, the life of every kind of packet, the
state it keeps, and why each check exists. The [README](../README.md) is the
quick reference; this is the long version.

- [1. The problem](#1-the-problem)
- [2. The trick: routing ciphertext without keys](#2-the-trick-routing-ciphertext-without-keys)
- [3. WireGuard in five minutes](#3-wireguard-in-five-minutes)
- [4. The relay's state](#4-the-relays-state)
- [5. Server registration](#5-server-registration)
- [6. A client connects](#6-a-client-connects)
- [7. Sessions: the state machine](#7-sessions-the-state-machine)
- [8. Server-initiated handshakes and rekeys](#8-server-initiated-handshakes-and-rekeys)
- [9. Client gates: `none` vs `response`](#9-client-gates-none-vs-response)
- [10. The dispatcher, step by step](#10-the-dispatcher-step-by-step)
- [11. Index space: relay indexes vs forwarded indexes](#11-index-space-relay-indexes-vs-forwarded-indexes)
- [12. Timers and expiry](#12-timers-and-expiry)
- [13. Reload (SIGHUP)](#13-reload-sighup)
- [14. When things move: roaming and restarts](#14-when-things-move-roaming-and-restarts)
- [15. Security model](#15-security-model)
- [16. Code map](#16-code-map)
- [17. How it is tested](#17-how-it-is-tested)

## 1. The problem

A WireGuard server sits on a home or office network behind NAT, with no public
address and no port forward. Its clients (laptops, phones) are behind NATs too.
Neither side can receive an unsolicited packet, so neither can start a
connection to the other.

Both sides *can* send packets out to a host on the internet, and NATs let the
replies back in. wg-relay is that host: everyone points their WireGuard
`Endpoint` at it, and it passes packets between them.

```mermaid
flowchart LR
    subgraph home["Home network (NAT)"]
        S["WireGuard server<br/>10.99.0.1"]
    end
    subgraph cafe["Cafe Wi-Fi (NAT)"]
        L["Laptop<br/>10.99.0.11"]
    end
    subgraph mobile["Mobile carrier (CGNAT)"]
        P["Phone<br/>10.99.0.12"]
    end
    R(("wg-relay<br/>public UDP :51820"))
    S -- "outbound UDP,<br/>kept open by keepalives" --> R
    L --> R
    P --> R
    X["Stranger"] -. "dropped" .-> R
```

The constraints that shape the design:

| Constraint | Consequence |
|---|---|
| Clients and server run **stock WireGuard** (kernel, wireguard-go, mobile apps) | No custom protocol or agent; the relay must work with packets WireGuard already sends |
| The relay must **never be able to read traffic** | It holds no client↔server keys and forwards datagrams byte-for-byte |
| The relay is on the public internet | It must not become an open reflector, and must refuse strangers |

## 2. The trick: routing ciphertext without keys

If the relay can't decrypt anything, how does it know where a packet goes? It
uses two fields that WireGuard leaves readable on purpose:

1. **mac1** on handshake messages. Every initiation and response ends with a
   16-byte MAC keyed with `BLAKE2s-256("mac1----" ‖ recipient_public_key)`. It
   exists so a recipient can cheaply discard junk before doing any
   cryptography. A side effect: **anyone who knows a candidate public key can
   test whether a handshake was addressed to it.** The relay knows the public
   keys of its servers (and listed clients), so it tries each one.
2. **Session indexes.** Every handshake carries a random 32-bit `sender_idx`
   chosen by its sender. Afterwards, every packet *to* that side carries it as
   `receiver_idx`. The relay watches handshakes go by, notes which index belongs
   to which address, and routes everything after that by index.

```mermaid
flowchart TD
    A["Handshake initiation arrives"] --> B{"mac1 valid for<br/>server key K?"}
    B -- "try each allowlisted key" --> C["It is for server K:<br/>forward to K's registered address"]
    B -- "no key matches" --> D["Drop: no_mac1_match"]
    C --> E["Remember: sender_idx belongs<br/>to the address it came from"]
    E --> F["Later data with receiver_idx = that index<br/>goes back to that address"]
```

A MAC can only be checked against a key you already have; it can't be reversed
to reveal the key. This one fact explains several behaviours later on (for
example, why the relay can't route a server's handshake to a client it has
never heard of, see [section 8](#8-server-initiated-handshakes-and-rekeys)).

## 3. WireGuard in five minutes

WireGuard has four message types. Only the header fields in **bold** matter to
the relay; everything else is opaque. All integers are little-endian.

| Type | Name | Size | Layout |
|---|---|---|---|
| 1 | Initiation | 148 B | type(1) reserved(3) **sender_idx(4)** ephemeral(32) enc_static(48) enc_timestamp(28) **mac1(16)** mac2(16) |
| 2 | Response | 92 B | type(1) reserved(3) **sender_idx(4) receiver_idx(4)** ephemeral(32) enc_empty(16) **mac1(16)** mac2(16) |
| 3 | Cookie reply | 64 B | type(1) reserved(3) **receiver_idx(4)** nonce(24) enc_cookie(32) |
| 4 | Data | ≥ 32 B | type(1) reserved(3) **receiver_idx(4)** counter(8) encrypted payload |

mac1 covers every byte before it: the first 116 bytes of an initiation, the
first 60 of a response. Cookie replies are WireGuard's DoS defence: a peer under
load answers a handshake with a cookie instead of doing the expensive work.

A handshake is one round trip:

```mermaid
sequenceDiagram
    participant I as Initiator
    participant R as Responder
    I->>R: Initiation (sender_idx = i, mac1 keyed to R's public key)
    Note right of R: decrypts I's static key,<br/>checks it is a known peer
    R->>I: Response (sender_idx = r, receiver_idx = i, mac1 keyed to I's public key)
    Note left of I: session established
    I->>R: Data (receiver_idx = r)
    R->>I: Data (receiver_idx = i)
```

Two details the relay depends on:

- **The response's mac1 is keyed to the initiator's public key**, the one the
  responder just decrypted and authenticated. So a server's response tells the
  relay *which client the server accepted*, as long as the relay has that
  client's key to test.
- **Each side picks its own index**, and a new handshake (every 2 minutes, or
  after a restart) picks new ones. The relay has to keep learning.

WireGuard identifies a peer by its key and indexes, never by source address. That
is why every peer on a host can share the same `Endpoint` (the relay) without
confusion.

## 4. The relay's state

The relay is a single-threaded state machine (`Relay` in `src/relay/mod.rs`).
`Relay::handle(src, datagram, now)` does no I/O: it returns a verdict, and the
socket loop in `src/app.rs` acts on it.

```mermaid
flowchart LR
    subgraph cfg["From relay.toml"]
        P["peers<br/>key → Server(tunnel) | Client(servers)"]
        G["gate: none | response"]
    end
    subgraph learned_state["Learned at runtime"]
        REG["registry<br/>server key ↔ address<br/>(authenticated, 180 s TTL)"]
        SES["session table<br/>receiver_idx → {dest, expected_src,<br/>state, server, client}<br/>(200 s idle TTL)"]
        LRN["learned<br/>client key → address<br/>(from accepted responses)"]
        RL["rate limiter<br/>source IP → token bucket"]
    end
    subgraph tunnels["Relay's own WireGuard"]
        T["one boringtun Tunn per server<br/>indexes in a reserved prefix"]
    end
```

| Table | Written when | Read when | Expires |
|---|---|---|---|
| `registry` | a packet **authenticates** on a server's relay tunnel | finding a server's address; checking a packet came from a server | 180 s without authenticated traffic |
| `sessions` | a handshake is forwarded (pending) or accepted (open) | every type 2, 3 and 4 packet | 200 s without traffic on that index |
| `learned` | a server's response is accepted for a listed client | a server starts a handshake to that client | when no live session involves that client |
| `rate limiter` | every initiation | every initiation | when the bucket would be full again |

The relay never trusts an address it hasn't either authenticated (servers) or
seen in a handshake it forwarded (clients).

## 5. Server registration

The relay is an ordinary WireGuard peer of each server, with its own key pair
and a `/32` tunnel address (`10.99.0.254`). This tunnel carries no user traffic;
it exists so the relay learns, **with cryptographic proof**, where each server
is right now.

```mermaid
sequenceDiagram
    participant S as Server (behind NAT)
    participant N as Server's NAT
    participant R as wg-relay
    Note over S: [Peer] relay, PersistentKeepalive = 25
    S->>N: Initiation, mac1 keyed to relay's key
    N->>R: same packet, from 198.51.100.7:40001
    Note over R: mac1 matches the relay's own key<br/>parse_handshake_anon reveals sender = server "main"<br/>"main" is allowlisted, so its Tunn takes the packet
    R->>N: Response (from the relay's Tunn for "main")
    N->>S: Response
    Note over R: handshake authenticated:<br/>registry["main"] = 198.51.100.7:40001
    loop every 25 s
        S->>R: keepalive (authenticated data packet)
        Note over R: registry refreshed, NAT mapping kept open
    end
```

What counts as authenticated: a completed handshake, a data packet, or a
keepalive that decrypts on that server's tunnel. A cookie reply never counts,
because producing one proves nothing about who you are. If an authenticated
packet arrives from a **new** address (the server's NAT rebound), the registry
moves the server there and every session using the old address is rewritten.

Registration is refused for keys that aren't allowlisted
(`registration_unknown_key`) and for client keys
(`client_registration_refused`): clients never talk to the relay directly.

The relay also answers pings to its tunnel IP, so `ping 10.99.0.254` from the
server is a one-line registration check.

## 6. A client connects

The client's config just lists the server with `Endpoint = relay:51820`. Here is
a full connection in `response` mode, with what the relay records at each step.
The client's NAT gives it the public address `C`; the server is registered at
`S`.

```mermaid
sequenceDiagram
    participant C as Client (public addr C)
    participant R as wg-relay
    participant S as Server (registered at S)
    C->>R: Initiation, sender_idx = i, mac1 for server
    Note over R: rate limit OK, mac1 matches server "main", "main" is registered<br/>sessions[i] = {dest: C, expected_src: S, Pending}
    R->>S: Initiation (unchanged bytes)
    Note over S: decrypts client's static key, it is a known peer
    S->>R: Response, sender_idx = r, receiver_idx = i, mac1 for client
    Note over R: sessions[i] exists and the packet came from S<br/>mac1 matches listed client "laptop", allowed to reach "main"<br/>sessions[i] becomes Open, learned["laptop"] = C<br/>sessions[r] = {dest: S, expected_src: C, Open}
    R->>C: Response (unchanged bytes)
    C->>R: Data, receiver_idx = r
    Note over R: sessions[r]: came from C, Open, so send to S
    R->>S: Data
    S->>R: Data, receiver_idx = i
    Note over R: sessions[i]: came from S, Open, so send to C
    R->>C: Data
```

After the handshake there are two session entries, one per direction. Each one
says where packets with that index go **and the only address allowed to send
them**. That second field is what stops anyone else from injecting packets into
the session, even if they guess the index.

## 7. Sessions: the state machine

Every entry in the session table follows this life cycle:

```mermaid
stateDiagram-v2
    [*] --> Pending: initiation forwarded<br/>(entry for the initiator's index)
    [*] --> Open: response accepted<br/>(entry for the responder's index)
    Pending --> Open: response accepted
    Pending --> Pending: cookie reply forwarded
    Pending --> [*]: 200 s idle / revoked by reload
    Open --> Open: data or cookie forwarded (refreshes last_seen)
    Open --> [*]: 200 s idle / revoked by reload / index reused (newest wins)
```

What each state lets through, always only from `expected_src`:

| Packet | `Pending` | `Open` |
|---|---|---|
| Type 2, response | yes, subject to the gate (section 9) | n/a |
| Type 3, cookie reply | **yes**, so a server under load can still answer | yes |
| Type 4, data | **no** (`session_not_open`) | yes |

A WireGuard session rekeys every 2 minutes, which creates new indexes; the old
entries simply age out after 200 s of silence. If two unrelated sessions pick
the same index (probability 2⁻³² per pair), the newest entry wins and a warning
is logged.

## 8. Server-initiated handshakes and rekeys

Sometimes the server starts the handshake: when its session with a client has
expired and it has data to send, or right after it restarts. Its initiation's
mac1 is keyed to the **client's** public key, so the relay can only route it if
that client is listed in `relay.toml` and the relay has seen where it lives.

```mermaid
sequenceDiagram
    participant S as Server (registered at S)
    participant R as wg-relay
    participant C as Client (learned at C)
    S->>R: Initiation, sender_idx = j, mac1 for "laptop"
    Note over R: mac1 matches listed client "laptop"<br/>source S is a registered server, "laptop" may reach it<br/>learned["laptop"] = C<br/>sessions[j] = {dest: S, expected_src: C, Pending}
    R->>C: Initiation
    C->>R: Response, receiver_idx = j, mac1 for server
    Note over R: came from C (not a server), so mac1 must match<br/>the session's server: it does<br/>sessions[j] Open, new entry for the client's index
    R->>S: Response
```

If the client isn't listed, no key matches the mac1 and the packet is dropped
(`no_mac1_match`); if it is listed but has never completed a handshake through
this relay, its address is unknown (`client_addr_unknown`). In practice this is
rare: clients normally initiate, and `PersistentKeepalive` keeps their sessions
fresh. It mostly shows up for a few seconds after the server restarts.

## 9. Client gates: `none` vs `response`

Both modes treat initiations the same way: anyone may send one to a registered
server, subject to the per-IP rate limit. The server's own WireGuard then
decides whether it knows that client. The modes differ in what the relay does
with the server's **response**:

```mermaid
flowchart TD
    A["Type 2 response arrives"] --> B{"sessions[receiver_idx]<br/>exists?"}
    B -- no --> X1["Drop: unknown_index"]
    B -- yes --> C{"from the session's<br/>expected_src?"}
    C -- no --> X2["Drop: wrong_source"]
    C -- yes --> D{"source is a<br/>registered server?"}
    D -- "no: a client answering<br/>a server's handshake" --> E{"mac1 matches the<br/>session's server?"}
    E -- no --> X3["Drop: response_not_for_server"]
    E -- yes --> OK["Open session, forward"]
    D -- yes --> F{"mac1 matches a<br/>listed client?"}
    F -- "yes" --> G{"client may reach<br/>this server?"}
    G -- no --> X4["Drop: acl"]
    G -- yes --> H["learned[client] = its address"] --> OK
    F -- "no" --> I{"gate"}
    I -- none --> OK
    I -- response --> X5["Drop: response_unknown_client"]
```

| | `none` | `response` |
|---|---|---|
| `relay.toml` lists | servers (clients optional) | servers **and** clients |
| Who decides access | the server's peer list only | the server's peer list **and** the relay's client list |
| Revoking a client | remove it from the server | remove it from `relay.toml` + SIGHUP (instant), or from the server |
| Server-initiated handshakes | only to listed clients | to every listed client |
| Strangers' initiations | reach the server, which drops them | reach the server, which drops them; the relay would also refuse the session |

In `response` mode the relay is a second, independent gate: a client the server
still accepts can be cut off from the relay alone, without touching the server.

## 10. The dispatcher, step by step

Every datagram goes through `Relay::route` (`src/relay/mod.rs`). The checks are
ordered from cheapest to most expensive, so junk is rejected before any
cryptography happens.

```mermaid
flowchart TD
    IN["UDP datagram from src"] --> P{"parse: type, size,<br/>reserved bytes"}
    P -- bad --> M["Drop: malformed"]
    P -- "type 1" --> RL{"rate limit<br/>for src IP"}
    RL -- empty --> D1["Drop: rate_limited"]
    RL -- ok --> RM{"mac1 keyed to<br/>relay's own key?"}
    RM -- yes --> REG["register_init:<br/>identify sender, hand to its Tunn"]
    RM -- no --> FI["forward_init<br/>(sections 6 and 8)"]
    P -- "type 2/3/4" --> PX{"receiver_idx in a<br/>relay tunnel's prefix?"}
    PX -- yes --> TR["tunnel_rx:<br/>that server's Tunn"]
    PX -- no --> T2{"type"}
    T2 -- 2 --> FR["forward_response<br/>(section 9)"]
    T2 -- "3 or 4" --> FX["forward_indexed<br/>(section 7)"]
    REG --> V["Verdict"]
    TR --> V
    FI --> V
    FR --> V
    FX --> V
    V --> OUT{"Forward(addr)?<br/>Consumed?<br/>Drop(reason)?"}
```

Each forwarding rule returns `Result<SocketAddr, Reason>`; `handle()` turns that
into a `Verdict`, counts it, and logs drops at debug level with their reason.
The socket loop sends `Forward` datagrams unchanged and drains the relay
tunnels' own output (handshake responses, keepalives, ping replies) after every
event.

The initiation rule in full:

```mermaid
flowchart TD
    A["Type 1, not for the relay"] --> R{"sender_idx in a<br/>relay prefix?"}
    R -- yes --> X0["Drop: reserved_index"]
    R -- no --> B{"mac1 matches<br/>a server?"}
    B -- yes --> C{"server<br/>registered?"}
    C -- no --> X1["Drop: server_not_registered"]
    C -- yes --> L{"src is the server<br/>itself?"}
    L -- yes --> X2["Drop: loop"]
    L -- no --> OK1["Pending session for sender_idx,<br/>forward to server"]
    B -- no --> E{"mac1 matches a<br/>listed client?"}
    E -- no --> X3["Drop: no_mac1_match"]
    E -- yes --> F{"src is a<br/>registered server?"}
    F -- no --> X4["Drop: rekey_not_from_server"]
    F -- yes --> G{"client may reach<br/>that server?"}
    G -- no --> X5["Drop: acl"]
    G -- yes --> H{"client's address<br/>learned?"}
    H -- no --> X6["Drop: client_addr_unknown"]
    H -- yes --> OK2["Pending session for sender_idx,<br/>forward to client"]
```

## 11. Index space: relay indexes vs forwarded indexes

The relay's own tunnels need session indexes too, and they share the
`receiver_idx` field with forwarded traffic. If a forwarded session ever used an
index the relay owns, the relay would swallow its packets. So the space is split:

```mermaid
flowchart LR
    subgraph idx["32-bit session index"]
        direction LR
        PFX["upper 24 bits: prefix"] --- CNT["lower 8 bits: counter"]
    end
    subgraph owners["Who owns a prefix"]
        T1["prefix 0x3f19a2: relay tunnel for server 'main'"]
        T2["prefix 0x08c4e7: relay tunnel for server 'backup'"]
        F["every other prefix: forwarded sessions"]
    end
```

- boringtun numbers a tunnel's sessions `prefix << 8 | counter`, so each relay
  tunnel uses at most 256 indexes, all under one prefix.
- Each server's tunnel gets a **random** prefix that no live forwarded session is
  using at the time it is created.
- A forwarded handshake whose `sender_idx` falls inside a relay prefix is
  dropped (`reserved_index`). WireGuard simply retries with a new random index.

Together these guarantee the two kinds of index never collide, and a packet
whose `receiver_idx` is in a relay prefix can go straight to that relay tunnel.

## 12. Timers and expiry

| Timer | Value | Where | Purpose |
|---|---|---|---|
| Peer keepalive | 25 s | node configs (`PersistentKeepalive`) | keeps NAT mappings open, refreshes the server's registration |
| WireGuard rekey | about 2 min | WireGuard itself | new keys and new indexes |
| Registration TTL | 180 s | `REGISTRY_TTL` | a server silent for 3 min is forgotten |
| Session TTL | 200 s idle | `SESSION_TTL` | indexes from old handshakes age out |
| Relay tick | 250 ms | `app.rs` | runs relay tunnel timers, expires tables, prunes rate-limit buckets |
| Stats log | 60 s | `app.rs` | logs all counters, including per-reason rejects |
| Rate limit | `handshake_rate_per_ip`, burst 2 s worth | `relay.toml` | caps initiations per source IP |

The values nest deliberately: a healthy server refreshes its registration about
seven times per TTL, and a session that is still in use is refreshed on every
packet, long before 200 s, while one replaced by a rekey disappears soon after.

```mermaid
gantt
    title One server and one client over five minutes (relative seconds)
    dateFormat X
    axisFormat %s
    section Server registration
    registered, refreshed every 25 s     :active, 0, 300
    section Client session 1
    handshake + traffic                  :done, 0, 120
    idle until expiry                    :120, 320
    section Client session 2 (rekey)
    handshake + traffic                  :active, 120, 240
    section Client session 3 (rekey)
    handshake + traffic                  :active, 240, 300
```

## 13. Reload (SIGHUP)

`kill -HUP` re-reads `relay.toml`. If the file is invalid, the running config
stays and an error is logged. Changes to `listen` or `private_key` need a
restart; everything else applies at once:

```mermaid
flowchart TD
    A["SIGHUP"] --> B{"relay.toml valid?"}
    B -- no --> K["Log error, keep running config"]
    B -- yes --> C["Rebuild peers:<br/>servers keep their relay tunnel,<br/>new servers get a fresh prefix"]
    C --> D["Removed servers lose their<br/>registration and tunnel"]
    D --> E["Forget learned addresses<br/>of removed clients"]
    E --> F["Re-check every session against<br/>the new config"]
    F --> G{"server still a server?<br/>client still listed and allowed?<br/>gate still allows it?"}
    G -- no --> H["Session dropped now:<br/>next packet gets unknown_index"]
    G -- yes --> I["Session kept"]
```

Revocation is immediate, not "at the next rekey": a removed client's very next
packet is rejected. Switching from `none` to `response` drops open sessions whose
client was never identified, i.e. unlisted clients.

## 14. When things move: roaming and restarts

**A server's NAT rebinds.** Its next keepalive to the relay authenticates from
the new address; the registry moves it and every session entry is rewritten. Until
then (at most one keepalive interval, 25 s) traffic in both directions is lost:
client packets go to the old address, and the server's packets arrive from an
address no session expects.

**A client changes network** (Wi-Fi to cellular). Its packets now come from a
new address that no session expects, so they are dropped. WireGuard notices it
is getting no replies and starts a fresh handshake, which then works normally:

```mermaid
sequenceDiagram
    participant C as Client
    participant R as wg-relay
    participant S as Server
    Note over C: moves from Wi-Fi (C1) to cellular (C2)
    C->>R: Data from C2
    Note over R: session expects C1: drop (wrong_source)
    C->>R: Data from C2 (no replies arrive)
    Note over R: drop (wrong_source)
    Note over C: about 5 to 15 s without replies:<br/>WireGuard starts a new handshake
    C->>R: Initiation from C2
    R->>S: Initiation
    S->>R: Response
    R->>C: Response to C2
    Note over C,S: traffic flows again over the new path
```

The relay can't follow the client sooner because the client never authenticates
to the relay; accepting its new address on its word would let anyone hijack
sessions.

**The server restarts.** It re-registers within seconds (its first packet to the
relay is a handshake). Client sessions are gone on the server side; clients'
next data gets no reply and they re-handshake as above. Server-initiated
handshakes reach only listed clients ([section 8](#8-server-initiated-handshakes-and-rekeys)).

## 15. Security model

```mermaid
flowchart LR
    subgraph visible["The relay can see"]
        V1["who talks to which server<br/>(mac1 + addresses)"]
        V2["which listed client a server accepted<br/>(response mac1)"]
        V3["packet timing, sizes, volume"]
        V4["every host's public IP and port"]
    end
    subgraph hidden["The relay cannot see or do"]
        H1["payloads: no session keys"]
        H2["forge or modify packets:<br/>receivers would reject them"]
        H3["impersonate a client to the server:<br/>it never has client keys"]
    end
```

**What stops abuse:**

| Threat | Defence |
|---|---|
| Using the relay as a reflector or amplifier | It only sends to authenticated server addresses or addresses from a handshake it forwarded; replies are never larger than requests; forwarded traffic never triggers relay-generated replies |
| Strangers reaching a server | The server's peer list drops them; in `response` mode the relay also refuses to open their sessions |
| Injecting packets into someone's session | Every non-handshake packet must come from the session's `expected_src` |
| Redirecting a server's traffic | Registration requires a full WireGuard handshake with the server's key; replays fail WireGuard's timestamp and counter checks |
| Handshake floods | Per-IP token bucket before any mac1 work or key exchange |
| A revoked client lingering | SIGHUP drops its sessions immediately |

**What the relay's private key is worth to an attacker:** it opens only the
registration tunnels, which carry nothing but keepalives and pings to
`10.99.0.254/32`. With it, an attacker could pose as the relay to servers, which
gains them the same position as an on-path attacker: they can drop traffic, but
not read it.

## 16. Code map

```mermaid
flowchart TD
    main["main.rs<br/>parse CLI, logging, report errors"] --> app["app.rs<br/>Cli, socket loop, timers, signals"]
    app --> cfg["config/<br/>relay.toml, Rate, Summary, ConfigError"]
    app --> relay["relay/mod.rs<br/>Relay, handle, route, tick"]
    relay --> fwd["relay/forward.rs<br/>forward_init, forward_response,<br/>forward_indexed"]
    relay --> regm["relay/registration.rs<br/>register_init, tunnel_rx, ICMP"]
    relay --> rel["relay/reload.rs<br/>reload, session_allowed"]
    relay --> rsn["relay/reason.rs + metrics.rs<br/>Reason, Verdict, counters"]
    relay --> tbl["tables.rs<br/>Registry, SessionTable, RateLimiter"]
    fwd --> pkt["packet/<br/>parse, mac1, SessionIdx"]
    regm --> bt["boringtun Tunn<br/>(relay's own WireGuard)"]
    cfg --> key["key/<br/>PeerKey, PrivateKey"]
```

Following one data packet through the code:

1. `app.rs` `serve()` receives it with `recv_from` and calls `relay.handle(src, bytes, now)`.
2. `handle()` calls `route()`, which calls `packet::parse()` and gets `Packet::Data { receiver }`.
3. `relay_tunnel(receiver)` finds no relay prefix, so `forward_indexed()` looks
   up `sessions.get(receiver)`, checks `expected_src` and the state, and
   refreshes `last_seen`.
4. It returns `Ok(dest)`; `handle()` records `Verdict::Forward(dest)` in the metrics.
5. `serve()` calls `send_to(bytes, dest)` with the original, unmodified bytes.

## 17. How it is tested

| Layer | What | Where |
|---|---|---|
| Unit | session table, registry, rate limiter, `Rate` parsing, ICMP reply | `#[cfg(test)]` modules in `src/` |
| Packet | parsing, size checks, mac1 matching on real packets made by boringtun | `tests/packet.rs` |
| Config | defaults, exact `ConfigError` for each bad input, warnings, `--check-config` | `tests/config.rs` |
| Relay, in-process | full handshakes between boringtun peers through `Relay::handle` for both gates, reload, roaming, reserved indexes, rate limits, 20 000 mutated packets | `tests/relay.rs` |
| End-to-end | real kernel WireGuard in network namespaces behind real NATs | `tests/netns.sh` |

The end-to-end topology:

```mermaid
flowchart LR
    subgraph relayns["relay namespace"]
        BR["br0 192.0.2.1<br/>wg-relay :51820<br/>tcpdump"]
    end
    subgraph s["server side"]
        SRV["srv<br/>wg0 10.99.0.1"] --- NS["natsrv<br/>MASQUERADE"]
    end
    subgraph c1s["client 1"]
        C1["c1<br/>wg0 10.99.0.11"] --- N1["natc1"]
    end
    subgraph c2s["client 2"]
        C2["c2<br/>wg0 10.99.0.12"] --- N2["natc2"]
    end
    subgraph sts["stranger"]
        ST["st<br/>wg0 10.99.0.13"] --- N3["natst"]
    end
    NS --- BR
    N1 --- BR
    N2 --- BR
    N3 --- BR
```

It runs once per gate and checks that clients reach the server, the stranger
doesn't, rekeys in both directions work, SIGHUP revokes instantly, and, from a
packet capture at the relay, that forwarded handshakes cannot be opened with the
relay's key, every forwarded packet is byte-identical, and the ping payload
never appears on the wire.
