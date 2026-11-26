# wg-relay reference

This document gives the exact rules wg-relay follows, its configuration, logs and metrics, and its known limitations. For setup, see the [README](../README.md). For a guided tour of the design with diagrams, read [How wg-relay works](how-it-works.md).

## Terms

| Term | Meaning |
|---|---|
| server, client | WireGuard has only peers. A server is a peer that runs all the time and answers handshakes that others start. A client, such as a laptop or phone, connects out and starts the handshakes. The relay does not know these roles; it only knows configured and unconfigured peers. |
| configured peer | A peer whose public key is listed in `relay.toml`, usually a server. It must be reachable through the relay, so it registers with the relay. |
| unconfigured peer | Any other peer, usually a client. It needs no relay configuration. |
| endpoint | The public address and UDP port (`ip:port`) a peer's packets come from, as the relay sees them after any NAT. |
| registration tunnel | An ordinary WireGuard tunnel between a configured peer and the relay. It proves to the relay where the peer can be reached, and carries only handshakes, keepalives and pings to the relay. |
| registration | The relay's record of a configured peer's current endpoint, learned from its registration tunnel. |
| message types | WireGuard has four: type 1 is a handshake initiation, type 2 a handshake response, type 3 a cookie reply and type 4 transport data. |
| mac1 | A MAC in every handshake message, keyed with a hash of the recipient's public key. Anyone who knows that public key can check it, so the relay uses it to find which configured peer an initiation is for. |
| sender index, receiver index | Each side of a WireGuard session picks a random 32-bit index and announces it in its handshake message as the sender index. Every later message to that side carries it as the receiver index. Both are cleartext. |
| session entry | The relay's routing entry for one index: where messages carrying it go, and the only address allowed to send them. Each forwarded handshake creates two entries, one per direction. "Session" in this document means a session entry unless it says WireGuard session. |
| pending, established | A session entry is pending from the forwarded initiation until the relay accepts the matching response, and established after that. Only established entries carry transport data. |
| reserved prefix | A block of 256 indexes that share their upper 24 bits and belong to one registration tunnel. Forwarded sessions may not use them. |
| data plane, control plane | The two halves of the relay. The data plane forwards traffic on established sessions without locks. The control plane decides everything else and owns all state that changes. See [Architecture](#architecture). |
| GRO, GSO | Generic receive offload and generic segmentation offload: the kernel coalesces several received UDP datagrams into one buffer, or splits one large send into several datagrams. See [Socket I/O](#socket-io). |

## Configuration

`relay.toml` is a TOML file. Unknown keys are an error. `wg-relay --check-config -c relay.toml` validates it and prints a summary of the effective config. `SIGHUP` reloads it; the last column says which keys a reload applies, and [Reload](#reload-sighup) gives the details.

| Key | Default | Meaning | On reload |
|---|---|---|---|
| `listen` | `"0.0.0.0:51820"` | UDP address and port the relay binds | needs a restart |
| `private_key` | required | The relay's WireGuard private key (`wg genkey`), in base64. It opens only the registration tunnels. | needs a restart |
| `tunnel_ip` | `"10.99.0.254"` | IPv4 address of the relay inside every registration tunnel. Configured peers route it with `AllowedIPs = <tunnel_ip>/32`, and the relay answers pings on it. No network should assign it to a peer. | applied |
| `handshake_rate_per_ip` | `"10/s"` | Handshake initiations each source (IPv4 address or IPv6 /64) may send, written `"<n>/s"` or `"<n>/m"`. Must be positive. The burst is two seconds' worth. | applied |
| `workers` | one per CPU the process may use, at most 256 | Forwarding threads, from 1 to 256. On systems other than Linux the relay always uses one. | needs a restart |
| `public_endpoint` | unset | Where peers reach the relay: `"<host>:<port>"`, with a hostname, an IPv4 address or a bracketed IPv6 address. Used verbatim as `Endpoint` in the printed [`[Peer]` section](#the-printed-peer-section). | applied, and the section is printed again |
| `metrics_listen` | unset (off) | Address of the [Prometheus endpoint](#prometheus-metrics), for example `"127.0.0.1:9586"`. | needs a restart |

Each `[[peer]]` table declares one configured peer. At least one is required, and adding, removing or renaming peers applies on reload.

| Key | Meaning |
|---|---|
| `name` | Label used in logs and as the `peer` label of metrics. Must be unique. |
| `pubkey` | The peer's WireGuard public key, in base64. Must be unique and must differ from the relay's own public key. |

Command-line flags, each with an environment variable that does the same:

| Flag | Environment variable | Meaning |
|---|---|---|
| `-c`, `--config <path>` | `WG_RELAY_CONFIG` | config file (default `relay.toml`) |
| `--check-config` | `WG_RELAY_CHECK_CONFIG` | validate the config, print a summary and exit |
| `--print-peer` | `WG_RELAY_PRINT_PEER` | print the relay's `[Peer]` section and exit |
| `--metrics-listen <addr>` | `WG_RELAY_METRICS_LISTEN` | serve metrics on this address, overriding `metrics_listen` |

## Architecture

`relay.toml` lists the configured peers by public key. One UDP port carries two kinds of traffic: the registration tunnels between the relay and its configured peers, and forwarded traffic between peers, which the relay never decrypts.

### Data plane and control plane

The **data plane** (`DataPlane`) holds two tables: the established sessions (index to destination, expected source and the time of establishment) and the reserved prefixes (prefix to configured peer). It only reads them. For each datagram it does one of three things:

- It forwards transport data and cookie replies on a live established session.
- It drops what it can judge alone: `invalid_source`, `malformed`, `wrong_source`, and `unknown_index` for transport data whose index is neither a live established session nor in a reserved prefix.
- It hands everything else to the control plane: handshake messages, messages to a registration tunnel, and cookie replies on an index that is not a live established session.

The **control plane** (`ControlPlane`) owns all state that changes: the configured peers and their registration tunnels, the registry of endpoints, the rate limiter, the budgets, the session table with its quotas and lifetimes, and reload. It is the only writer of the data plane's tables:

- The session table publishes or withdraws an established entry in the same call that changes the entry, so the two tables never disagree.
- The control plane reserves a prefix when it creates a registration tunnel, and frees it when the tunnel's peer is removed. It reads the same reserved prefixes as the data plane; there is no second copy.

No established session ever has an index in a reserved prefix. The data plane therefore looks up the reserved prefixes only when the established sessions miss, and forwarded data never pays for that lookup.

### Threads

The relay runs `workers` forwarding threads, all alike.

- Each thread has its own UDP socket bound to the listen address with `SO_REUSEPORT`. The kernel spreads incoming flows across the sockets by their address pair, and keeps each flow on one thread, in order.
- The threads share one relay. They read the data plane at the same time without locks, because it is a concurrent hash map (`papaya`). They lock the control plane, a `Mutex`, only for the datagrams the data plane hands over, and for timer ticks and reloads.
- The thread that handled a datagram sends the result on its own socket, together with any datagrams the registration tunnels queued. Any socket will do, because they all have the same address.
- Every thread offers the control plane a timer tick every 250 ms (`TICK_INTERVAL`), then sends what the registration tunnels' timers queued. The control plane runs at most one tick per interval.
- Each thread counts what the data plane decided on it. The stats line and the shutdown line add every thread's counters to the control plane's.

The main thread forwards nothing. It starts the forwarding threads, checks every 250 ms that each is still running, and runs the stats line, the metrics endpoint, `SIGHUP` handling and shutdown. [Socket I/O](#socket-io) describes how each thread uses its socket.

## Registration

Only configured peers register. Each one has the relay as a `[Peer]` with `AllowedIPs = <tunnel_ip>/32` and `PersistentKeepalive = 25`. The relay runs one `boringtun::noise::Tunn` per configured peer.

- **Identifying the peer.** A handshake initiation whose mac1 is keyed to the relay's own public key is a registration initiation. `parse_handshake_anon` decrypts the sender's static public key from it. A key that is not configured is rejected (`registration_unknown_key`). A configured peer's initiation goes to its `Tunn`, which performs the full handshake, including replay protection.
- **Recording the endpoint.** After every packet that authenticates on a configured peer's tunnel, the relay sets `registry[peer] = src_addr`. Transport data, a keepalive, and a handshake response to the relay's own initiation all count. A bare initiation does not, because it could be a replay, and neither does a cookie reply. A registration expires 180 s after the last such packet.
- **Roaming.** If the recorded address changed, every session entry that uses the old address is rewritten to the new one.
- **Reserved prefixes.** Each registration tunnel numbers its indexes in its own randomly chosen reserved prefix. The relay never picks a prefix that a live session is using. A forwarded handshake whose sender index falls in a reserved prefix is dropped (`reserved_index`), and the peer retries with a new random index. Packets whose receiver index is in a reserved prefix go only to that registration tunnel. The relay's own indexes therefore never collide with forwarded sessions.
- **Ping.** The relay answers IPv4 ICMP echo requests to `tunnel_ip`. Running `ping 10.99.0.254` on a configured peer checks its registration.

### The printed [Peer] section

At startup the relay logs the `[Peer]` section that configured peers add, as one `info` event. The event's first line carries the log prefix, and the other lines are the section alone, so it can be copied as it is. `--print-peer` prints only the section to stdout and exits.

- `PublicKey` is derived from `private_key`, which is never printed.
- `Endpoint` is `public_endpoint` verbatim, checked when the config is loaded. Without `public_endpoint`, it is `listen` if that names a specific address, and otherwise the placeholder `<relay public address>:<listen port>`.
- A reload that changes `public_endpoint` or `tunnel_ip` prints the section again. `listen` and `private_key` take effect only after a restart, so until then the section keeps the running values.

## Session table

The session table maps each index to a session entry: `receiver_index → { dst, src, state, since, peer }`.

| Field | Meaning |
|---|---|
| `dst` | where messages carrying the index are sent |
| `src` | the only address allowed to send them |
| `state` | `pending` or `established` |
| `since` | when the entry entered its current state; its lifetime runs from here |
| `peer` | the configured peer the session was routed to, used to revoke sessions on reload |

**Every type 2, 3 and 4 message must arrive from the entry's `src`.**

### Lifetimes

Lifetimes are fixed. Traffic never extends them.

- An **established** entry expires 200 s after its handshake was accepted (`ESTABLISHED_TIMEOUT`), however busy it is. WireGuard never uses a key older than 180 s (`REJECT_AFTER_TIME`), and by then it has moved to a newer session's indexes. The extra 20 s cover the round trip.
- A **pending** entry expires 10 s after the initiation (`PENDING_TIMEOUT`), however many cookie replies pass through it.

Forwarding never writes to an entry. The data plane forwards types 3 and 4 on established entries by reading its own copy of them. The control plane forwards a cookie reply on a pending entry by reading the table.

Garbage collection removes expired entries every second (`GC_INTERVAL`). Counts include expired entries until then. The table gives memory back once garbage collection finds it mostly empty.

### Index ownership

A live entry owns its index. Its address pair is its `src` and `dst`.

- A handshake that picks an index held by a live entry of a different address pair is dropped (`index_in_use`), so nobody can take over an index someone else is using. The peer retries with a new index.
- A live established entry is never replaced, not even by the same address pair. An initiation that re-sends or replays an established session's index is dropped (`index_in_use`). Replacing the entry would turn it back into a pending one, which would cut off the session's traffic and, once answered, restart its lifetime. WireGuard picks a fresh random index for every initiation, so a real peer never does this.
- Re-sending an initiation while its entry is still pending replaces the entry, which starts a new 10 s lifetime.

### Quotas

Four limits bound the table:

| Limit | Constant | Value | When it is reached |
|---|---|---|---|
| pending entries per configured peer | `MAX_PENDING_PER_PEER` | 1,024 | A new initiation to that peer evicts its oldest pending entry, counted as `pending_evicted`. |
| entries per configured peer, pending and established | `MAX_SESSIONS_PER_PEER` | 65,536 | Initiations to the peer and responses from it are dropped (`peer_quota`). |
| pending entries in total | `MAX_PENDING` | 262,144 | Initiations not for the relay are dropped before the mac1 scan (`too_many_pending`). |
| entries in total | `MAX_SESSIONS` | 917,504 | Initiations not for the relay are dropped before the mac1 scan, and responses are dropped (`too_many_sessions`). |

- **Pending entries per peer.** Eviction keeps a flood aimed at one configured peer from disturbing handshakes to any other peer. Even for the targeted peer, a handshake survives if it is answered before the flood sends 1,024 more initiations.
- **Entries per peer.** This leaves room for about 16,000 busy WireGuard sessions, since a busy session holds 4 entries: the current pair, plus the previous pair until it expires. Initiations are dropped right after the mac1 scan. Responses are dropped because they would add the responder's entry. The quota bounds what a configured peer can take by answering spoofed initiations with fabricated responses, and it frees up as the peer's entries expire. It is checked before eviction, so a peer at this quota is refused even if its pending quota could evict.
- **Pending entries in total.** This leaves most of the table to established sessions during a flood of initiations. With the default budgets such a flood cannot reach the limit. Filling it needs at least 256 configured peers at their pending quota, and the scans that create that many entries within their 10 s lifetime cost about three times what the forwarding budget allows in that time.
- **Entries in total.** This is a memory backstop (see [Memory](#memory)). Reaching it takes 14 configured peers at their quota, or about 229,000 busy WireGuard sessions.

### Memory

With every entry established, the `MAX_SESSIONS` cap bounds the session tables at about 240 MB, and about 256 MB at the peak while they grow.

- **Session table.** An entry takes 128 B on a 64-bit build (two socket addresses, a timestamp, a public key, the index and the state), plus one control byte in the `HashMap`. The map keeps at most 7/8 of its buckets full and grows in powers of two. 917,504 is exactly 7/8 of 2^20 buckets, so the full table takes 2^20 × 129 B, about 135 MB. While the map grows to that size, the old half-size table briefly exists alongside it.
- **Data plane copy.** Each established entry also has a copy in the data plane's concurrent map (`papaya`): an 88 B entry allocated on its own, plus an 8 B pointer and a metadata byte per slot. That averages about 117 B per established entry.
- **Everything else.** The per-peer pending queues and counters add a few bytes per pending entry and per configured peer. Each forwarding thread allocates 2 MiB of receive buffers at startup.

## Forwarding rules

The relay never sends cookie replies, or anything else, in answer to forwarded traffic. Nothing on the forwarding path can panic; a 10,000-case mutation test covers this. The [drop reasons](#drop-reasons) are listed in the order the relay checks them.

### Every datagram

1. A datagram whose source can never be a reply destination is dropped (`invalid_source`). That is source port 0, the unspecified address, a multicast address, or the IPv4 broadcast address 255.255.255.255. An IPv4-mapped IPv6 address is unmapped before the check.
2. The datagram is parsed with explicit size checks (`malformed`). Types 1 to 3 must have their exact sizes (148, 92 and 64 B), transport data must be at least 32 B, and the reserved header bytes must be zero.

### Per-source rate limit

Every handshake initiation, for the relay or forwarded, is rate-limited per source before any other work (`rate_limited`). Other message types are not rate-limited.

- A source is an IPv4 address or an IPv6 /64. An IPv4-mapped IPv6 address, which a dual-stack `[::]` socket reports for IPv4 senders, counts as its IPv4 address.
- Each source is hashed with a random key into one of 65,536 fixed buckets, so the limiter's memory is constant (under 2 MB) however many sources appear. Sources that share a bucket share its allowance.
- Each bucket allows `handshake_rate_per_ip` initiations, with a burst of two seconds' worth.

After the rate limit, the relay checks the initiation's mac1 against its own key. A match is a registration initiation, which goes through the [registration budget](#handshake-budgets) and then [registration](#registration). Any other initiation is forwarded as described next.

### Type 1: handshake initiation

A forwarded initiation passes these checks in order:

1. Its sender index must not be in a reserved prefix (`reserved_index`).
2. The table must hold fewer than `MAX_SESSIONS` entries (`too_many_sessions`) and fewer than `MAX_PENDING` pending entries (`too_many_pending`).
3. The forwarding budget must not be spent (`forwarding_budget`).
4. The mac1 scan must find a configured peer P whose key matches (`no_mac1_match`).
5. P must be below its entry quota (`peer_quota`) and registered (`peer_not_registered`).
6. The initiation must not come from P's own endpoint (`loop`). Any other source is accepted.

The relay then records a pending entry for the initiator's index and forwards the initiation to P's endpoint. Storing the entry can still fail with `index_in_use`. If P is at its pending quota, P's oldest pending entry is evicted.

`sessions[sender_index] = {dst: <initiator's address>, src: <P's endpoint>, state: pending, peer: P}`

An unconfigured peer can never receive an initiation, because no configured key matches its mac1. A configured peer therefore cannot start a handshake towards an unconfigured one, but configured peers can start handshakes with each other in both directions.

### Type 2: handshake response

A response must name a live entry by its receiver index (`unknown_index`) and come from that entry's `src`, which is P's endpoint (`wrong_source`). The entry must still be pending (`session_not_pending`), so each initiation gets one response. The responder's sender index must not be in a reserved prefix (`reserved_index`).

The relay then creates an established entry for the responder's sender index and marks the initiator's entry established. Both live 200 s from now. Creating the responder's entry is subject to P's quota (`peer_quota`), the global cap (`too_many_sessions`) and [index ownership](#index-ownership) (`index_in_use`). If it is refused, the initiator's entry stays pending.

The relay does not check whom the configured peer accepted. The peer's own WireGuard peer list is the only authentication. The relay only ensures that the response really comes from the peer's endpoint.

### Types 3 and 4: cookie reply and transport data

Both are forwarded only from the entry's `src` (`wrong_source`), and neither changes the entry. A session lives as long as its fixed lifetime, not as long as someone keeps sending.

- **Transport data** needs a live established entry. The data plane itself drops data on any other index outside the reserved prefixes (`unknown_index`), including data on a pending index, without involving the control plane.
- **A cookie reply** may also pass on a pending entry, so a peer under load can answer an initiation. The control plane decides cookie replies on any index that is not a live established session.

## Handshake budgets

Initiations are unauthenticated, so the CPU work they cause before the sender is known must be bounded:

- Finding a forwarded initiation's destination, the mac1 scan, costs one keyed BLAKE2s per configured key tried, with eight keys hashed per SIMD batch.
- A registration attempt costs an X25519 operation, about as much as 400 key checks.

Two token buckets, one per path, bound this work, so a flood on one path cannot starve the other. Each has a one-second burst, is checked before the work and is charged after it.

| Budget | Constant | Rate | Charge | When it is spent |
|---|---|---|---|---|
| forwarding | `FORWARDING_WORK_PER_SEC` | 1,000,000 mac1 checks per second | the number of keys the scan tried | initiations not for the relay are dropped (`forwarding_budget`) |
| registration | `REGISTRATION_WORK_PER_SEC` | 200,000 mac1 checks per second | 400 per attempt, so 500 attempts per second | registration initiations are dropped (`registration_budget`) |

An initiation goes through these steps:

1. The per-source rate limit.
2. One mac1 check against the relay's own key.
3. A registration initiation from a configured peer's current endpoint skips the registration budget, so only the per-source limit applies to it. Any other registration initiation needs the registration budget, and is charged.
4. Any other initiation follows the [forwarding rules](#type-1-handshake-initiation), which charge the forwarding budget for the scan.

A flood of registration attempts from other addresses therefore cannot stop registered peers from re-handshaking their registration tunnels. A dropped initiation costs only parsing, the limiter and at most one hash, so forwarding continues at full speed during a flood.

### Sizing

Legitimate forwarding load is about `WireGuard sessions × configured peers / 240` mac1 checks per second: every session rekeys every 2 minutes, and a scan tries half the keys on average. The default budget allows, for example, 1,000 configured peers with 200,000 sessions, or 10,000 configured peers with 24,000 sessions. For comparison, the session table's cap holds about 229,000 busy sessions.

Legitimate registration load from addresses that are not registered consists only of first registrations and address changes. At 500 per second, even 10,000 peers re-registering after a relay restart are admitted within 20 s.

## Socket I/O

Each forwarding thread runs a tokio current-thread runtime, which drives its socket and its timer ticks. The main thread's runtime drives the stats timer, the signal handlers and the metrics endpoint.

### Receiving

Each socket is read in batches through `quinn-udp`. One `recvmmsg` call fills up to 32 receive buffers of 64 KiB each, 2 MiB per thread, allocated once at startup.

Where the kernel supports UDP GRO, one buffer can hold up to 64 datagrams from one source that the kernel coalesced on receipt, never more than 64 KiB in total. The relay splits such a buffer at the reported segment size and passes every datagram to `Relay::handle` separately, exactly as if it had arrived alone.

The loop handles one batch per wake-up and charges the runtime's cooperative budget for every receive buffer. Under a sustained flood a thread therefore still yields after a bounded amount of work. A due timer tick or a request to stop is handled before the next batch.

### Sending

Where the kernel supports UDP GSO, the relay hands consecutive forwarded datagrams of a batch to the kernel as one send if they go to the same address, carry the same ECN bits and have the same length (the last one may be shorter). One send holds at most 64 datagrams and 65,507 bytes. The kernel or the NIC splits it back into the very same datagrams.

- A run of datagrams within one receive buffer is sent straight from it. A run that continues into the next buffer is first copied together.
- A run ends at a datagram that the relay drops or consumes, at a change of destination or ECN bits, or at a longer datagram. Datagrams therefore leave byte-identical and in the order they arrived.
- Without GSO, every forwarded datagram is a send of its own.
- If a GSO send fails (some drivers and paths reject GSO), its datagrams are sent again one by one, so only those the network itself refuses are lost. After `EIO` or `EINVAL`, `quinn-udp` stops using GSO for the rest of the process's life, and the relay logs that once at `info`.

The startup line reports whether GRO and GSO are available (`gro=true gso=true`).

### ECN

The ECN bits of a received datagram are copied to the datagrams forwarded from it, so congestion marks reach the far end. WireGuard itself copies them from the inner packet to the outer one. The rest of the TOS byte (DSCP) is not kept. The registration tunnels' own datagrams (handshake messages, keepalives, ping replies) are sent without ECN after each batch or timer tick.

### Kernel settings

When `quinn-udp` sets up a socket, it forbids IP fragmentation and turns on receive timestamps. On Linux the relay restores both settings to what they were before:

- A datagram larger than a path's MTU is then fragmented, as by any other UDP socket, instead of being dropped.
- The timestamps' control message would otherwise leave no room for the ECN bits next to a GRO segment size.

### Binding and thread failure

On Linux the sockets are bound with `SO_REUSEPORT`. Before binding them, the relay binds the address once without it, so a second relay started on the same port fails to start instead of silently taking a share of the flows. On other systems `SO_REUSEPORT` does not spread UDP flows, so the relay runs one forwarding thread, and logs a warning if `workers` asks for more.

If a forwarding thread fails to start, panics or ends, the relay stops the others and exits with an error naming the thread.

## Drop reasons and logs

Every dropped datagram increments a counter for its reason and logs `reject reason=<reason> src=<addr>` at `debug` level. Per-packet logs stay at debug so that nobody can flood the log.

### Drop reasons

In the order the relay checks them:

| Reason | Meaning |
|---|---|
| `invalid_source` | the source can never be a reply destination: port 0, unspecified, multicast or IPv4 broadcast |
| `malformed` | wrong size, type or reserved bytes |
| `rate_limited` | the source (IPv4 address or IPv6 /64) exceeded `handshake_rate_per_ip` |
| `registration_budget` | the registration budget is spent, and the registration initiation did not come from a configured peer's endpoint; dropped before any X25519 work |
| `registration_unknown_key` | the registration initiation came from a key that is not configured |
| `tunnel_auth_failed` | a datagram to a registration tunnel failed authentication |
| `reserved_index` | a forwarded handshake picked an index in a reserved prefix |
| `too_many_sessions` | the session table holds 917,504 entries |
| `too_many_pending` | 262,144 handshakes already await a response, across all configured peers |
| `forwarding_budget` | the forwarding budget is spent; the forwarded initiation was dropped before the mac1 scan |
| `no_mac1_match` | the initiation is not for any configured peer or the relay |
| `peer_quota` | the target configured peer already has 65,536 session entries |
| `peer_not_registered` | the target configured peer has no current registration |
| `loop` | the initiation came from the target's own endpoint |
| `index_in_use` | the handshake's sender index belongs to a live session of another address pair, or to a live established session |
| `unknown_index` | no live session for the receiver index; for transport data, no live established session, so data on a pending or expired index counts here too |
| `wrong_source` | the message did not come from the session's `src` |
| `session_not_pending` | a response to a handshake that was already answered |

### The stats line

Every 60 s the relay logs one line of counters, for example:

```
metrics="rx=74 rx_bytes=9120 forwarded=60 … pending_evicted=0 reject.peer_not_registered=1 reject.unknown_index=4" control="half_open_expired=3 established_expired=0 … gc_runs=60"
```

The line also carries `sessions`, the number of session entries. At shutdown the relay logs the `metrics` field once more.

The `metrics` field holds the datagram counters:

| Counter | Meaning |
|---|---|
| `rx`, `rx_bytes` | datagrams and bytes received |
| `forwarded`, `forwarded_bytes` | datagrams and bytes forwarded |
| `tunnel_rx`, `tunnel_tx` | datagrams taken and sent by the registration tunnels |
| `rx_errors`, `tx_errors` | socket failures. Each failure is logged only at `debug`, since a remote host can cause them at packet rate. |
| `pending_evicted` | pending entries evicted by a newer initiation to the same configured peer. A steady rise means a flood aimed at one peer, which otherwise shows up only as later `unknown_index` drops. |
| `reject.<reason>` | drops for one reason, listed only when non-zero |

The `control` field holds what only the control plane counts: session and registration lifecycles, mac1 work, registration attempts, and registration tunnel errors (`tunnel_error.<kind>`, listed only when non-zero). The [Prometheus metrics](#prometheus-metrics) export the same counters and more.

## Prometheus metrics

### The endpoint

`metrics_listen = "<ip>:<port>"` in `relay.toml` turns on a plain HTTP endpoint. `--metrics-listen <ip>:<port>` and `WG_RELAY_METRICS_LISTEN` override the file.

- It serves the Prometheus text format (version 0.0.4) for `GET /metrics` and `HEAD /metrics`. Other paths get 404, and other methods 405.
- Any IPv4 or IPv6 address works, including the wildcards `0.0.0.0` and `[::]`.
- It is off when unset, and changing it needs a restart.
- The listener is bound at startup, before the forwarding threads start, so an address in use fails startup. The bound address is logged once.
- The endpoint has no authentication or TLS. Bind it to loopback or a private network, or firewall it.

### How a scrape works

The HTTP server runs on the main thread's runtime, never on a forwarding thread. It serves at most 16 connections at once, and answers each within 10 s.

Every scrape takes a fresh snapshot when the request arrives, through the same path as the stats line. Nothing is cached.

- The main thread locks the control plane once, just long enough to copy its counters, its session counts and each configured peer's state. That is one lookup per table per peer, with no scan.
- It copies each forwarding thread's counters. Each thread publishes them after every batch and timer tick, so they are at most a fraction of a second old.

Metrics add almost nothing to the forwarding path: only plain, unshared increments of counters each thread already keeps (bytes per outcome and messages per type). Everything else is counted by the control plane under the lock it already holds, or read at scrape time.

### Labels

Labels have low cardinality only: `reason`, `type`, `state`, `plane`, `direction`, `kind`, `result`, `budget`, `error`, `worker` (the thread index) and `peer` (a configured peer's `name`). Source addresses, session indexes and the keys of unconfigured peers are never labels. Every drop reason, message type, tunnel error kind and worker appears from the start, at zero.

### What to alert on

The abuse signals, roughly in the order they show a flood. [`grafana/alerts.yml`](../grafana/alerts.yml) holds Prometheus alerting rules for them.

- **Half-open handshakes:** `rate(wg_relay_sessions_expired_total{state="pending"}[5m])`. These are initiations that were forwarded but never answered. A flood of spoofed or junk initiations to a configured peer drives the rate up, together with `wg_relay_pending_sessions_evicted_total`. Per server, `wg_relay_peer_sessions{state="pending"}` and `wg_relay_peer_initiations_total{peer}` show which one is targeted.
- **Rate limiting:** `rate(wg_relay_datagrams_dropped_total{reason="rate_limited"}[5m])`. Sources are sending initiations faster than `handshake_rate_per_ip`. If `wg_relay_rate_limit_buckets_used` rises towards `wg_relay_rate_limit_buckets`, the flood comes from many sources.
- **CPU budgets:** `rate(wg_relay_datagrams_dropped_total{reason=~"forwarding_budget|registration_budget"}[5m]) > 0`. Legitimate handshakes are being dropped. `wg_relay_handshake_budget_remaining_checks` is then at or below 0, and `rate(wg_relay_mac1_checks_total[5m])` is near `wg_relay_forwarding_budget_checks_per_second`.
- **Table fullness:** `wg_relay_sessions / wg_relay_sessions_max` or `wg_relay_sessions{state="pending"} / wg_relay_pending_sessions_max` above, say, 0.8, and any `too_many_sessions`, `too_many_pending` or `peer_quota` drops.
- **Junk:** `rate(wg_relay_datagrams_dropped_total{reason="unknown_index"}[5m])` well above its usual level. Some `unknown_index` drops always come from sessions that just expired or roamed. `no_mac1_match`, `malformed` and `invalid_source` are the equivalent signals for handshakes and garbage.
- **Control plane pressure:** the `control` share of `wg_relay_datagrams_decided_total{plane}` rising, meaning that more of the traffic needs the lock.
- **Operations:** `wg_relay_peer_registered == 0` for a server that should be up, and `wg_relay_config_last_reload_successful == 0`.

### All metrics

Traffic, summed over the control plane and every forwarding thread:

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `wg_relay_datagrams_received_total` | counter | | UDP datagrams received |
| `wg_relay_received_bytes_total` | counter | | their UDP payload bytes |
| `wg_relay_datagrams_forwarded_total` | counter | | datagrams forwarded unchanged |
| `wg_relay_forwarded_bytes_total` | counter | | their bytes |
| `wg_relay_datagrams_delivered_locally_total` | counter | | datagrams taken by the registration tunnels |
| `wg_relay_delivered_locally_bytes_total` | counter | | their bytes |
| `wg_relay_datagrams_dropped_total` | counter | `reason` | datagrams dropped, one series per [drop reason](#drop-reasons) |
| `wg_relay_dropped_bytes_total` | counter | | their bytes |
| `wg_relay_messages_received_total` | counter | `type` | received datagrams that parsed as a WireGuard message: `handshake_initiation`, `handshake_response`, `cookie_reply` or `transport_data`. Excludes `invalid_source` and `malformed` drops. |
| `wg_relay_messages_forwarded_total` | counter | `type` | messages forwarded; `cookie_reply` counts the cookie replies passed on |
| `wg_relay_datagrams_decided_total` | counter | `plane` | datagrams by the plane that decided them: `data` (without a lock) or `control` (under its lock, handed over by the data plane) |
| `wg_relay_tunnel_datagrams_sent_total` | counter | | datagrams the registration tunnels sent: handshake messages, keepalives, ping replies and cookie replies |
| `wg_relay_tunnel_sent_bytes_total` | counter | | their bytes |
| `wg_relay_socket_errors_total` | counter | `direction` | failed socket receives (`receive`) and sends (`send`) |

The initiations seen, forwarded and rate-limited are `wg_relay_messages_received_total{type="handshake_initiation"}`, `wg_relay_messages_forwarded_total{type="handshake_initiation"}` and `wg_relay_datagrams_dropped_total{reason="rate_limited"}`. The first also counts registration initiations.

Per forwarding thread, so that skew between threads shows. These count only what the thread's data plane decided; datagrams it handed to the control plane count in the totals only.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `wg_relay_worker_datagrams_total` | counter | `worker` | datagrams the data plane decided on this thread |
| `wg_relay_worker_bytes_total` | counter | `worker` | their bytes |
| `wg_relay_worker_datagrams_forwarded_total` | counter | `worker` | datagrams the data plane forwarded on this thread |
| `wg_relay_worker_forwarded_bytes_total` | counter | `worker` | their bytes |
| `wg_relay_worker_socket_errors_total` | counter | `worker`, `direction` | socket failures on this thread |

Sessions and garbage collection:

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `wg_relay_sessions` | gauge | `state` | session entries, `pending` or `established`, including expired ones not yet collected |
| `wg_relay_sessions_max` | gauge | | `MAX_SESSIONS`, the cap on all entries; there is no separate cap on established ones |
| `wg_relay_pending_sessions_max` | gauge | | `MAX_PENDING` |
| `wg_relay_peer_sessions_max` | gauge | | `MAX_SESSIONS_PER_PEER` |
| `wg_relay_peer_pending_sessions_max` | gauge | | `MAX_PENDING_PER_PEER` |
| `wg_relay_sessions_expired_total` | counter | `state` | entries removed at the end of their fixed lifetime; `pending` ones are half-open handshakes that were never answered. Established entries expire on schedule, not when idle. |
| `wg_relay_pending_sessions_evicted_total` | counter | | pending entries evicted by a newer initiation to the same configured peer |
| `wg_relay_sessions_revoked_total` | counter | | entries removed by a reload together with their configured peer |
| `wg_relay_sessions_roamed_total` | counter | | entries rewritten because their configured peer moved |
| `wg_relay_gc_runs_total` | counter | | garbage collection passes; what they remove is counted by the two `_expired_total` counters |

Sessions refused because a table was full are the `too_many_sessions`, `too_many_pending` and `peer_quota` series of `wg_relay_datagrams_dropped_total`.

Handshake cost, meaning rate limiting, budgets, mac1 work and registration:

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `wg_relay_handshake_rate_per_source` | gauge | | `handshake_rate_per_ip`, in initiations per second |
| `wg_relay_rate_limit_buckets_used` | gauge | | per-source rate-limit buckets some source has used since startup. The table is fixed, so buckets are never freed, and sources that hash to the same bucket share it. |
| `wg_relay_rate_limit_buckets` | gauge | | rate-limit buckets in all (65,536) |
| `wg_relay_forwarding_budget_checks_per_second` | gauge | | `FORWARDING_WORK_PER_SEC` |
| `wg_relay_registration_budget_checks_per_second` | gauge | | `REGISTRATION_WORK_PER_SEC` |
| `wg_relay_handshake_budget_remaining_checks` | gauge | `budget` | mac1 checks the `forwarding` or `registration` budget would allow now; at or below 0, its initiations are dropped |
| `wg_relay_mac1_scans_total` | counter | | scans of the configured peers' keys for a forwarded initiation's destination |
| `wg_relay_mac1_checks_total` | counter | | mac1 keys hashed: every key a scan tried, plus the relay's own key once per initiation |
| `wg_relay_registration_initiations_total` | counter | `result` | initiations to the relay itself that passed the rate limit: `accepted` by a registration tunnel, or `rejected` (registration budget, unknown key or failed authentication) |
| `wg_relay_registration_key_exchanges_total` | counter | | X25519 operations spent identifying the senders of registration initiations |
| `wg_relay_tunnel_errors_total` | counter | `error` | datagrams a registration tunnel refused, grouped from boringtun's errors: `replay` (stale timestamp or counter), `authentication` (bad MAC, tag or key), `session` (unknown index, expired session), `under_load` or `other` |
| `wg_relay_tunnel_cookie_replies_sent_total` | counter | | cookie replies the registration tunnels sent because they were under load |

Budget exhaustion is the `forwarding_budget` and `registration_budget` series of `wg_relay_datagrams_dropped_total`.

Configured peers and registrations:

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `wg_relay_configured_peers` | gauge | | configured peers |
| `wg_relay_registered_peers` | gauge | | configured peers with a live registration |
| `wg_relay_reserved_prefixes` | gauge | | index prefixes reserved for registration tunnels, one per configured peer |
| `wg_relay_registrations_total` | counter | `kind` | `new`: a peer that was not registered registered; `roamed`: a registered peer moved to a new endpoint |
| `wg_relay_registrations_expired_total` | counter | | registrations that timed out |
| `wg_relay_peer_registered` | gauge | `peer` | 1 if the configured peer is registered |
| `wg_relay_peer_last_authenticated_timestamp_seconds` | gauge | `peer` | when the peer last authenticated on its registration tunnel; absent while the registry holds nothing for it |
| `wg_relay_peer_sessions` | gauge | `peer`, `state` | session entries routed to the peer; `pending` ones are initiations aimed at it that await its answer |
| `wg_relay_peer_initiations_total` | counter | `peer`, `result` | initiations whose mac1 named the peer: `forwarded`, or `dropped` after the scan (not registered, at its quota, a loop, an index in use, a full table). Counted since the peer was configured, so a removed and re-added peer starts again at 0. |

The relay and the process:

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `wg_relay_config_reloads_total` | counter | `result` | reloads, `success` or `failure` |
| `wg_relay_config_last_reload_successful` | gauge | | 0 if the last reload failed and the previous config is still running; 1 before any reload |
| `wg_relay_config_last_reload_success_timestamp_seconds` | gauge | | when the config was last applied, at startup or by a reload |
| `wg_relay_workers` | gauge | | forwarding threads |
| `wg_relay_build_info` | gauge | `version` | always 1 |
| `process_start_time_seconds` | gauge | | when the process started |
| `process_cpu_seconds_total` | counter | | user and system CPU time (Linux) |
| `process_resident_memory_bytes` | gauge | | resident memory (Linux) |
| `process_virtual_memory_bytes` | gauge | | virtual memory (Linux) |
| `process_open_fds` | gauge | | open file descriptors (Linux) |
| `process_max_fds` | gauge | | the soft limit on open files, unless unlimited (Linux) |

### Not exported

These figures are not exported, because counting them would add shared state to the lock-free forwarding path or a scan under the control plane's lock:

- forwarded traffic per configured peer, because the data plane's established sessions do not record which configured peer they belong to;
- per-session or per-source figures;
- how many rate-limit buckets are empty right now, which would need a scan of all 65,536;
- whether an established session was idle when it expired, because the relay never tracks idleness.

## Reload (SIGHUP)

On `SIGHUP` the relay re-reads and validates `relay.toml`. If the file is invalid, the running config stays in effect and an error is logged. Changes to `listen`, `workers`, `private_key` and `metrics_listen` need a restart; the relay logs a warning and keeps the running values. Everything else applies immediately:

- A **removed peer** loses its registration, its registration tunnel and every session routed to it. The next packet of any of those sessions, in either direction, is dropped (`unknown_index`).
- Sessions with peers that are still configured are untouched.
- Unconfigured peers are revoked in the configured peers' WireGuard configs, not at the relay.

## Limitations

### Connectivity

- **An unconfigured peer that changes network loses data for about 5–15 s.** This happens on a move from Wi-Fi to cellular, or on NAT rebinding. Its packets now come from a new address that does not match the session's `src`, so they are dropped (`wrong_source`). WireGuard starts a new handshake on its own once it stops hearing back (keepalive timeout plus rekey timeout), and the new session works normally.
- **A configured peer that moves loses data until it re-registers.** It re-registers on its next authenticated packet to the relay, and its sessions are then rewritten to its new endpoint. Data sent in the meantime is lost.
- **Unconfigured peers cannot receive initiations**, because the relay cannot tell which peer such a handshake is for. Clients normally start the handshake, and the side that started a session also does its timed rekeys, so with `PersistentKeepalive` this rarely matters. When the server must send first, for example right after it restarts, that traffic waits until the client sends something. To make a peer reachable, add it to `relay.toml`; it then registers like a server.
- **Two configured peers cannot register from the same `ip:port`.** The newest claimant wins, and a warning is logged.
- **Index collisions** between independent sessions (probability 2⁻³² per pair) make the newer handshake fail once (`index_in_use`). Its retry uses a new index.
- **The ICMP responder is IPv4-only.**

### Trust

- **Each configured peer's own WireGuard peer list is the only authentication.** Strangers' handshakes reach the configured peer, which drops them. The relay learns an unconfigured peer's address from the initiation it forwards. An on-path attacker who replays a peer's fresh initiation from another address, ahead of the original, can therefore make that handshake fail. That is a denial of service only.
- **Packets spoofed from a configured peer's endpoint (`ip:port`) are trusted as that peer.** The source address is the only check on the forwarding path. This needs the peer's endpoint and a network path that allows spoofing it. With that:
  - Relay-bound initiations from the endpoint skip the registration budget and are limited only per source. X25519 work from such packets therefore grows with the number of registered peers times `handshake_rate_per_ip` instead of being capped.
  - Fake responses from it establish pending sessions to that peer, and fake cookie replies pass on pending sessions, though they do not extend them.
  - The per-peer and global quotas bound the memory this can take. It remains a denial-of-service lever against that one peer, whose quota it can fill.
- **A configured peer can fill its own quota.** A malicious or compromised configured peer can answer spoofed initiations aimed at itself with fabricated responses. Each creates two established entries for 200 s, until the peer holds 65,536 entries. That denies new sessions only to that peer: other peers have their own quotas, and the global cap needs 14 such peers. Conversely, a configured peer that genuinely carries more than about 16,000 busy sessions reaches its quota (`peer_quota`) and needs `MAX_SESSIONS_PER_PEER` raised.
- **The relay cannot cap who uses its bandwidth.** A configured peer can accept any number of unconfigured peers. Only handshakes are rate-limited, per source (IPv4 address or IPv6 /64).

### Floods

- **WireGuard's cookie defence is weaker behind the relay.** A server under load binds its cookies to the sender's address, but every packet it receives comes from the relay. One cookie obtained through the relay is therefore valid for initiations from any source, even a spoofed one. The relay's per-source rate limit and forwarding budget are then the only brakes. See [How it works, section 3.5](how-it-works.md#35-cookies-wireguards-defence-under-load).
- **The per-source initiation limit is charged before any check.** Someone who can spoof a peer's source address can use up that peer's allowance and delay its handshakes. For a configured peer, that includes its re-registration.
- **The per-source initiation limit is shared** by all hosts behind one NAT address or in one IPv6 /64, and by unrelated sources that hash to the same bucket. Many distributed sources are held back only by the handshake budgets.
- **A flood spread over the whole address space empties every rate-limit bucket.** There are 65,536 buckets. Spoofed initiations from sources spread across all of them, at roughly 65,536 × `handshake_rate_per_ip` per second (655,360 per second at the default 10/s), leave every bucket empty.
  - Until the flood ends, every host's new handshakes and rekeys are dropped (`rate_limited`). This includes registered configured peers' re-handshakes with the relay.
  - Established sessions keep forwarding.
  - Keepalives on a registration tunnel are not rate-limited, so a configured peer stays registered until its tunnel's current keys age out, at most 180 s after its last handshake with the relay. Its registration then expires 180 s later.
- **Spoofed initiations can crowd out handshakes to one configured peer.** Each spoofed initiation aimed at a configured peer takes one of that peer's 1,024 pending slots. A flood that cycles through all of them before the peer's response comes back evicts every legitimate pending entry. With a 100 ms round trip that takes about 10,000 initiations per second. New handshakes to that peer, and only that peer, then fail until the flood ends. Other peers' handshakes, established sessions and memory are unaffected.
- **Junk initiations can exhaust the forwarding budget.** A mac1 cannot be looked up by index, so an initiation that matches no key costs a scan of every configured key before it can be dropped. During a sustained flood of them, forwarded handshakes compete for the budget. Established sessions keep forwarding and registration tunnels are unaffected, but new handshakes and rekeys between peers may be dropped (`forwarding_budget`) until the flood ends.
- **During a registration flood, a peer registering from a new address competes for the registration budget.** That covers a first registration, NAT rebinding, and every peer after a relay restart. Such registrations may be delayed (`registration_budget`) until the flood ends. Peers already registered from their current address are not affected.

### Performance

- **One flow, one core.** The kernel keeps every flow (source and destination address pair) on one forwarding thread. A single busy flow, such as a configured peer's tunnel to the relay carrying all its traffic, is therefore bound by one core however many threads run. Flows are spread by hash, so a few heavy flows can land on the same thread.
- **Handshakes take turns.** The control plane is one `Mutex`. Every datagram the data plane hands over (handshake messages, registration tunnel datagrams, and cookie replies on an index that is not a live established session), every timer tick and every reload holds it while it is decided.
  - That work does not scale with threads, and a thread waiting for the lock stops forwarding meanwhile. A flood of handshakes or of junk cookie replies (64 B each) therefore stalls every thread that receives part of the flood.
  - Junk transport data with made-up indexes never takes the lock. The data plane drops it (`unknown_index`) after one lookup in the established sessions and one in the reserved prefixes. Only data aimed at a registration tunnel's prefix reaches the control plane.
  - Each handshake also costs a mac1 scan over the configured peers, eight keys per SIMD batch, which is fine for thousands of keys.
- **Changes reach other threads slightly late.** After a reload removes a peer, after garbage collection, or after a roam, a thread may still forward the rest of a batch it is already deciding on the old entry. Later lookups see the change. A session established by a handshake response is published before the response is sent on, so the initiator's first data always finds it.
- **Failed GSO sends cost extra sends.** After `EIO` or `EINVAL` from a GSO send (from a driver without UDP segmentation offload, for example), GSO stays off until a restart, and forwarding continues with one send per datagram. Other failures leave GSO on. To a destination whose path MTU is smaller than the forwarded datagrams, every run first fails as a GSO send (`EMSGSIZE`) and then goes one fragmented datagram at a time. If the kernel rejects the ECN control message itself (very old kernels), `quinn-udp` stops setting it, and forwarded IPv4 datagrams lose their ECN bits.

## The namespace integration test

`tests/netns.sh` runs an end-to-end test with kernel WireGuard. It needs root, the `wireguard` kernel module, `iproute2`, `wireguard-tools`, `iptables`, `tcpdump` and `ping`. Without root on the host, a privileged container works:

```sh
cargo build --bins --examples
docker run --rm --privileged -v "$PWD":/src:ro -w /src debian:trixie-slim bash -c \
  'apt-get update -qq && apt-get install -y -qq iproute2 wireguard-tools iptables tcpdump iputils-ping >/dev/null && tests/netns.sh'
```

The test builds four hosts in Linux network namespaces. Each is behind its own MASQUERADE NAT and runs kernel WireGuard. The relay runs three forwarding threads.

| Host | Role |
|---|---|
| server | configured in `relay.toml`, so it registers |
| `c1` | a client the server knows; unconfigured |
| `c2` | a client the server knows; configured in `relay.toml`, so it registers too |
| stranger | knows the server's public key but is not one of the server's peers; unconfigured |

The test asserts that:

1. the server and `c2` register with the relay, and a scrape of `/metrics` shows two registered peers;
2. both clients ping the server;
3. the stranger gets nothing through. A `tcpdump` on the server's LAN, decrypted offline with the server's key by `examples/pcap_check.rs --initiators`, shows that the stranger's handshakes reach the server, which drops them;
4. pings still work after a **server-initiated** rekey towards the configured `c2` (the server removes and re-adds it), and after **client-initiated** rekeys from both clients;
5. removing the server from `relay.toml` and sending `SIGHUP` cuts its sessions off immediately, while `c2` stays registered;
6. in the capture at the relay, forwarded handshakes cannot be opened with the relay's private key (the server's key opens them), forwarding is byte-identical, and the ping payload never appears on the wire.

## The throughput benchmark

`examples/bench_forward.rs` measures forwarding throughput through a real relay process on loopback. Its purpose is to compare changes to the forwarding path between builds.

```sh
cargo build --release --bins --examples
target/release/examples/bench_forward          # plain sends, one datagram each
target/release/examples/bench_forward --gso    # bursts that reach the relay as GRO buffers
target/release/examples/bench_forward --bin /tmp/old/wg-relay --senders 8 --secs 10 --sizes 64,512,1420
taskset -c 4-7 target/release/examples/bench_forward --workers 2 --flows 64 --servers 8 --senders 4 --relay-cpus 0-3
```

### What it does

1. It starts the relay binary with a temporary config that lists the servers.
2. It registers each server through a real handshake with the relay.
3. It completes one client handshake through the relay per flow. Each flow has its own client socket, and the flows go to the servers in turn. All handshakes use boringtun.
4. It sends each flow's encrypted data packet over and over from the sender threads. The relay does not check counters, so one packet can be repeated. One counting thread per server counts what reaches the server sockets.
5. At the end it removes the relay process and the temporary config.

For each plaintext size it prints:

- the rate the senders offered;
- the forwarded rate, in packets per second and in Mbit/s of UDP payload;
- the loss;
- the share of forwarded datagrams that kept the ECN bits they were sent with (ECT(0));
- the relay's CPU time per second of the measurement window, read from `/proc` (100% is one core).

### Options

| Option | Default | Meaning |
|---|---|---|
| `--bin` | `target/release/wg-relay` | the relay binary to measure |
| `--secs` | 5 | measurement time per size, in seconds |
| `--senders` | 4 | sending threads. Raise it until there is loss: only then is the relay, not the senders, setting the rate. |
| `--flows` | 1 | client sockets, each with its own session through the relay |
| `--servers` | 1 | configured peers receiving the flows |
| `--workers` | not set | the relay's `workers` setting. When not given, the key is left out of the config, because older builds reject it. |
| `--sizes` | `64,1420` | plaintext sizes in bytes, comma-separated |
| `--gso` | off | send bursts with one GSO call each |
| `--junk` | 0 | extra client sockets, each with its own sending thread, that send the same data packet under made-up indexes. The relay drops them (`unknown_index`), so the forwarded rate shows what such a flood costs the real flows. |
| `--relay-cpus` | not set | run the relay under `taskset` on these CPUs |
| `--relay-log` | `warn` | the relay's log filter (`RUST_LOG`) |

### Getting meaningful numbers

- The kernel keeps each flow on one forwarding thread, so spreading load over threads needs many flows.
- With one server, every forwarded datagram lands in one socket, whose lock caps the rate on loopback. More servers are needed to see the relay's own limit.
- The senders and the relay compete for cores. `--relay-cpus` runs the relay on the given CPUs; running the benchmark itself under `taskset` on the other CPUs keeps the two apart.

### What it can and cannot show

It shows the relay's cost per datagram and per send, compared between builds on the same machine. Compare builds, not machines.

It cannot show the behaviour of a real network interface. Loopback has no NIC, so there is no driver GRO and no hardware offload, and the receiving side of every send is processed in software.

- Plain sends reach the relay one datagram per receive buffer. The relay still merges consecutive ones into GSO sends, copying them together.
- `--gso` sends bursts with one GSO call each. Loopback delivers each burst to the relay's GRO-enabled socket as one coalesced buffer, as a NIC's GRO would, so this mode exercises the zero-copy path.

## Code layout

| File | Purpose |
|---|---|
| `src/message/` | wire-format parsing, size checks, mac1, `SessionIndex` |
| `src/tables/registry.rs` | the registry: each configured peer's current endpoint |
| `src/tables/sessions.rs` | the session table, with its per-peer quotas and global cap |
| `src/tables/session.rs` | one session entry and its fixed lifetimes |
| `src/tables/accounting.rs` | the session table's per-peer and pending accounts |
| `src/tables/established.rs` | the view of established sessions that the session table keeps for the data plane |
| `src/tables/rate_limit.rs` | per-source token buckets |
| `src/tables/budget.rs` | work budgets |
| `src/relay/mod.rs` | `Relay`, which does no I/O, with one handle per thread (`share`). `handle` asks the data plane without a lock, then locks the control plane for what the data plane hands over. `record_verdict` turns an outcome into a `Verdict` and counts it. |
| `src/relay/data_plane.rs` | the data plane: `DataPlane::triage` forwards, drops or hands a datagram to the control plane, reading only. Also `ReservedPrefixes`, which only the control plane writes. |
| `src/relay/control_plane/` | the control plane: `ControlPlane` and its state |
| `src/relay/control_plane/dispatch.rs` | the per-source limit, and `classify`, which sorts datagrams into one `Class` per case for one `match` over the handlers |
| `src/relay/control_plane/forward.rs` | forwarded handshakes and sessions |
| `src/relay/control_plane/registration.rs` | registration tunnels |
| `src/relay/control_plane/reload.rs` | reload |
| `src/relay/control_plane/timers.rs` | the tick's throttle, registration tunnel timers and garbage collection |
| `src/relay/verdict.rs`, `src/relay/metrics.rs`, `src/relay/metrics/control.rs` | `DropReason`, `Verdict`, the datagram counters each plane keeps (`Metrics`), and those only the control plane keeps (`ControlMetrics`: lifecycles, mac1 work, registration tunnel errors) |
| `src/relay/snapshot.rs`, `src/relay/control_plane/snapshot.rs` | `ControlSnapshot`, the control plane's counters, session counts and configured peers, copied in one hold of its lock; `LIMITS` |
| `src/config/` | `relay.toml` parsing and validation, `Rate`, `PublicEndpoint`, `RelayPeer` (the `[Peer]` section configured peers paste) and the `--check-config` summary |
| `src/main.rs` | parses the CLI, sets up logging, reports errors |
| `src/app.rs` | the clap `Cli` (`--check-config`, `--print-peer`, `--metrics-listen`), startup and shutdown |
| `src/app/supervisor.rs` | the main thread's loop: it watches the forwarding threads, logs stats, applies reloads, answers scrapes and handles `SIGHUP`, `SIGINT` and `SIGTERM` |
| `src/app/workers.rs` | the forwarding threads as a group: starting, watching, stopping and joining them, their counters, and the `Snapshot` shared by the stats line and scrapes |
| `src/app/forwarding.rs` | one forwarding thread: batched receive, forwarding, timer ticks and the relay's own datagrams |
| `src/app/metrics/` | the Prometheus endpoint: the text encoder (`encoder.rs`), the metric families by topic (`traffic.rs`, `state.rs`, `handshakes.rs`, `peers.rs`, `process.rs`) and a minimal HTTP server on tokio's `TcpListener` (`http.rs`) |
| `src/udp.rs` | the `SO_REUSEPORT` socket group and batched socket I/O on `quinn-udp`: `recvmmsg` with GRO, GSO sends, ECN, and the kernel settings it restores |
| `src/udp/runs.rs` | splitting GRO buffers into datagrams and grouping forwarded datagrams into GSO sends (pure and unit-tested) |
| `src/key/` | `PublicKey` and `PrivateKey` base64 newtypes |
| `src/error.rs` | `AppError` and the `Report` error-chain printer |
