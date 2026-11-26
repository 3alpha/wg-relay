# wg-relay reference

The exact rules wg-relay follows and its known limitations. For a guided tour with diagrams, read [How wg-relay works](how-it-works.md). For setup, see the [README](../README.md).

## Design

`relay.toml` lists the peers that must be reachable, by public key: usually the servers. Listed peers register with the relay; everyone else is unlisted and needs no relay config. One UDP socket carries two kinds of traffic: registration tunnels with listed peers, and forwarded traffic between peers. [How it works](how-it-works.md) defines these and the other terms used here (session, pending, established, reserved prefix) at its top.

Inside, the relay is split into two halves. The **forwarding half** (`Forwarder`) holds only the established sessions (index to destination, expected source and the time it was established) and the reserved prefixes (prefix to listed peer); it forwards transport data and cookie replies on live established sessions, drops what it can judge alone (`invalid_source`, `malformed`, `wrong_source`, and `unknown_index` for transport data on an index that is neither a live established session nor in a reserved prefix), never writes, and hands everything else to the control half: handshake messages, messages to a registration tunnel, and cookie replies on an index that is not a live established session. The **control half** (`Control`) owns everything that changes: listed peers and their registration tunnels, the registry, the rate limiter, the budgets, the session table with its quotas and lifetimes, reload. It is the forwarding half's only writer: the session table publishes or withdraws an established entry in the same call that changes it, so the two never disagree, and the control half reserves a prefix when it creates a registration tunnel and frees it when the tunnel's peer is removed. The control half reads the same reserved prefixes; there is no second copy. No established session is ever in a reserved prefix, so the forwarding half looks up the prefixes only when the established sessions miss, and forwarded data never pays for that lookup.

The relay runs `workers` forwarding threads (one per CPU the process may use by default). Each has its own UDP socket bound to the listen address with `SO_REUSEPORT`, so the kernel spreads incoming flows across the sockets by their address pair and keeps every flow on one thread, in order. All threads share one relay: they read the forwarding half at the same time without locks (a concurrent hash map, `papaya`), and lock the control half, a `Mutex`, only for the datagrams the forwarding half hands over and for the timers and reloads. Whichever thread handled a datagram sends the result on its own socket, together with any datagrams the registration tunnels queued, since every socket has the same address. Every forwarding thread offers the control half a timer tick every 250 ms (`TICK_INTERVAL`) and sends what the registration tunnels' timers queue; the control half runs at most one tick per interval. The threads are all alike: the main thread forwards nothing, and starts them, runs the stats line, SIGHUP and shutdown, and checks every 250 ms that each is still running. Each thread counts what its forwarding half decided; the stats and shutdown lines add every thread's counters to the control half's.

### Registration (listed peers only)

Each listed peer has the relay as a `[Peer]` with `AllowedIPs = <tunnel_ip>/32` and `PersistentKeepalive = 25`. The relay runs one `boringtun::noise::Tunn` per listed peer.

* A handshake initiation whose mac1 is keyed to the **relay's** public key is a registration initiation. `parse_handshake_anon` decrypts the sender's static key. Keys that are not listed are rejected (`registration_unknown_key`). A listed peer's initiation goes to its `Tunn`, which performs the full handshake, including replay protection.
* After **every packet that authenticates** on a listed peer's tunnel (data or a keepalive; never a bare initiation, which could be a replay, and never a cookie), the relay sets `registry[peer] = src_addr`. If the address changed (roaming), every session table entry using the old address is rewritten. Entries expire after 180 s.
* **The relay's indexes never collide with forwarded sessions.** Each registration tunnel owns a random 24-bit index prefix, a reserved prefix, so it uses 256 indexes. A new prefix is never one that a live session is using, and any forwarded handshake that picks an index inside a reserved prefix is dropped (`reserved_index`), so the peer retries with a new random index. Packets in a reserved prefix go only to that registration tunnel.
* The relay answers ICMP echo to `tunnel_ip` (`ping 10.99.0.254` from a listed peer checks its registration).

### Session table

`receiver_idx → { dest_addr, expected_src_addr, established, since, peer }`, where `since` is when the entry entered its current state and `peer` is the listed peer the session was routed to, used to revoke sessions on reload. **Every type 2, 3 and 4 packet must arrive from `expected_src_addr`.**

Lifetimes are fixed and never extended by traffic. An established entry expires 200 s after its handshake was accepted (`ESTABLISHED_TTL`), however busy it is: WireGuard never uses a key older than 180 s (`REJECT_AFTER_TIME`) and has moved to a newer session's indexes by then, so the extra 20 s only cover the round trip. A pending entry (an initiation without an accepted response) expires 10 s after the initiation (`PENDING_TTL`), whatever cookie replies pass through it. Types 3 and 4 on an established entry are forwarded by the forwarding half, which only reads its copy of the established entries, and a cookie reply on a pending entry by the control half, which only reads the table. Expired entries are removed by a sweep every second.

Quotas bound the table:

* **Pending entries per listed peer**: at most 1,024 (`MAX_PENDING_PER_PEER`). A new initiation for a peer at this quota evicts that peer's oldest pending entry (counted as `pending_evicted` in the stats), so a flood aimed at one listed peer disturbs only handshakes to that peer, and even there a handshake answered within the time the flood takes to send 1,024 more initiations survives.
* **Entries per listed peer**, pending and established together: at most 65,536 (`MAX_SESSIONS_PER_PEER`), room for about 16,000 busy sessions (a busy session holds 4 entries: the current pair, plus the previous pair until it expires). A peer at this quota gets no new entries, and initiations to it are dropped right after the mac1 scan (`peer_quota`); so are responses from it, which would add the responder's entry. This bounds what a listed peer that answers spoofed initiations with fabricated responses can take, and the quota frees up as its entries expire. It is checked before eviction, so a peer at this quota is refused even if its pending quota could evict.
* **Pending entries in total**: at most 262,144 (`MAX_PENDING`), so a flood of initiations leaves most of the table to established sessions; beyond that, initiations not for the relay are dropped before the mac1 scan (`too_many_pending`). With the default budgets a flood of initiations cannot reach it: filling it needs at least 256 listed peers at quota, and the scans that create that many entries within their 10 s lifetime cost about three times what the forwarding budget allows in that time.
* **Entries in total**: at most 917,504 (`MAX_SESSIONS`), a memory backstop. Beyond it, initiations not for the relay are dropped before the mac1 scan and responses are dropped too (`too_many_sessions`). An entry takes 128 B on a 64-bit build (two socket addresses, a timestamp, a public key, the index and state) plus one control byte in the `HashMap`, which keeps at most 7/8 of its buckets full and grows in powers of two: 917,504 is exactly 7/8 of 2^20 buckets, so the full table takes 2^20 × 129 B, about 135 MB. While it grows into that size the old half-size table briefly coexists with it. Each established entry also has a copy in the forwarding half's concurrent map (`papaya`), which the forwarding threads read without locks: an 88 B entry allocated on its own, plus an 8 B pointer and a metadata byte per slot, about 117 B per established entry on average. With every entry established, the cap therefore bounds the two tables at about 240 MB, about 256 MB at the peak while they grow. The per-peer pending queues and counters add a few bytes per pending entry and per listed peer, and each forwarding thread allocates 2 MiB of receive buffers at startup. Reaching the cap takes 14 listed peers at their quota, or about 229,000 busy sessions.

Counts include expired entries until the next sweep. The table gives memory back once the sweep finds it mostly empty. A handshake that picks an index held by a live entry of a different address pair is dropped (`index_in_use`), so nobody can take over an index someone else is using; the peer retries with a new index. A live **established** entry is never replaced, not even by the same address pair: re-sending (or replaying) an initiation with the index of an established session is dropped (`index_in_use`) instead of turning the entry back into a pending one, which would cut off the session's traffic and, once answered, restart its lifetime. WireGuard picks a fresh random index for every initiation, so a real peer never does this. Re-sending an initiation while its entry is still pending replaces the entry, which starts a new 10 s.

### Forwarding rules

Before any other work, a datagram whose source can never be a reply destination is dropped (`invalid_source`): source port 0, the unspecified address, a multicast address, or the IPv4 broadcast address 255.255.255.255, after unmapping an IPv4-mapped IPv6 address.

Every initiation is rate-limited per source first. Then, unless it is for the relay and comes from a listed peer's registered address, it must fit in one of two handshake budgets (below). A source is an IPv4 address or an IPv6 /64 (an IPv4-mapped IPv6 address, as a dual-stack `[::]` socket reports IPv4 senders, counts as its IPv4 address), hashed with a random key into one of 65,536 fixed buckets, so the limiter's memory is constant (under 2 MB) however many sources appear; sources that share a bucket share its allowance.

**Type 1, handshake initiation** not for the relay, a forwarded initiation (`sender_idx` must not be in a reserved prefix; then the global session cap, the global pending cap and the forwarding budget are checked before the scan):

* **mac1 matches a listed peer P**, which must be below its quota of entries (`peer_quota`) and registered (`peer_not_registered`). Accepted from any source except P's own address (`loop`). The relay records `idx[sender] = {dest: src, expected_src: addr(P), established: false, peer: P}`, evicting P's oldest pending entry if P is at its quota, and forwards to P.
* Otherwise the packet is dropped (`no_mac1_match`). An unlisted peer can therefore never receive an initiation: a listed peer cannot start a handshake towards it, but listed peers can start handshakes with each other in both directions.

**Type 2, handshake response** (it must match a pending entry and come from its `expected_src`, the listed peer's registered address):

* The initiator's entry becomes `established`, and an established entry is created for the responder's `sender_idx`; both live 200 s from now. Creating it is subject to P's quota (`peer_quota`) and the global cap (`too_many_sessions`); if refused, the initiator's entry stays pending.
* A response to an entry that is already established is dropped (`session_not_pending`): one response per initiation.

The relay does not check who the listed peer accepted. Its own WireGuard peer list is the only authentication; the relay only ensures the response really comes from it.

**Types 3 and 4** (cookie reply and transport data) are forwarded only from `expected_src`. Data requires an `established` session: the forwarding half drops data on any other index outside the reserved prefixes itself (`unknown_index`, a pending index included), without the control half. A cookie reply may also pass on a pending one, so a peer under load can answer an initiation. Neither changes the entry: a session lives as long as its lifetime, not as long as someone keeps sending.

### Handshake budgets

Initiations are unauthenticated, so their cost must be bounded. Scanning for the destination costs one keyed BLAKE2s per listed key, with eight keys hashed per SIMD batch, and a registration attempt costs an X25519 operation, about as much as 400 key checks, before the sender is known. Two token buckets, each with a one-second burst, are checked before that work and charged after it, so a flood on one path cannot starve the other:

* **Forwarding**, `FORWARDING_WORK_PER_SEC` = 1,000,000 mac1 checks per second, charged the number of keys a scan tried. When it is empty, initiations not for the relay are dropped (`forwarding_budget`).
* **Registration**, `REGISTRATION_WORK_PER_SEC` = 200,000 mac1 checks per second, charged 400 per attempt, so 500 attempts per second. When it is empty, registration initiations are dropped (`registration_budget`).

The order for an initiation is: the per-source limit; one mac1 check against the relay's own key; for a registration initiation, **if `src` is the address a listed peer is currently registered from, the registration budget is skipped** (only the per-source limit applies), otherwise the registration budget is required and charged; any other initiation goes to the forwarding rules above. A flood of registration attempts from other addresses therefore cannot stop registered peers from re-handshaking their registration tunnels. Dropped initiations cost only parsing, the limiter and at most one hash, so forwarding continues at full speed during a flood.

Legitimate forwarding load is about `sessions × listed peers / 240` checks per second: every session rekeys every 2 minutes, and a scan tries half the keys on average. The default allows, for example, 1,000 listed peers with 200,000 sessions, or 10,000 with 24,000; the session table's cap holds about 229,000 busy sessions. Legitimate registration load from unregistered addresses is only first registrations and address changes, and at 500 per second even 10,000 peers re-registering after a relay restart are admitted within 20 s.

### Other rules

The relay never sends cookie replies (or anything else) for forwarded traffic. Datagrams are parsed with explicit size checks: exact sizes for types 1–3, at least 32 B for data, and the reserved bytes must be zero. Nothing on the forwarding path can panic. This is covered by a 10 000-case mutation test.

### Socket I/O

Each forwarding thread runs a tokio current-thread runtime that drives its own socket and its timer ticks; the main thread's runtime drives the stats timer and the signal handlers. Each socket is read in batches through `quinn-udp`: one `recvmmsg` call fills up to 32 receive buffers of 64 KiB each (2 MiB per thread, allocated once at startup). Where the kernel supports UDP GRO, one buffer can hold up to 64 datagrams from one source that the kernel coalesced on receipt, never more than 64 KiB in total. The relay splits such a buffer at the reported segment size and passes every datagram to `Relay::handle` on its own, exactly as if it had arrived alone.

Forwarded datagrams leave through UDP GSO where the kernel supports it. Consecutive datagrams of a batch that go to the same address, carry the same ECN bits and have the same length (the last one may be shorter) are handed to the kernel as one send of at most 64 datagrams and 65,507 bytes, which the kernel or the NIC splits back into the very same datagrams. A run within one receive buffer is sent straight from it; a run that continues into the next buffer is copied together first. A datagram the relay drops or consumes, a change of destination or ECN bits, or a longer datagram ends a run, so datagrams leave byte-identical and in the order they arrived. Without GSO, every forwarded datagram is a send of its own. If a GSO send fails (some drivers and paths reject GSO), its datagrams are sent again one by one, so only those the network itself refuses are lost; after `EIO` or `EINVAL`, `quinn-udp` stops using GSO for the rest of the process's life, and the relay logs that once at `info`. The startup line reports whether GRO and GSO are available (`gro=true gso=true`).

The ECN bits of a received datagram are copied to the datagrams forwarded from it, as WireGuard copies them from the inner packet to the outer one, so congestion marks reach the far end. The rest of the TOS byte (DSCP) is not kept. The registration tunnels' own datagrams (handshake responses, keepalives, ping replies) are sent without ECN after every batch.

When it sets up the socket, `quinn-udp` forbids IP fragmentation and turns on receive timestamps. On Linux the relay puts both back as the kernel had them: a datagram larger than a path's MTU is fragmented as by any other UDP socket instead of being dropped, and the timestamps' control message would leave no room for the ECN bits next to a GRO segment size.

The loop handles one batch per wake-up and charges the runtime's cooperative budget for every receive buffer, so under a sustained flood a thread still yields after a bounded amount of work. A due timer tick or a request to stop comes before the next batch.

On Linux the sockets are bound with `SO_REUSEPORT`; before binding them the relay binds the address once without it, so a second relay started on the same port fails as before instead of silently taking a share of the flows. Elsewhere `SO_REUSEPORT` does not spread UDP flows, so the relay runs one forwarding thread and logs a warning if `workers` asked for more. If a forwarding thread fails to start, panics or ends, the relay stops the others and exits with an error naming the thread.

## Rejects and metrics

Every rejected datagram increments a per-reason counter and logs `reject reason=<reason> src=<addr>` at `debug` level. Per-packet logs are kept at debug because otherwise anyone could flood the log. Counters are logged every 60 s and at shutdown, for example `rx=74 forwarded=60 … pending_evicted=0 reject.peer_not_registered=1 reject.unknown_index=4`. Besides the rejects, `forwarded` counts datagrams forwarded, `tunnel_rx` and `tunnel_tx` count datagrams taken and sent by the registration tunnels, `recv_errors` and `send_errors` count socket failures (logged individually only at `debug`, since a remote host can cause them at packet rate), and `pending_evicted` counts pending entries evicted by a newer initiation to the same listed peer: a steady rise means a flood aimed at one peer, which otherwise shows up only as later `unknown_index` drops.

The reasons, in the order the relay checks them:

| Reason | Meaning |
|---|---|
| `invalid_source` | the source can never be a reply destination: port 0, unspecified, multicast or IPv4 broadcast |
| `malformed` | wrong size, type or reserved bytes |
| `rate_limited` | the source (IPv4 address or IPv6 /64) exceeded `handshake_rate_per_ip` |
| `registration_budget` | the registration budget is spent and the registration initiation did not come from a registered address; dropped before any X25519 work |
| `registration_unknown_key` | the registration initiation came from a key that is not listed |
| `tunnel_auth_failed` | a datagram to a registration tunnel failed authentication |
| `reserved_index` | a forwarded handshake picked an index in the relay's range |
| `too_many_sessions` | the session table holds 917,504 entries |
| `too_many_pending` | 262,144 handshakes already await a response, across all listed peers |
| `forwarding_budget` | the forwarding budget is spent; the forwarded initiation was dropped before the mac1 scan. Called `handshake_budget` before, a name that hid that registration has its own budget |
| `no_mac1_match` | the initiation is not for any listed peer or the relay |
| `peer_quota` | the target listed peer already has 65,536 session entries |
| `peer_not_registered` | the target listed peer has no current registration |
| `loop` | the initiation came from the target's own address |
| `index_in_use` | the handshake's `sender_idx` belongs to a live session of another address pair, or to a live established session |
| `unknown_index` | no live session for `receiver_idx`; for transport data, no live established session, so data on a pending or expired index counts here too |
| `wrong_source` | the packet is not from the session's `expected_src_addr` |
| `session_not_pending` | a response to a handshake that was already answered |

## Reload (SIGHUP)

`relay.toml` is re-read and validated. If it is invalid, the current config stays in effect and an error is logged. Changes to `listen`, `workers` and `private_key` need a restart (a warning is logged). Everything else applies immediately:

* A **removed peer** loses its registration, its registration tunnel and every session routed to it. The next packet of any of those sessions is rejected (`unknown_index`), in both directions.
* Sessions with peers that are still listed are untouched.
* Unlisted peers are revoked in the listed peers' WireGuard configs, not at the relay.

## Limitations

* **An unlisted peer that changes network** (Wi-Fi to cellular, NAT rebinding) **loses data until it re-handshakes, about 5–15 s.** Its packets now come from a new address, which no longer matches `expected_src_addr`, so they are dropped (`wrong_source`). WireGuard starts a new handshake on its own once it stops hearing back (keepalive timeout plus rekey timeout), and the new session then works normally. A listed peer that moves re-registers on its next authenticated packet to the relay and its sessions are migrated, but data sent in the meantime is lost.
* **Each listed peer's own WireGuard peer list is the only authentication**, and strangers' handshakes reach the listed peer (it drops them). The relay learns an unlisted peer's address from the initiation it forwards, so an on-path attacker who replays a peer's fresh initiation from another address first can make that handshake fail. That is a denial of service only.
* **Unlisted peers cannot receive initiations**: the relay cannot tell which peer such a handshake is for. Clients normally start the handshake, and the side that started a session also does its timed rekeys, so with `PersistentKeepalive` this rarely matters. When the server must send first (e.g. right after it restarts), that traffic waits until the client sends something. List a peer to make it reachable; it then registers like a server.
* **The relay cannot cap who uses its bandwidth.** A listed peer can accept any number of unlisted peers; only handshakes are rate-limited, per source (IPv4 address or IPv6 /64).
* **WireGuard's cookie defence is weaker behind the relay.** A server under load binds cookies to the sender's address, but it sees every packet coming from the relay, so one cookie obtained through the relay is valid for initiations from any (even spoofed) source. The relay's per-source rate limit and forwarding budget are then the only brakes. See [How it works, section 3.5](how-it-works.md#35-under-load-cookies-and-mac2).
* **The per-source initiation limit is charged before any check**, so someone who can spoof a peer's source address can use up that peer's allowance and delay its handshakes (for a listed peer, including its re-registration).
* **The per-source initiation limit is shared** by all hosts behind one NAT address or in one IPv6 /64, and by unrelated sources that hash to the same bucket. Many distributed sources are held back only by the handshake budgets.
* **A flood spread over the whole address space saturates every rate-limit bucket.** There are 65,536 buckets, so spoofed initiations from sources spread across all of them at roughly 65,536 × `handshake_rate_per_ip` per second (655,360 per second at the default 10/s) leave every bucket empty, including those of registered listed peers, whose re-handshakes with the relay are then dropped (`rate_limited`) until the flood ends, as are every other host's new handshakes and rekeys. Established sessions keep forwarding, and keepalives on a registration tunnel are not rate-limited, so a listed peer stays registered until its tunnel's current keys age out (at most 180 s after its last handshake with the relay) and its registration then expires (180 s later).
* **Spoofed initiations can crowd out handshakes to one listed peer.** Each one aimed at a listed peer takes one of that peer's 1,024 pending slots. A flood that cycles through all of them before the peer's response comes back (with a 100 ms round trip, about 10,000 initiations per second) evicts every legitimate pending entry, so new handshakes to that peer (only) fail until the flood ends. Other peers' handshakes, established sessions and memory are unaffected.
* **Junk initiations can exhaust the forwarding budget.** A mac1 cannot be looked up by index, so an initiation that matches no key costs a scan of every listed key before it can be dropped. A sustained flood of them makes forwarded handshakes compete for the budget: established sessions keep forwarding and registration tunnels are unaffected, but new handshakes and rekeys between peers may be dropped (`forwarding_budget`) until the flood ends.
* **During a registration flood, a peer registering from a new address competes for the registration budget.** That covers a first registration, NAT rebinding and every peer after a relay restart; their registrations may be delayed (`registration_budget`) until the flood ends. Peers already registered from their current address are not affected.
* **Packets spoofed from a listed peer's registered `ip:port` are trusted as that peer.** The source address is the only check on the forwarding path. Relay-bound initiations from it skip the registration budget and are limited only per source, so X25519 work from such packets grows with the number of registered peers times `handshake_rate_per_ip` instead of being capped. Fake responses from it establish pending sessions to that peer, and fake cookie replies pass on pending ones (but no longer extend them). The per-peer and global quotas bound the memory this can take; it remains a denial-of-service lever against that one peer, whose quota it can fill. This needs the registered `ip:port` and a network path that allows spoofing it.
* **A listed peer can fill its own quota.** A malicious or compromised listed peer can answer spoofed initiations aimed at itself with fabricated responses, each creating two established entries for 200 s, until it holds 65,536 entries. That denies new sessions only to itself; other peers have their own quotas, and the global cap needs 14 such peers. Conversely, a listed peer that genuinely carries more than about 16,000 busy sessions reaches its quota (`peer_quota`) and needs `MAX_SESSIONS_PER_PEER` raised.
* **Two listed peers cannot register from the same `ip:port`.** The newest claimant wins and a warning is logged.
* **Index collisions** between independent sessions (probability 2⁻³² per pair) make the newer handshake fail once (`index_in_use`); its retry uses a new index.
* **One flow, one core.** The kernel keeps every flow (source and destination address pair) on one forwarding thread, so a single busy flow, such as one listed peer's tunnel to the relay carrying all its traffic, is bound by one core however many threads run. Flows are spread by hash, so a few heavy flows can land on the same thread.
* **Handshakes take turns.** The control half is one `Mutex`: every datagram the forwarding half hands over (handshake messages, registration tunnel datagrams, and cookie replies on an index that is not a live established session), every timer tick and every reload holds it while it is decided, so that work does not scale with threads, and a thread waiting for it stops forwarding meanwhile. Under a flood of handshakes or of junk cookie replies (64 B each), that stalls every thread receiving part of the flood, not just one thread as before. Junk transport data with made-up indexes never takes the lock: the forwarding half drops it (`unknown_index`) after one lookup in the established sessions and one in the reserved prefixes, and only data aimed at a registration tunnel's prefix reaches the control half. Each handshake also costs a mac1 scan over the listed peers, eight keys per SIMD batch, which is fine for thousands of keys.
* **Changes reach other threads a little late.** After a reload removes a peer, an expiry sweep or a roam, a thread may forward the rest of a batch it is already deciding on the old entry; later lookups see the change. A session established by a handshake response is published before the response is sent on, so the initiator's first data always finds it.
* **Failed GSO sends cost extra sends.** After `EIO` or `EINVAL` from a GSO send (a driver without UDP segmentation offload, for example), GSO stays off until a restart and forwarding continues with one send per datagram. Other failures leave GSO on: to a destination whose path MTU is smaller than the forwarded datagrams, every run first fails as a GSO send (`EMSGSIZE`) and then goes one datagram at a time, fragmented. If the kernel rejects the ECN control message itself (very old kernels), `quinn-udp` stops setting it and forwarded IPv4 datagrams lose their ECN bits.
* The ICMP responder is IPv4-only, and metrics are logged rather than exported.

## The namespace integration test

`tests/netns.sh` needs root, the `wireguard` kernel module, `iproute2`, `wireguard-tools`, `iptables`, `tcpdump` and `ping`. Without root on the host, a privileged container works:

```sh
cargo build --bins --examples
docker run --rm --privileged -v "$PWD":/src:ro -w /src debian:trixie-slim bash -c \
  'apt-get update -qq && apt-get install -y -qq iproute2 wireguard-tools iptables tcpdump iputils-ping >/dev/null && tests/netns.sh'
```

The test runs a server, two clients the server knows and a stranger. `relay.toml` lists the server and the second client `c2`, which both register; the first client `c1` and the stranger are unlisted. The stranger knows the server's public key but is not one of the server's peers. Each host is behind its own MASQUERADE NAT and runs kernel WireGuard. The test asserts that:

1. the server and `c2` register with the relay;
2. both clients ping the server;
3. the stranger gets nothing through. A `tcpdump` on the server's LAN, decrypted offline with the server key by `examples/pcap_check.rs --initiators`, shows its handshakes reach the server, which drops them;
4. pings still work after a **server-initiated** rekey towards the listed `c2` (the server removes and re-adds it), and after **client-initiated** rekeys from both clients;
5. removing the server from `relay.toml` and sending `SIGHUP` cuts its sessions off immediately, while `c2` stays registered;
6. in the relay-side capture, forwarded handshakes cannot be opened with the relay's private key (the server's key opens them), forwarding is byte-identical, and the ping payload never appears on the wire.

## The throughput benchmark

`examples/bench_forward.rs` measures forwarding throughput through a real relay process on loopback, so that changes to the forwarding path can be compared the same way:

```sh
cargo build --release --bins --examples
target/release/examples/bench_forward          # plain sends, one datagram each
target/release/examples/bench_forward --gso    # bursts that reach the relay as GRO buffers
target/release/examples/bench_forward --bin /tmp/old/wg-relay --senders 8 --secs 10 --sizes 64,512,1420
taskset -c 4-7 target/release/examples/bench_forward --workers 2 --flows 64 --servers 8 --senders 4 --relay-cpus 0-3
```

It starts the binary given by `--bin` (default `target/release/wg-relay`) with a temporary config listing `--servers` peers (default 1) and, if `--workers` is given, that many forwarding threads (older builds reject the key, so it is left out otherwise). It registers each server through a real handshake with the relay and completes one client handshake through it per flow (`--flows`, default 1), each flow from its own client socket and to the servers in turn, all with boringtun. It then sends each flow's encrypted data packet over and over from `--senders` threads (the relay does not check counters) and counts what reaches the server sockets, one counting thread per server. For each plaintext size it prints the rate the senders offered, the forwarded rate in packets per second and in Mbit/s of UDP payload, the loss, the share of forwarded datagrams that kept the ECN bits they were sent with (ECT(0)), and the relay's CPU time per second of the window from `/proc` (100% is one core). Raise `--senders` until there is loss: only then is the relay, not the senders, setting the rate. `--junk` adds that many client sockets, each with its own sending thread, that send the same data packet under made-up indexes, which the relay drops (`unknown_index`): the forwarded rate then shows what such a flood costs the real flows. The child process and the temporary config are removed at the end.

The kernel keeps each flow on one forwarding thread, so spreading load over threads needs many flows; with one server every forwarded datagram also lands in one socket, whose lock caps the rate on loopback, so more servers are needed to see the relay's own limit. Senders and relay compete for cores: `--relay-cpus` runs the relay under `taskset` on the given CPUs, and running the bench itself under `taskset` on the others keeps the two apart.

What it can show is the relay's cost per datagram and per send, compared between builds on the same machine. What it cannot show is a real interface: loopback has no NIC, so there is no driver GRO and no hardware offload, and the receiving side of every send is processed in software. Plain sends reach the relay one datagram per receive buffer (the relay still merges consecutive ones into GSO sends, copying them together); `--gso` sends bursts with one GSO call each, which loopback delivers to the relay's GRO-enabled socket as one coalesced buffer, as a NIC's GRO would, so it exercises the zero-copy path. Compare builds, not machines.

## Code layout

| File | Purpose |
|---|---|
| `src/packet/` | wire-format parsing, size checks, mac1, `SessionIdx` |
| `src/tables/` | soft state: `registry.rs`; `sessions.rs` the session table with fixed lifetimes (`entry.rs`), per-peer quotas and a global cap, its per-peer and pending accounts in `ledger.rs`, and the established-session view it keeps for the forwarding half in `established.rs`; `rate_limit.rs` per-source token buckets; `budget.rs` work budgets |
| `src/relay/mod.rs` | `Relay` (no I/O), one handle per thread (`share`): `handle` asks the forwarding half without a lock, then locks the control half for what it hands over; `settle` turns an outcome into a `Verdict` and counts it |
| `src/relay/forwarder.rs` | the forwarding half: `Forwarder::triage` forwards, drops or hands a datagram to the control half, read only; `ReservedPrefixes`, which only the control half writes |
| `src/relay/control/` | the control half: `Control` and its state; `dispatch.rs` the per-source limit, `classify` into one `Class` per case and one `match` over the handlers; `forward.rs` forwarded handshakes and sessions, `registration.rs` registration tunnels, `reload.rs`, `timers.rs` the tick's cadence, registration tunnel timers and the expiry sweep |
| `src/relay/reason.rs`, `metrics.rs` | `Reason`, `Verdict` and the counters each half keeps |
| `src/config/` | `relay.toml` parsing and validation, `Rate`, `--check-config` summary |
| `src/main.rs` | parse the CLI, set up logging, report errors |
| `src/app.rs` | clap `Cli`, startup and shutdown, the main thread: it supervises the forwarding threads, logs stats and handles SIGHUP/SIGINT/SIGTERM |
| `src/app/workers.rs` | the forwarding threads as a group: start, watch, stop and join them, their counters |
| `src/app/forwarding.rs` | one forwarding thread: batched receive, forwarding, timer ticks, the relay's own datagrams |
| `src/udp.rs` | the `SO_REUSEPORT` socket group and batched socket I/O on `quinn-udp`: `recvmmsg` with GRO, GSO sends, ECN, the kernel settings kept |
| `src/udp/runs.rs` | splitting GRO buffers into datagrams and grouping forwarded datagrams into GSO sends (pure, unit-tested) |
| `src/key/` | `PeerKey` / `PrivateKey` base64 newtypes |
| `src/error.rs` | `AppError` and the `Report` error-chain printer |
