# wg-relay

wg-relay is a UDP relay for WireGuard. It lets standard, unmodified WireGuard clients reach WireGuard servers that sit behind NAT, without a public address or port forward on either side. The relay forwards encrypted packets unchanged and never holds a key that could decrypt them.

The relay is configured with nothing more than the public keys of the peers that must be reachable, usually the servers. Clients need no entry at all, and a single relay serves any number of independent WireGuard networks.

```
   network A                                             network A
   server ──NAT──┐                         ┌──NAT── laptop, phone
                 ├──►      wg-relay   ◄────┤
   network B     │    (public UDP port)    │         network B
   server ──NAT──┘                         ├──NAT── laptop
                                           └───✗─── unknown host (dropped)
```

## Features

- **Stock WireGuard on every endpoint.** Kernel `wg`, wireguard-go and the mobile apps work unmodified. No agent, custom client or coordination service is involved.
- **No inbound connectivity required.** Every host only sends to the relay, so servers and clients can sit behind any NAT, including carrier-grade NAT.
- **End-to-end encryption is preserved.** The relay holds no session keys and forwards datagrams byte for byte. A compromised relay can drop traffic, but cannot read or modify it, and cannot add peers.
- **Many networks on one relay.** Adding a network means adding its server's public key. Networks are isolated from one another by their own WireGuard peer lists.
- **Minimal configuration.** The relay lists only the peers that must be reachable. Who may connect to them is decided where it always is in WireGuard: in each peer's own config.
- **Abuse resistance.** Only configured peers can register, and a session is established only when a configured peer answers. Handshakes are rate-limited per source and by separate CPU budgets for forwarding and registration, so a flood cannot stall forwarding and cannot stop registered peers from staying registered; pending handshakes and session entries have a quota per configured peer, so a flood aimed at one network does not refuse handshakes to the others and a misbehaving configured peer cannot fill the session table; session entries expire a fixed time after their handshake, however much traffic arrives; memory stays bounded however many sources appear; and the relay cannot be used as a reflector.
- **Simple to operate.** One binary, one UDP port and one TOML file. Configuration reloads on `SIGHUP`, and a removed peer is cut off immediately. The relay prints the `[Peer]` section servers paste, and can serve Prometheus metrics. The implementation is about 5,000 lines of Rust.

## How it works

WireGuard leaves a few header fields readable by design. wg-relay routes using only those fields.

1. **Registration.** Each configured peer, typically a server, adds the relay as an ordinary WireGuard peer. This tunnel proves to the relay, cryptographically, at which address the peer can currently be reached, and keeps its NAT mapping open.
2. **Destination by mac1.** Every handshake carries a MAC keyed with the recipient's public key. The relay tests it against the configured keys and identifies the destination without decrypting anything.
3. **Sessions by index.** Each side announces a random session index in its handshake, in cleartext. The relay records which index belongs to which address, and routes the rest of the session by index.

[How wg-relay works](docs/how-it-works.md) describes the design in detail, with diagrams: the WireGuard protocol, every packet path, the state the relay keeps, roaming and the security model.

## Multiple networks

The relay holds a list of peers, identified by public key: the ones that must be reachable, usually one server per network. Several independent networks, run by different people, can therefore share one relay: each network's owner provides their server's public key, and the relay operator adds it to `relay.toml`.

```toml
[[peer]]
name = "alice-home"
pubkey = "<alice's server public key>"

[[peer]]
name = "bob-office"
pubkey = "<bob's server public key>"
```

- **Isolation.** A session is established only if the configured peer accepts the other side in its own WireGuard config. Alice's laptop is not a peer of Bob's server, so Bob's server drops its handshakes.
- **Clients are not configured on the relay.** Each network's owner adds and removes their own clients in their server's WireGuard config, without involving the relay operator.
- **Private keys stay private.** The relay operator never sees any network's private keys, and cannot read or join any network's traffic.
- **Independent addressing.** The relay never sees the addresses inside the tunnels, so networks may use overlapping subnets. The only shared address is the relay's own `tunnel_ip` (`10.99.0.254` by default), which no network should assign to a peer.
- **Scale.** The relay tests each handshake against the configured keys, eight at a time with SIMD, which is fast enough for thousands of keys. Each configured peer costs about 11 KB of memory for its registration tunnel.

Changes take effect on `SIGHUP`, without a restart and without disturbing other networks.

## Quick start

**1. Build the relay.**

```sh
cargo build --release
```

**2. Write `relay.toml`.** Generate the relay's key with `wg genkey`, then list the server by public key:

```toml
listen = "0.0.0.0:51820"
private_key = "<relay private key>"
tunnel_ip = "10.99.0.254"         # the relay's address inside each configured peer's tunnel
handshake_rate_per_ip = "10/s"
public_endpoint = "relay.example.com:51820"  # where peers reach the relay
# workers = 4                     # forwarding threads; default one per CPU
# metrics_listen = "127.0.0.1:9586"  # Prometheus metrics at /metrics; off by default

[[peer]]
name = "main"
pubkey = "<server public key>"
```

**3. Configure the server.** Add the relay as a peer, and set the relay as the endpoint of every client peer. The relay prints its own `[Peer]` section at startup, and `wg-relay --print-peer -c relay.toml` prints only that section, ready to paste:

```ini
[Interface]
PrivateKey = <server private key>
Address    = 10.99.0.1/24
ListenPort = 51820            # any port; no port forward needed

[Peer]
# wg-relay: registration tunnel only
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

**4. Configure the client.** The client has no entry in `relay.toml`. It uses an ordinary configuration in which the server's endpoint is the relay:

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

**5. Start the relay and verify.**

```sh
./target/release/wg-relay --check-config -c relay.toml   # validate; prints roles and warnings
./target/release/wg-relay --print-peer -c relay.toml     # the [Peer] section for each server
RUST_LOG=info ./target/release/wg-relay -c relay.toml
ping 10.99.0.254                                         # on the server: confirms registration
ping 10.99.0.1                                           # on the client: confirms the tunnel
```

Keep `PersistentKeepalive` on every peer. It keeps NAT mappings and registrations current.

The printed `Endpoint` is `public_endpoint` verbatim. Without it, the relay uses `listen` if that names a specific address, and otherwise prints `<relay public address>:<port>` for you to fill in. The section changes only if a reload changes `public_endpoint` or `tunnel_ip`, and is then printed again. It never contains the private key.

## Access control

There is a single rule: **a session is established only when a configured peer answers from its endpoint.** Anyone may send a handshake to a configured peer, and the peer's own WireGuard peer list decides whether to answer, so a handshake from an unknown host is dropped there.

| To | Edit |
|---|---|
| add or remove a client | the server's WireGuard config |
| add or remove a network, or make a peer reachable | `relay.toml`, then `SIGHUP` |
| cut a configured peer off immediately | remove it from `relay.toml`, then `SIGHUP` |

Configured peers can reach one another in both directions. An unconfigured peer can start a handshake with a configured peer, but cannot receive one, so a peer that must be reachable, for example a laptop that a server calls first, can be added to `relay.toml` too.

## Trust model

| The relay can | The relay cannot |
|---|---|
| see which keys communicate, when, and how much | decrypt any traffic |
| see each host's public IP address and port | inject or modify packets: WireGuard rejects them |
| drop or delay packets | add a peer: each configured peer's own config decides |

The relay's own private key opens only the registration tunnels, which carry keepalives and pings to `10.99.0.254` and nothing else.

## Limitations

- **All traffic passes through the relay.** There is no direct peer-to-peer path, so the relay's latency and bandwidth apply.
- **Network changes interrupt traffic briefly.** When a client changes network, for example from Wi-Fi to mobile data, traffic stops for about 5–15 s until WireGuard performs a new handshake.
- **A single relay is a single point of failure.** There is no failover.
- **A configured peer cannot initiate a handshake to an unconfigured peer.** Clients normally initiate handshakes themselves, so this rarely matters; a peer that must be reachable can be added to `relay.toml`.
- **The relay cannot cap who uses its bandwidth.** A configured peer can accept any number of unconfigured peers; only handshakes are rate-limited.
- **WireGuard's handshake flood protection is weaker behind the relay.** The relay's per-source rate limit and forwarding budget compensate in part; see [section 3.5 of the guide](docs/how-it-works.md#35-under-load-cookies-and-mac2).
- **A sustained handshake flood delays new sessions.** Existing sessions keep forwarding, but legitimate handshakes compete with the flood: junk initiations compete with all forwarded handshakes for the forwarding budget, a flood aimed at one configured peer can evict pending handshakes to that peer, and a registration flood delays peers that register from a new address.
- **One flow is forwarded by one core.** The relay forwards on several threads, but the kernel keeps each flow (address pair) on one of them, and handshakes are decided one at a time. Ping replies are IPv4-only.

The [reference](docs/reference.md#limitations) gives the complete list with the reasoning behind each item, and the [guide's security model](docs/how-it-works.md#15-security-model) covers threats and defences.

## Operation

```sh
kill -HUP $(pidof wg-relay)                                     # reload relay.toml
RUST_LOG=wg_relay=debug ./target/release/wg-relay -c relay.toml # log every rejected packet
WG_RELAY_CONFIG=/etc/wg-relay.toml ./target/release/wg-relay    # every flag also reads an env var (see --help)
```

Every rejected packet is counted under a named reason, such as `wrong_source` or `rate_limited`. The counters are logged every minute and at shutdown. The [reference](docs/reference.md) lists every reason, along with the exact forwarding and reload rules.

## Metrics

With `metrics_listen` set (for example `"127.0.0.1:9586"`), or `--metrics-listen` / `WG_RELAY_METRICS_LISTEN`, which override it, the relay serves Prometheus metrics over plain HTTP at `/metrics`. It is off by default, and changing it needs a restart. The endpoint has no authentication, so keep it on loopback or a private network, or firewall it.

```yaml
scrape_configs:
  - job_name: wg-relay
    static_configs:
      - targets: ["127.0.0.1:9586"]
```

In Docker (here an image built with `docker build -t wg-relay .`), listen on all of the container's interfaces and publish the port only to the host's loopback or a private network, without editing the mounted config:

```sh
docker run -d --name wg-relay -p 51820:51820/udp -p 127.0.0.1:9586:9586 \
  -e WG_RELAY_METRICS_LISTEN=0.0.0.0:9586 \
  -v /etc/wg-relay/relay.toml:/etc/wg-relay/relay.toml:ro wg-relay
```

Every scrape takes a fresh snapshot: the stats line's counters, plus session counts against their limits, the cost of unauthenticated handshakes (rate limiting, CPU budgets, mac1 scans, registration attempts) and each configured peer's state, labelled by its name in `relay.toml`. Addresses, session indexes and keys never appear in labels. Worth graphing or alerting on:

- `wg_relay_peer_registered{peer}`: 0 means that server cannot be reached through the relay.
- `rate(wg_relay_sessions_expired_total{state="pending"}[5m])`: half-open handshakes, the clearest sign of an initiation flood; `wg_relay_peer_initiations_total{peer}` shows which server it targets.
- `rate(wg_relay_datagrams_dropped_total{reason}[5m])`: floods show up as `rate_limited`, `no_mac1_match`, `unknown_index`, `forwarding_budget` or `registration_budget`; a full table as `too_many_sessions`, `too_many_pending` or `peer_quota`.
- `rate(wg_relay_forwarded_bytes_total[5m])` and `wg_relay_sessions{state}` for load, `wg_relay_worker_datagrams_total{worker}` for skew between forwarding threads.
- `wg_relay_config_last_reload_successful`: 0 after a `SIGHUP` that failed and left the old config running.

The [reference](docs/reference.md#prometheus-metrics) lists every metric and what to alert on.

### Grafana dashboard and alerts

[`grafana/wg-relay.json`](grafana/wg-relay.json) is a Grafana (10 or later) dashboard for these metrics: an overview, traffic, drops and abuse signals, sessions, configured peers, forwarding threads and the process. Import it under Dashboards > New > Import, or put it in a directory a dashboard provider loads. It has no fixed data source: pick the Prometheus data source, job and instance in the variables at the top. [`grafana/alerts.yml`](grafana/alerts.yml) holds Prometheus alerting rules for the signals in "What to alert on"; add it to `rule_files` in `prometheus.yml` and tune the thresholds marked as such to your traffic.

## Testing

```sh
cargo test                                             # unit and in-process tests
cargo build --bins --examples && sudo tests/netns.sh   # end-to-end, with kernel WireGuard
cargo build --release --bins --examples && target/release/examples/bench_forward  # throughput on loopback
```

The end-to-end test builds a network in Linux network namespaces: a server, two clients and a stranger, each behind its own NAT and running kernel WireGuard. It verifies that both clients connect and the stranger does not, that rekeys work in both directions, including one the server starts towards a configured client, and that `SIGHUP` revokes a removed peer immediately. A packet capture at the relay verifies that the relay's key cannot open forwarded handshakes and that every forwarded packet is byte-identical. The [reference](docs/reference.md#the-namespace-integration-test) explains how to run the test in Docker without root on the host. The benchmark forwards encrypted data packets through a real relay process and prints packets per second and Mbit/s, so builds can be compared; the [reference](docs/reference.md#the-throughput-benchmark) explains what it can and cannot show.

## Documentation

- [How wg-relay works](docs/how-it-works.md): the design, with diagrams.
- [Reference](docs/reference.md): forwarding rules, reject reasons, reload behaviour, limitations, the test suite and the code layout.
- [`relay.example.toml`](relay.example.toml): a commented example configuration.
