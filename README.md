# wg-relay

wg-relay is a small, self-hosted UDP relay that lets ordinary WireGuard clients reach WireGuard servers behind NAT. Neither side needs a public address or a port forward, and the relay cannot read the traffic it forwards.

WireGuard itself has only peers. Here a *server* is a peer that runs all the time and answers handshakes that others start, and a *client* is a peer, such as a laptop or phone, that connects out and starts the handshakes. The relay knows neither role. It only distinguishes peers whose public key is listed in `relay.toml`, called *configured peers*, and in the usual setup those are the servers.

```
   network A                                             network A
   server ──NAT──┐                         ┌──NAT── laptop, phone
                 ├──►      wg-relay   ◄────┤
   network B     │    (public UDP port)    │         network B
   server ──NAT──┘                         ├──NAT── laptop
                                           └───✗─── unknown host (dropped)
```

## Why use it

- **No port forwarding.** Neither the server nor the clients need a port forward, a public address or any router configuration. Only the relay needs a public UDP port.
- **Stock WireGuard on every peer.** Kernel WireGuard, wireguard-go and the official mobile apps work unmodified. Nothing else is installed on any peer.
- **No accounts and no third party.** There is no login, identity provider or coordination server.
- **Clients need no relay configuration.** The relay's config lists only the servers.
- **The relay cannot read traffic.** It holds no peer keys and forwards datagrams byte for byte. A compromised relay can drop traffic, but cannot read or modify it, and cannot add peers.
- **Access control stays in WireGuard.** You distribute keys and admit peers in each peer's own config, exactly as without the relay.
- **Small and self-hosted.** One binary with one UDP port and one TOML file, about 5,000 lines of Rust. It ships as the container image `ghcr.io/3alpha/wg-relay`, with a [`docker-compose.yml`](docker-compose.yml) in the repository.
- **Many networks on one relay.** Each network is isolated by its own WireGuard peer lists.
- **Bounded under abuse.** Handshakes are rate-limited and budgeted, session state has quotas and fixed lifetimes, and memory stays bounded however many sources appear. The [reference](docs/reference.md) has the exact rules.

## Compared with Tailscale

| | wg-relay | Tailscale |
|---|---|---|
| Software on each device | stock WireGuard | the Tailscale client |
| Accounts | none | an account with an identity provider |
| Coordination server | none | Tailscale's hosted one, or self-hosted Headscale |
| Keys and access rules | your own WireGuard configs, managed as usual | distributed by the coordination server, with ACLs |
| Data path | always through the relay, with no NAT hole punching | direct where NAT traversal succeeds, DERP relays as fallback |
| Extras | none: no mesh management, DNS or ACL layer | ACLs, MagicDNS, key management |

Tailscale is the better choice for many devices, managed access and direct paths between peers. wg-relay fits a few servers behind NAT, clients that should run nothing beyond WireGuard, and setups without a third party. Its cost is that all traffic crosses the relay, which adds latency and uses the relay's bandwidth.

## How it works

WireGuard leaves a few header fields readable by design, and wg-relay routes using only those.

1. **Registration.** Each server adds the relay as an ordinary WireGuard peer. This *registration tunnel* proves to the relay where the server can currently be reached, and its keepalives hold the server's NAT mapping open.
2. **Destination by mac1.** Every handshake initiation carries a MAC, called mac1, keyed with the recipient's public key. The relay checks it against the configured servers' keys to find the destination, without decrypting anything.
3. **Sessions by index.** Each side announces a random session index in cleartext in its handshake. The relay records which index belongs to which address, and routes the rest of the session by index.

[How wg-relay works](docs/how-it-works.md) explains the design in detail, with diagrams.

## Quick start

### What changes in each peer's WireGuard config

**Server.** Add one `[Peer]` for the relay. The relay prints this block at startup and with `--print-peer`. The client entries stay as they are; if one sets an `Endpoint`, point it at the relay.

```diff
 [Interface]
 PrivateKey = <server private key>
 Address    = 10.99.0.1/24
 ListenPort = 51820   # any port; no port forward needed

+[Peer]
+# wg-relay: registration tunnel only
+PublicKey           = <relay public key>
+Endpoint            = relay.example.com:51820
+AllowedIPs          = 10.99.0.254/32
+PersistentKeepalive = 25
+
 [Peer]
 PublicKey  = <laptop public key>
 AllowedIPs = 10.99.0.11/32
```

**Client.** The server's `Endpoint` changes from the server's address to the relay's, and `PersistentKeepalive` is added if it was not set.

```diff
 [Interface]
 PrivateKey = <laptop private key>
 Address    = 10.99.0.11/32

 [Peer]
 PublicKey           = <server public key>
-Endpoint            = server.example.com:51820
+Endpoint            = relay.example.com:51820
 AllowedIPs          = 10.99.0.1/32
+PersistentKeepalive = 25
```

Keys, addresses and `AllowedIPs` do not change. Keep both `PersistentKeepalive` lines: they keep NAT mappings and the registration current.

### Running the relay

**1. Write `relay.toml`** with a key from `wg genkey` and the server's public key:

```toml
private_key = "<relay private key>"
public_endpoint = "relay.example.com:51820"  # optional: fills in the printed Endpoint

[[peer]]
name = "main"
pubkey = "<server public key>"
```

The relay listens on `0.0.0.0:51820` by default. The [reference](docs/reference.md#configuration) describes every setting.

**2. Run it**, from source or as a container (see [Docker](#docker)):

```sh
cargo build --release
./target/release/wg-relay --check-config -c relay.toml   # validate and print a summary
RUST_LOG=info ./target/release/wg-relay -c relay.toml
```

**3. Paste the relay's `[Peer]` block into the server's config.** The relay logs it at startup, and `wg-relay --print-peer -c relay.toml` prints only the block.

**4. Verify.** `ping 10.99.0.254` on the server confirms its registration. `ping 10.99.0.1` on the client confirms the tunnel.

## Access control and multiple networks

A session is established only when a server listed in `relay.toml` answers the handshake. Anyone may send a handshake to such a server, and the server's own WireGuard peer list decides whether to answer. A stranger's handshake is therefore dropped by the server.

| To | Edit |
|---|---|
| add or remove a client | the server's WireGuard config |
| add or remove a network | `relay.toml`, then `SIGHUP` |
| cut a server off immediately | remove it from `relay.toml`, then `SIGHUP` |

Several networks run by different people can share one relay. Each owner gives the relay operator their server's public key, and manages their own clients without involving the operator. Networks may use overlapping subnets, because the relay never sees addresses inside the tunnels. The only shared address is the relay's `tunnel_ip` (`10.99.0.254` by default), which no network should assign to a peer.

Peers listed in `relay.toml` can reach one another in both directions. A peer that is not listed can start a handshake but cannot receive one, so a client that a server must contact first should be listed too.

The relay can see which keys communicate, when and how much, and each host's public address. It can drop or delay packets. It cannot decrypt, inject or modify traffic, and cannot add a peer. Its own private key opens only the registration tunnels, which carry nothing but keepalives and pings to `tunnel_ip`.

## Limitations

- **All traffic passes through the relay.** There is no direct path between peers, so the relay's latency and bandwidth apply.
- **A network change interrupts traffic for about 5–15 s.** When a client moves, for example from Wi-Fi to mobile data, traffic stops until WireGuard performs a new handshake.
- **A single relay is a single point of failure.** There is no failover.
- **A server cannot start a handshake with a client that is not listed in `relay.toml`.** Clients normally start handshakes themselves, so this rarely matters.
- **The relay cannot cap bandwidth use.** A server can accept any number of clients, and only handshakes are rate-limited.
- **A sustained handshake flood delays new sessions.** Existing sessions keep forwarding.
- **One flow is forwarded by one core.** The kernel keeps each address pair on one forwarding thread.

The [reference](docs/reference.md#limitations) gives the complete list with the reasoning behind each item, and the [guide's security model](docs/how-it-works.md#14-security-model) covers threats and defences.

## Operation

```sh
kill -HUP $(pidof wg-relay)                                     # reload relay.toml
RUST_LOG=wg_relay=debug ./target/release/wg-relay -c relay.toml # log every rejected packet
WG_RELAY_CONFIG=/etc/wg-relay.toml ./target/release/wg-relay    # every flag also reads an env var (see --help)
```

A reload applies peer changes immediately. A few settings need a restart; see [Reload](docs/reference.md#reload-sighup). Every rejected packet is counted under a named reason, such as `wrong_source` or `rate_limited`, and the counters are logged every minute and at shutdown. The reference lists [every reason](docs/reference.md#drop-reasons).

## Docker

Release images are published as `ghcr.io/3alpha/wg-relay` for `linux/amd64` and `linux/arm64`. `docker build -t wg-relay .` builds the same image locally. The container runs as uid 65532, which must be able to read the mounted `relay.toml`.

```sh
docker run -d --name wg-relay --restart unless-stopped \
  -p 51820:51820/udp \
  -v /etc/wg-relay/relay.toml:/etc/wg-relay/relay.toml:ro \
  ghcr.io/3alpha/wg-relay
```

The relay rate-limits handshakes per source address, so it must see each peer's real address. Whether it does depends on the network mode:

| Network | Real source addresses | Notes |
|---|---|---|
| `--network host` | yes | No NAT or connection tracking in front of the relay. Best for a relay that faces the internet under load. |
| Bridge with `-p` (the default), rootful Docker on Linux | IPv4: yes. IPv6: only if the container network has IPv6 enabled and Docker manages ip6tables. | The host kernel tracks every flow, which costs throughput. A flood from many sources can fill its connection tracking table before the relay's own limits apply. |
| Bridge with `-p` on rootless Docker, Docker Desktop, or with `iptables` disabled | no | A userspace proxy makes every peer appear as one address. Forwarding works, but all peers share one rate-limit bucket, so one abuser can starve the rest. |
| `macvlan` or `ipvlan` | yes | The container gets its own address on the network, without NAT. |

To check, watch the metric `wg_relay_rate_limit_buckets_used` with several peers connected. It grows with the number of distinct source addresses, and stays at 1 if they are being rewritten.

[`docker-compose.yml`](docker-compose.yml) runs the relay with Docker Compose (`docker compose up -d`) and publishes the metrics port to the host's loopback. Its comments explain how to switch to the host network.

## Metrics

The relay can serve Prometheus metrics over plain HTTP at `/metrics`. It is off by default. Set `metrics_listen` (for example `"127.0.0.1:9586"`), or pass `--metrics-listen` or `WG_RELAY_METRICS_LISTEN`. The endpoint has no authentication, so keep it on loopback or a private network, or firewall it.

In Docker, listen on all of the container's interfaces and publish the port only to the host's loopback:

```sh
docker run -d --name wg-relay -p 51820:51820/udp -p 127.0.0.1:9586:9586 \
  -e WG_RELAY_METRICS_LISTEN=0.0.0.0:9586 \
  -v /etc/wg-relay/relay.toml:/etc/wg-relay/relay.toml:ro ghcr.io/3alpha/wg-relay
```

The reference lists [every metric](docs/reference.md#prometheus-metrics) and [what to alert on](docs/reference.md#what-to-alert-on). [`grafana/wg-relay.json`](grafana/wg-relay.json) is a dashboard for Grafana 10 or later; pick the Prometheus data source, job and instance in its variables. [`grafana/alerts.yml`](grafana/alerts.yml) holds Prometheus alerting rules; add it to `rule_files` and tune the thresholds marked `tune` to your traffic.

## Testing

```sh
cargo test                                             # unit and in-process tests
cargo build --bins --examples && sudo tests/netns.sh   # end-to-end, with kernel WireGuard
cargo build --release --bins --examples && target/release/examples/bench_forward  # throughput on loopback
```

The end-to-end test builds NATed hosts in Linux network namespaces and checks that clients connect, a stranger does not, rekeys work, `SIGHUP` revokes a removed server, and forwarded packets are byte-identical and unreadable to the relay. The reference explains [the end-to-end test](docs/reference.md#the-namespace-integration-test), including how to run it in Docker without root, and [the benchmark](docs/reference.md#the-throughput-benchmark).

## Documentation

- [How wg-relay works](docs/how-it-works.md): the design, with diagrams.
- [Reference](docs/reference.md): configuration, forwarding rules, drop reasons, metrics, reload, limitations, tests and code layout.
- [`relay.example.toml`](relay.example.toml): a config template.

## License

[MIT](LICENSE).
