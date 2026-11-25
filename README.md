# wg-relay

wg-relay is a UDP relay for WireGuard. It lets standard, unmodified WireGuard clients reach WireGuard servers that sit behind NAT, without a public address or port forward on either side. The relay forwards encrypted packets unchanged and never holds a key that could decrypt them.

A single relay serves any number of independent WireGuard networks. Each network is a server and its clients, and the relay only needs their public keys.

```
   network A                                             network A
   server ──NAT──┐                         ┌──NAT── laptop, phone
                 ├──►      wg-relay   ◄────┤
   network B     │    (public UDP port)    │         network B
   server ──NAT──┘                         ├──NAT── laptop
                                           └───✗─── unlisted host (dropped)
```

## Features

- **Stock WireGuard on every endpoint.** Kernel `wg`, wireguard-go and the mobile apps work unmodified. No agent, custom client or coordination service is involved.
- **No inbound connectivity required.** Every host only sends to the relay, so servers and clients can sit behind any NAT, including carrier-grade NAT.
- **End-to-end encryption is preserved.** The relay holds no session keys and forwards datagrams byte for byte. A compromised relay can drop traffic, but cannot read or modify it, and cannot add peers.
- **Many networks on one relay.** Each server and client is identified by its public key. Networks are isolated from one another, and adding one is a few lines of configuration.
- **Access control.** Only listed servers can register. In the default mode, a session opens only for a listed client that is permitted to reach that server. Handshakes are rate-limited per source IP, and the relay cannot be used as a reflector.
- **Simple to operate.** One binary, one UDP port and one TOML file. Configuration reloads on `SIGHUP`, and a removed key is cut off immediately. The implementation is about 1,700 lines of Rust.

## How it works

WireGuard leaves a few header fields readable by design. wg-relay routes using only those fields.

1. **Server registration.** Each server adds the relay as an ordinary WireGuard peer. This tunnel proves to the relay, cryptographically, at which address the server can currently be reached, and keeps the server's NAT mapping open.
2. **Destination by mac1.** Every handshake carries a MAC keyed with the recipient's public key. The relay tests it against the keys it knows and identifies the destination without decrypting anything.
3. **Sessions by index.** Each side announces a random session index in its handshake, in cleartext. The relay records which index belongs to which address, and routes the rest of the session by index.

[How wg-relay works](docs/how-it-works.md) describes the design in detail, with diagrams: the WireGuard protocol, every packet path, the state the relay keeps, roaming and the security model.

## Multiple networks

The relay holds a list of servers and clients, identified by public key. Each client lists the servers it may reach. Several independent networks, run by different people, can therefore share one relay: each network's owner provides the public keys of their server and clients, and the relay operator adds them to `relay.toml`.

```toml
[[server]]
name = "alice-home"
pubkey = "<alice's server public key>"

[[server]]
name = "bob-office"
pubkey = "<bob's server public key>"

[[client]]
name = "alice-laptop"
pubkey = "<alice's laptop public key>"
servers = ["alice-home"]

[[client]]
name = "bob-phone"
pubkey = "<bob's phone public key>"
servers = ["bob-office"]
```

- **Isolation.** In the default `response` mode, a client can only open a session with a server that both accepts it in its own WireGuard peer list and appears in the client's `servers` list. In the example, Alice's laptop cannot open a session with Bob's server. In `none` mode, each server's peer list alone keeps other networks out.
- **Private keys stay private.** The relay operator never sees any network's private keys, and cannot read or join any network's traffic.
- **Independent addressing.** The relay never sees the addresses inside the tunnels, so networks may use overlapping subnets. The only shared address is the relay's own `tunnel_ip` (`10.99.0.254` by default), which no network should assign to a peer.
- **Scale.** The relay tests each handshake against the listed keys in turn, which is fast enough for thousands of keys.

Changes take effect on `SIGHUP`, without a restart and without disturbing other networks.

## Quick start

**1. Build the relay.**

```sh
cargo build --release
```

**2. Write `relay.toml`.** Generate the relay's key with `wg genkey`, then list the servers and clients by public key:

```toml
listen = "0.0.0.0:51820"
private_key = "<relay private key>"
tunnel_ip = "10.99.0.254"         # the relay's address inside each server's tunnel
client_gate = "response"          # "none" | "response" (see Access control)
handshake_rate_per_ip = "10/s"

[[server]]
name = "main"
pubkey = "<server public key>"

[[client]]
name = "laptop"
pubkey = "<laptop public key>"
servers = ["main"]                # the servers this client may reach
```

**3. Configure the server.** Add the relay as a peer, and set the relay as the endpoint of every client peer:

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

**4. Configure the client.** The client uses an ordinary configuration in which the server's endpoint is the relay:

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
RUST_LOG=info ./target/release/wg-relay -c relay.toml
ping 10.99.0.254                                         # on the server: confirms registration
ping 10.99.0.1                                           # on the client: confirms the tunnel
```

Keep `PersistentKeepalive` on every peer. It keeps NAT mappings and server registrations current.

## Access control

The server's own WireGuard peer list always decides which clients can authenticate. The `client_gate` setting determines whether the relay enforces a second check of its own.

| `client_gate` | Listed in `relay.toml` | A session opens when |
|---|---|---|
| `response` (default) | servers and clients | the server accepts the client, **and** the client is listed for that server |
| `none` | servers only | the server accepts the client |

With `response`, a client can be revoked at the relay with `SIGHUP`, without changing the server. In both modes, a handshake from an unlisted host reaches the server, which drops it because the host is not one of its peers.

## Trust model

| The relay can | The relay cannot |
|---|---|
| see which keys communicate, when, and how much | decrypt any traffic |
| see each host's public IP address and port | inject or modify packets: WireGuard rejects them |
| drop or delay packets | add a peer: each server's peer list decides |

The relay's own private key opens only the registration tunnels, which carry keepalives and pings to `10.99.0.254` and nothing else.

## Limitations

- **All traffic passes through the relay.** There is no direct peer-to-peer path, so the relay's latency and bandwidth apply.
- **Network changes interrupt traffic briefly.** When a client changes network, for example from Wi-Fi to mobile data, traffic stops for about 5–15 s until WireGuard performs a new handshake.
- **A single relay is a single point of failure.** There is no failover.
- **In `none` mode, a server cannot initiate a handshake to an unlisted client.** Clients normally initiate handshakes themselves, so this rarely matters.
- **WireGuard's handshake flood protection is weaker behind the relay.** The relay's per-IP rate limit compensates in part; see [section 3.5 of the guide](docs/how-it-works.md#35-under-load-cookies-and-mac2).
- **The relay is single-threaded.** Ping replies are IPv4-only, and metrics are written to the log rather than exported.

The [reference](docs/reference.md#limitations) gives the complete list with the reasoning behind each item, and the [guide's security model](docs/how-it-works.md#15-security-model) covers threats and defences.

## Operation

```sh
kill -HUP $(pidof wg-relay)                                     # reload relay.toml
RUST_LOG=wg_relay=debug ./target/release/wg-relay -c relay.toml # log every rejected packet
WG_RELAY_CONFIG=/etc/wg-relay.toml ./target/release/wg-relay    # every flag also reads an env var (see --help)
```

Every rejected packet is counted under a named reason, such as `wrong_source` or `rate_limited`. The counters are logged every minute and at shutdown. The [reference](docs/reference.md) lists every reason, along with the exact forwarding and reload rules.

## Testing

```sh
cargo test                                             # unit and in-process tests
cargo build --bins --examples && sudo tests/netns.sh   # end-to-end, with kernel WireGuard
```

The end-to-end test builds a network in Linux network namespaces: a server, two clients and an unlisted host, each behind its own NAT and running kernel WireGuard. It verifies that listed clients connect and the unlisted host does not, that rekeys work in both directions, and that `SIGHUP` revokes a client immediately. A packet capture at the relay verifies that the relay's key cannot open forwarded handshakes and that every forwarded packet is byte-identical. The [reference](docs/reference.md#the-namespace-integration-test) explains how to run the test in Docker without root on the host.

## Documentation

- [How wg-relay works](docs/how-it-works.md): the design, with diagrams.
- [Reference](docs/reference.md): forwarding rules, reject reasons, reload behaviour, limitations, the test suite and the code layout.
- [`relay.example.toml`](relay.example.toml): a commented example configuration.
