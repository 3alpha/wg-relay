# wg-relay

**Reach your WireGuard server from anywhere, even when it sits behind NAT. Keep stock WireGuard on every device, and use a relay that cannot read a single byte of your traffic.**

Your server is at home or in the office, behind a router you can't forward ports on, maybe behind carrier-grade NAT. Your laptop and phone are on café Wi-Fi and mobile data. Nobody can reach anybody.

wg-relay is a tiny UDP relay you run on any cheap public host. Everyone points their WireGuard `Endpoint` at it, and it quietly passes packets between them. Your WireGuard connection stays end-to-end: the relay never holds a key that could open it.

```
   home server ──NAT──┐                     ┌──NAT── laptop
                      └──►  wg-relay  ◄─────┼──NAT── phone
                                            └───✗─── stranger (dropped)
```

## Why you'll like it

- **Stock WireGuard everywhere.** Kernel `wg`, wireguard-go and the mobile apps work as they are. No agent, no custom client, no coordination service.
- **No public IP, no port forward.** Every host only makes outbound connections, so it works behind any NAT, including CGNAT.
- **A relay you don't have to trust.** It forwards encrypted packets byte for byte and holds no session keys. Even if someone takes over the relay, they can drop your traffic, but they can't read it, change it or add themselves as a peer.
- **Not an open door.** Only servers you list can register. With the default gate, only clients you list can open sessions. Handshakes are rate-limited per IP, and the relay can't be used to bounce traffic at other hosts.
- **Small and boring to run.** One binary, one UDP port, one TOML file. Reload it with `SIGHUP`, and a revoked key is cut off on the spot. About 1,700 lines of Rust.

## How it works, in 30 seconds

WireGuard keeps a couple of header fields readable on purpose, and wg-relay routes on just those.

1. **Your server registers.** It adds the relay as an ordinary WireGuard peer. That tunnel proves to the relay, cryptographically, where the server is right now, and keeps the server's NAT open.
2. **mac1 says who a handshake is for.** Every WireGuard handshake carries a checksum keyed with the recipient's public key. The relay tries the keys it knows and finds the destination without decrypting anything.
3. **Session indexes carry everything else.** Each side announces a random session number in its handshake, in the clear. The relay notes which number belongs to which address, then routes the rest of the session with a single lookup.

Want the whole story? **[How wg-relay works](docs/how-it-works.md)** is a guided tour with diagrams: the WireGuard protocol itself, every packet path, the relay's state, roaming and the security model.

## Quick start

**1. Build the relay.**

```sh
cargo build --release
```

**2. Write `relay.toml`.** Generate the relay's key with `wg genkey`, and list your server and clients by public key:

```toml
listen = "0.0.0.0:51820"
private_key = "<relay private key>"
tunnel_ip = "10.99.0.254"         # the relay's address inside the server's tunnel
client_gate = "response"          # "none" | "response" (see below)
handshake_rate_per_ip = "10/s"

[[server]]
name = "main"
pubkey = "<server public key>"

[[client]]
name = "laptop"
pubkey = "<laptop public key>"
servers = ["main"]                # which servers this client may reach
```

**3. Configure the server.** Add the relay as a peer, and point every client peer at the relay too:

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

**4. Configure the client.** It's a completely normal config. The relay is simply the server's address:

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

**5. Run it and check.**

```sh
./target/release/wg-relay --check-config -c relay.toml   # validate; prints roles and warnings
RUST_LOG=info ./target/release/wg-relay -c relay.toml
ping 10.99.0.254                                         # from the server: is it registered?
ping 10.99.0.1                                           # from the laptop: you're in
```

Keep `PersistentKeepalive` on every peer: it keeps NAT mappings and the server's registration fresh.

## Choose who gets in

The server's own WireGuard peer list always decides who can actually connect. `client_gate` decides whether the relay adds a second lock of its own.

| `client_gate` | What you list in `relay.toml` | A session opens when |
|---|---|---|
| `response` (default) | servers and clients | the server accepts a client **and** that client is on the relay's list for that server |
| `none` | servers only | the server accepts the client; nothing to keep in sync on the relay |

With `response` you can revoke a client from the relay with a `SIGHUP`, without touching the server. In both modes a stranger's handshake reaches the server, which drops it because the stranger isn't one of its peers.

## What the relay can and can't see

| The relay can | The relay can't |
|---|---|
| see which keys talk to each other, when, and how much | decrypt any traffic |
| see every host's public IP and port | inject or modify packets: WireGuard rejects them |
| drop or delay packets | add a peer: the server's peer list decides |

The relay's own private key only opens the registration tunnels, which carry nothing but keepalives and pings to `10.99.0.254`.

## Good to know

- **All traffic goes through the relay.** There is no direct peer-to-peer path, so you pay its latency and bandwidth.
- **Switching networks costs a few seconds.** When a client moves from Wi-Fi to mobile data, traffic pauses for about 5–15 s until WireGuard re-handshakes on its own.
- **One relay, no failover** yet.
- **In `none` mode, the server can't start a handshake to a client the relay doesn't know.** Clients normally start handshakes themselves, so this rarely matters.
- **WireGuard's flood protection is weaker behind the relay.** The relay's per-IP rate limit takes up part of the job. Details are in [the guide, section 3.5](docs/how-it-works.md#35-under-load-cookies-and-mac2).
- **Single-threaded**, which is fine for thousands of keys. Ping replies are IPv4-only, and metrics go to the log rather than to Prometheus.

The [full list of limitations](docs/reference.md#limitations) explains the reasoning behind each one, and the [guide's security model](docs/how-it-works.md#15-security-model) covers threats and defences.

## Running it

```sh
kill -HUP $(pidof wg-relay)                                     # reload relay.toml
RUST_LOG=wg_relay=debug ./target/release/wg-relay -c relay.toml # log every rejected packet
WG_RELAY_CONFIG=/etc/wg-relay.toml ./target/release/wg-relay    # every flag also reads an env var (see --help)
```

Every dropped packet is counted under a named reason, such as `wrong_source` or `rate_limited`. The counters are logged every minute and at shutdown. The [reference](docs/reference.md) lists every reason and the exact forwarding and reload rules.

## Tested for real

```sh
cargo test                                             # unit and in-process tests
cargo build --bins --examples && sudo tests/netns.sh   # end-to-end, real kernel WireGuard
```

The end-to-end test builds a small internet in network namespaces: a server, two clients and a stranger, each behind its own NAT, all running kernel WireGuard. It checks that clients get through and the stranger doesn't, that rekeys work in both directions, and that a `SIGHUP` revokes a client instantly. A packet capture at the relay checks that the relay's key can't open forwarded handshakes and that every forwarded packet leaves byte-identical. No root on your machine? The [reference](docs/reference.md#the-namespace-integration-test) shows how to run it in Docker.

## Learn more

- [How wg-relay works](docs/how-it-works.md): the guided tour, with diagrams.
- [Reference](docs/reference.md): forwarding rules, reject reasons, reload behaviour, the test suite and the code layout.
- [`relay.example.toml`](relay.example.toml): a commented example config.
