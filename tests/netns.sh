#!/usr/bin/env bash
# Integration test for wg-relay. Run as root (or in a --privileged container).
#
#   srv (10.10.0.2) -- natsrv 192.0.2.10 --+
#   c1  (10.11.0.2) -- natc1  192.0.2.11 --+-- br0 192.0.2.1 = relay :51820
#   c2  (10.12.0.2) -- natc2  192.0.2.12 --+
#   st  (10.13.0.2) -- natst  192.0.2.13 --+
#
# Every host runs kernel WireGuard behind its own NAT (MASQUERADE, unsolicited
# inbound dropped). Tunnel IPs: srv 10.99.0.1, c1 .11, c2 .12, st .13, relay .254.
# The relay runs three forwarding threads, each with its own socket.
# relay.toml lists srv and c2, which register with the relay; c1 and st are
# unlisted. The server has c1 and c2 as peers; st (stranger) is not one of them,
# although it knows the server's public key. The test asserts:
#   1. srv and c2 register with the relay
#   2. c1 (unlisted) and c2 (listed) ping the server
#   3. the stranger gets nothing through; a capture on the server's LAN shows
#      its handshakes reach the server, which drops them
#   4. pings still work after rekeys: server-initiated towards c2 (listed),
#      client-initiated for c1 and c2
#   5. SIGHUP after removing srv cuts its sessions off immediately
#   6. the relay capture: forwarded handshakes cannot be opened with the relay
#      key, forwarding is byte-identical, the ping payload never appears
#
# Needs: ip, wg, iptables, tcpdump, ping, the wireguard module, and
# `cargo build --bins --examples` (or WG_RELAY_BIN / PCAP_CHECK_BIN).
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "netns.sh must run as root" >&2; exit 1; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${WG_RELAY_BIN:-$ROOT/target/debug/wg-relay}
CHECK=${PCAP_CHECK_BIN:-$ROOT/target/debug/examples/pcap_check}
for t in ip wg iptables tcpdump ping "$BIN" "$CHECK"; do
    command -v "$t" >/dev/null || { echo "missing: $t" >&2; exit 1; }
done

P="wrt$$"
HOSTS=(srv c1 c2 st)
NSS=(relay "${HOSTS[@]}" natsrv natc1 natc2 natst)
declare -A NET=([srv]=10 [c1]=11 [c2]=12 [st]=13)
declare -A TIP=([srv]=10.99.0.1 [c1]=10.99.0.11 [c2]=10.99.0.12 [st]=10.99.0.13)
RELAY=192.0.2.1:51820
MARKER=c0ffee5ca1ab1e42 # ping payload pattern; must never appear on the wire
WORK=$(mktemp -d)
PIDS=()
LOG=/dev/null
x() { local ns=$1; shift; ip netns exec "$P-$ns" "$@"; }
step() { echo "==> $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

stop_bg() {
    for p in "${PIDS[@]}"; do kill -TERM "$p" 2>/dev/null || true; done
    for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
    PIDS=()
}

cleanup() {
    local rc=$?
    stop_bg
    if [[ $rc -ne 0 ]]; then
        echo "---- relay log ($LOG) ----"; tail -n 60 "$LOG" 2>/dev/null || true
        for n in "${HOSTS[@]}"; do echo "---- wg show ($n) ----"; x "$n" wg show 2>/dev/null || true; done
        echo "FAILED (rc=$rc); artifacts kept in $WORK"
    else
        rm -rf "$WORK"
    fi
    for n in "${NSS[@]}"; do ip netns del "$P-$n" 2>/dev/null || true; done
}
trap cleanup EXIT

step "building topology"
for n in "${NSS[@]}"; do ip netns add "$P-$n"; x "$n" ip link set lo up; done
x relay ip link add br0 type bridge
x relay ip addr add 192.0.2.1/24 dev br0
x relay ip link set br0 up
for h in "${HOSTS[@]}"; do
    nat="nat$h" i=${NET[$h]}
    ip link add wan netns "$P-$nat" type veth peer name "up$h" netns "$P-relay"
    x relay ip link set "up$h" master br0 up
    x "$nat" ip addr add "192.0.2.$i/24" dev wan
    x "$nat" ip link set wan up
    ip link add lan netns "$P-$nat" type veth peer name eth0 netns "$P-$h"
    x "$nat" ip addr add "10.$i.0.1/24" dev lan
    x "$nat" ip link set lan up
    x "$h" ip addr add "10.$i.0.2/24" dev eth0
    x "$h" ip link set eth0 up
    x "$h" ip route add default via "10.$i.0.1"
    x "$nat" sh -c "echo 1 >/proc/sys/net/ipv4/ip_forward"
    x "$nat" iptables -t nat -A POSTROUTING -o wan -j MASQUERADE
    x "$nat" iptables -A FORWARD -i wan -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    x "$nat" iptables -A FORWARD -i wan -j DROP
done

umask 077
for k in relay "${HOSTS[@]}"; do
    wg genkey >"$WORK/$k.key"
    wg pubkey <"$WORK/$k.key" >"$WORK/$k.pub"
done
pub() { cat "$WORK/$1.pub"; }

write_config() { # listed peers...
    {
        echo "private_key = \"$(cat "$WORK/relay.key")\""
        echo "handshake_rate_per_ip = \"10/s\""
        echo "workers = 3"
        for p in "$@"; do printf '[[peer]]\nname = "%s"\npubkey = "%s"\n' "$p" "$(pub "$p")"; done
    } >"$WORK/relay.toml"
}

peer_args() { # peer -> wg set arguments for that peer (endpoint is always the relay)
    case $1 in
        relay) echo "peer $(pub relay) endpoint $RELAY allowed-ips 10.99.0.254/32 persistent-keepalive 25" ;;
        *) echo "peer $(pub "$1") endpoint $RELAY allowed-ips ${TIP[$1]}/32 persistent-keepalive 25" ;;
    esac
}

setup_wg() {
    for h in "${HOSTS[@]}"; do
        local peers
        case $h in
            srv) peers="relay c1 c2" ;; # the server does not know the stranger
            c2) peers="relay srv" ;;    # listed, so it registers too
            *) peers="srv" ;;
        esac
        x "$h" ip link del wg0 2>/dev/null || true
        x "$h" ip link add wg0 type wireguard
        local args=""
        for p in $peers; do args+=" $(peer_args "$p")"; done
        # shellcheck disable=SC2086
        x "$h" wg set wg0 private-key "$WORK/$h.key" listen-port 51820 $args
        x "$h" ip addr add "${TIP[$h]}/24" dev wg0
        x "$h" ip link set wg0 up
    done
}

retry_ping() { # ns target tries
    for _ in $(seq "$3"); do x "$1" ping -c1 -W1 "$2" >/dev/null 2>&1 && return 0; done
    return 1
}
must_ping() { retry_ping "$1" "$2" "${3:-20}" || fail "$1 cannot reach $2"; x "$1" ping -q -c3 -i0.2 -W2 -p "$MARKER" "$2" >/dev/null || fail "$1 -> $2 lossy"; }
no_ping() { if x "$1" ping -c4 -i0.5 -W1 "$2" >/dev/null 2>&1; then fail "$1 unexpectedly reached $2"; fi; }

D="$WORK/run"
mkdir -p "$D"
LOG="$D/relay.log"
step "starting relay and captures"
write_config srv c2
"$BIN" --check-config -c "$WORK/relay.toml" >"$D/check.txt"
ip netns exec "$P-relay" tcpdump -i br0 -U -n -w "$D/relay.pcap" udp port 51820 2>"$D/tcpdump-relay.log" &
PIDS+=($!)
ip netns exec "$P-srv" tcpdump -i eth0 -U -n -w "$D/srv.pcap" udp 2>"$D/tcpdump-srv.log" &
PIDS+=($!)
for f in "$D"/tcpdump-*.log; do
    for _ in $(seq 50); do grep -q listening "$f" && break; sleep 0.1; done
done
RUST_LOG=${RUST_LOG:-wg_relay=debug,info} ip netns exec "$P-relay" "$BIN" -c "$WORK/relay.toml" >"$LOG" 2>&1 &
PIDS+=($!)
RELAY_PID=$!
sleep 0.3
setup_wg

grep -q 'wg-relay started.*workers=3' "$LOG" || fail "relay did not start three forwarding threads"

step "1. srv and c2 register"
retry_ping srv 10.99.0.254 15 || fail "srv not registered"
retry_ping c2 10.99.0.254 15 || fail "c2 not registered"

step "2. c1 (unlisted) and c2 (listed) ping the server"
must_ping c1 10.99.0.1
must_ping c2 10.99.0.1

step "3. the stranger gets nothing through"
no_ping st 10.99.0.1

step "4a. server-initiated rekey towards c2 (listed)"
x srv wg set wg0 peer "$(pub c2)" remove
# shellcheck disable=SC2046
x srv wg set wg0 $(peer_args c2)
retry_ping srv 10.99.0.12 20 || fail "server-initiated rekey to c2 failed"
must_ping c2 10.99.0.1

step "4b. client-initiated rekeys (c1, c2)"
for c in c1 c2; do
    x "$c" wg set wg0 peer "$(pub srv)" remove
    # shellcheck disable=SC2046
    x "$c" wg set wg0 $(peer_args srv)
    must_ping "$c" 10.99.0.1
done

step "5. SIGHUP after removing srv revokes it immediately"
write_config c2
kill -HUP "$RELAY_PID"
for _ in $(seq 20); do grep -q 'dropped_sessions=[1-9]' "$LOG" && break; sleep 0.1; done
grep -q 'peer removed from config.*peer=srv' "$LOG" || fail "reload did not remove srv"
no_ping c1 10.99.0.1
retry_ping c2 10.99.0.254 5 || fail "c2 lost its registration"

stop_bg
step "6. checking captures"
"$CHECK" "$D/relay.pcap" "$RELAY" "$(cat "$WORK/relay.key")" "$(cat "$WORK/srv.key")" "$MARKER" | sed 's/^/    /'
"$CHECK" --initiators "$D/srv.pcap" "$(cat "$WORK/srv.key")" >"$D/initiators.txt"
# Control: c2's rekey in step 4b is client-initiated, so it must show up.
grep -qxF "$(pub c2)" "$D/initiators.txt" || fail "capture at server shows no c2 handshake"
grep -qxF "$(pub st)" "$D/initiators.txt" || fail "stranger's handshakes should reach the server"
echo "    server LAN capture: stranger handshakes reached the server, which dropped them"
grep -E 'shutting down' "$LOG" | sed 's/^.*metrics=/    metrics: /'
echo "ALL NETNS CHECKS PASSED"
