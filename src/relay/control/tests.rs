use super::*;
use crate::packet;
use crate::relay::Relay;
use crate::relay::forwarder::Lookup;
use crate::tables::SessionState;
use base64::Engine;
use rand_core::OsRng;

fn b64(b: [u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// A config with this private key, listing these peers.
fn config(secret: &StaticSecret, peers: &[PeerKey]) -> Config {
    let mut cfg = format!("private_key = \"{}\"\n", b64(secret.to_bytes()));
    for (i, pk) in peers.iter().enumerate() {
        cfg += &format!("[[peer]]\nname = \"p{i}\"\npubkey = \"{pk}\"\n");
    }
    Config::parse(&cfg).unwrap()
}

/// A relay listing three random peers, none of them registered.
fn relay() -> Relay {
    let peers: Vec<PeerKey> =
        (0..3).map(|_| PublicKey::from(&StaticSecret::random_from_rng(OsRng)).into()).collect();
    Relay::new(&config(&StaticSecret::random_from_rng(OsRng), &peers))
}

/// Reload `relay` listing only these of its original peers.
fn reload_listing(relay: &mut Relay, peers: &[PeerKey]) {
    let cfg = config(&relay.control.secret, peers);
    relay.reload(&cfg);
}

fn src(i: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, i], 1))
}

/// A handshake initiation matching no listed key, so it costs a scan of all three.
fn junk() -> Vec<u8> {
    let mut p = vec![0u8; packet::INIT_LEN];
    p[0] = 1;
    p
}

/// A handshake initiation whose mac1 is for the relay but whose body is garbage.
fn junk_for_relay(relay: &Relay) -> Vec<u8> {
    let mut p = junk();
    let mac = relay.control.relay_mac1.mac(&p[..116]);
    p[116..132].copy_from_slice(&mac);
    p
}

#[test]
fn forwarding_budget_sheds_forwarded_initiations_once_spent() {
    let mut relay = relay();
    relay.control.forwarding_budget = WorkBudget::new(10.0);
    let t0 = Instant::now();
    let junk = junk();
    let verdicts: Vec<Verdict> = (0..5).map(|i| relay.handle(src(i), &junk, t0)).collect();
    let (miss, shed) =
        (Verdict::Drop(Reason::NoMac1Match), Verdict::Drop(Reason::ForwardingBudget));
    assert_eq!(verdicts, [miss, miss, miss, miss, shed], "10 -> 7 -> 4 -> 1 -> -2");
    assert_eq!(relay.handle(src(9), &junk, t0 + Duration::from_millis(300)), miss, "refilled");
    assert_eq!(relay.metrics().rejected(Reason::ForwardingBudget), 1);
}

/// A relay whose forwarding budget allows one scan and whose registration
/// budget allows one attempt, plus a registration initiation for it.
fn tiny_budgets() -> (Relay, Vec<u8>) {
    let mut relay = relay();
    relay.control.forwarding_budget = WorkBudget::new(3.0);
    relay.control.registration_budget = WorkBudget::new(REGISTRATION_WORK as f64);
    let reg = junk_for_relay(&relay);
    (relay, reg)
}

const MISS: Verdict = Verdict::Drop(Reason::NoMac1Match);
const FWD_SHED: Verdict = Verdict::Drop(Reason::ForwardingBudget);
const REG_ATTEMPT: Verdict = Verdict::Drop(Reason::TunnelAuthFailed);
const REG_SHED: Verdict = Verdict::Drop(Reason::RegistrationBudget);

#[test]
fn spent_forwarding_budget_leaves_registration_admitted() {
    let (t0, fwd) = (Instant::now(), junk());
    let (mut relay, reg) = tiny_budgets();
    assert_eq!([relay.handle(src(1), &fwd, t0), relay.handle(src(2), &fwd, t0)], [MISS, FWD_SHED]);
    assert_eq!(relay.handle(src(3), &reg, t0), REG_ATTEMPT);
    assert_eq!(relay.handle(src(4), &reg, t0), REG_SHED);
    assert_eq!(relay.handle(src(5), &fwd, t0), FWD_SHED);
}

#[test]
fn spent_registration_budget_leaves_forwarding_scanning() {
    let (t0, fwd) = (Instant::now(), junk());
    let (mut relay, reg) = tiny_budgets();
    assert_eq!(
        [relay.handle(src(1), &reg, t0), relay.handle(src(2), &reg, t0)],
        [REG_ATTEMPT, REG_SHED]
    );
    assert_eq!(relay.handle(src(3), &fwd, t0), MISS);
    assert_eq!(relay.handle(src(4), &fwd, t0), FWD_SHED);
}

#[test]
fn registered_address_skips_the_spent_registration_budget() {
    let t0 = Instant::now();
    let (mut relay, reg) = tiny_budgets();
    let listed = relay.control.mac1.peers[0];
    relay.control.registry.update(listed, src(7), t0);
    assert_eq!(
        [relay.handle(src(1), &reg, t0), relay.handle(src(2), &reg, t0)],
        [REG_ATTEMPT, REG_SHED]
    );
    assert_eq!(relay.handle(src(7), &reg, t0), REG_ATTEMPT, "registered");
    // Once the registration expires, the address competes for the budget again.
    let later = t0 + REGISTRY_TTL;
    relay.control.registration_budget = WorkBudget::new(REGISTRATION_WORK as f64);
    assert_eq!(
        [relay.handle(src(2), &reg, later), relay.handle(src(7), &reg, later)],
        [REG_ATTEMPT, REG_SHED]
    );
}

#[test]
fn full_pending_table_refuses_initiations_before_the_scan() {
    let mut relay = relay();
    relay.control.forwarding_budget = WorkBudget::new(10.0);
    let (now, a, b) = (Instant::now(), src(1), src(2));
    // Spread over enough peers that no quota evicts anything.
    let control = &mut relay.control;
    for i in 0..MAX_PENDING as u32 {
        let mut key = [0; 32];
        key[..4].copy_from_slice(&(i / MAX_PENDING_PER_PEER as u32).to_le_bytes());
        let s = crate::tables::Session::pending(a, b, PeerKey::from(key), now);
        assert!(control.sessions.insert(i.into(), s, &mut control.forwarder.open).is_ok());
    }
    assert_eq!(relay.control.sessions.pending(), MAX_PENDING);
    let mut junk = junk();
    junk[4] = 0xee; // a sender index none of the entries uses
    junk[7] = 0xee;
    let verdicts: Vec<Verdict> = (0..5).map(|_| relay.handle(a, &junk, now)).collect();
    assert_eq!(verdicts, [Verdict::Drop(Reason::TooManyPending); 5], "and no budget spent");
    relay.tick(now + PENDING_TTL + SWEEP_INTERVAL);
    assert_eq!(relay.control.sessions.pending(), 0);
    let later = now + PENDING_TTL + SWEEP_INTERVAL;
    assert_eq!(relay.handle(a, &junk, later), Verdict::Drop(Reason::NoMac1Match));
    relay.control.assert_forwarder_in_step();
}

/// `relay()` with these table limits and listed peers 0 and 1 registered.
fn limited(limits: SessionLimits, t0: Instant) -> Relay {
    let mut relay = relay();
    relay.control.sessions = SessionTable::new(SESSION_TTL, PENDING_TTL, limits);
    relay.control.forwarder.open = relay.control.sessions.new_view();
    for (i, peer) in relay.control.mac1.peers.clone().into_iter().take(2).enumerate() {
        relay.control.registry.update(peer, listed(i), t0);
    }
    relay
}

/// Where listed peer `i` is registered.
fn listed(i: usize) -> SocketAddr {
    SocketAddr::from(([203, 0, 113, i as u8 + 1], 51820))
}

/// A forwarded initiation for listed peer `i`, announcing `sender`.
fn init_for(relay: &Relay, i: usize, sender: u32) -> Vec<u8> {
    init_keyed(&relay.control.mac1.keys[i], sender)
}

/// A handshake initiation for the holder of `key`, announcing `sender`.
fn init_keyed(key: &Mac1Key, sender: u32) -> Vec<u8> {
    let mut p = junk();
    p[4..8].copy_from_slice(&sender.to_le_bytes());
    let mac = key.mac(&p[..116]);
    p[116..132].copy_from_slice(&mac);
    p
}

/// A handshake-response-shaped datagram; the relay never checks its contents.
fn response(sender: u32, receiver: u32) -> Vec<u8> {
    let mut p = vec![0u8; 92];
    p[0] = 2;
    p[4..8].copy_from_slice(&sender.to_le_bytes());
    p[8..12].copy_from_slice(&receiver.to_le_bytes());
    p
}

/// A transport data message for `receiver`.
fn data(receiver: u32) -> Vec<u8> {
    let mut p = vec![0u8; 48];
    p[0] = 4;
    p[4..8].copy_from_slice(&receiver.to_le_bytes());
    p
}

/// A cookie reply for `receiver`.
fn cookie(receiver: u32) -> Vec<u8> {
    let mut p = vec![0u8; 64];
    p[0] = 3;
    p[4..8].copy_from_slice(&receiver.to_le_bytes());
    p
}

#[test]
fn peer_at_quota_is_refused_without_blocking_other_peers() {
    let t0 = Instant::now();
    let limits = SessionLimits { pending_per_peer: 4, per_peer: 6, total: 100 };
    let mut relay = limited(limits, t0);
    let fwd = Verdict::Forward;
    // Listed peer 0 answers two spoofed initiations aimed at itself: 4 open entries.
    for i in 0..2 {
        let init = init_for(&relay, 0, 0x100 + i);
        assert_eq!(relay.handle(src(i as u8), &init, t0), fwd(listed(0)));
        let resp = response(0x200 + i, 0x100 + i);
        assert_eq!(relay.handle(listed(0), &resp, t0), fwd(src(i as u8)));
    }
    // Two more pending entries bring it to its quota.
    for i in 2..4 {
        let init = init_for(&relay, 0, 0x100 + i);
        assert_eq!(relay.handle(src(i as u8), &init, t0), fwd(listed(0)));
    }
    let quota = Verdict::Drop(Reason::PeerQuota);
    assert_eq!(relay.handle(src(9), &init_for(&relay, 0, 0x109), t0), quota);
    // A response would add the responder's entry, so it is refused too and
    // the initiator's entry stays pending.
    assert_eq!(relay.handle(listed(0), &response(0x202, 0x102), t0), quota);
    assert_eq!(
        relay.control.sessions.get(0x102.into(), t0).map(|s| s.state),
        Some(SessionState::Pending)
    );
    // Another listed peer is unaffected.
    assert_eq!(relay.handle(src(10), &init_for(&relay, 1, 0x110), t0), fwd(listed(1)));
    assert_eq!(relay.handle(listed(1), &response(0x210, 0x110), t0), fwd(src(10)));
    // Once the sweep removes the expired pending entries, peer 0 has room again.
    let later = t0 + PENDING_TTL;
    relay.tick(later);
    assert_eq!(relay.handle(src(11), &init_for(&relay, 0, 0x111), later), fwd(listed(0)));
    assert_eq!(relay.metrics().rejected(Reason::PeerQuota), 2);
    assert_eq!(relay.control.sessions.len(), 4 + 2 + 1);
    relay.control.assert_forwarder_in_step();
}

#[test]
fn full_table_refuses_initiations_before_the_scan() {
    let t0 = Instant::now();
    let limits = SessionLimits { pending_per_peer: 4, per_peer: 100, total: 3 };
    let mut relay = limited(limits, t0);
    for i in 0..3u8 {
        let init = init_for(&relay, usize::from(i % 2), 0x100 + u32::from(i));
        assert_eq!(relay.handle(src(i), &init, t0), Verdict::Forward(listed(usize::from(i % 2))));
    }
    relay.control.forwarding_budget = WorkBudget::new(3.0);
    let full = Verdict::Drop(Reason::TooManySessions);
    let verdicts: Vec<Verdict> =
        (0..5).map(|i| relay.handle(src(10 + i), &init_for(&relay, 1, 0x200), t0)).collect();
    assert_eq!(verdicts, [full; 5]);
    assert!(relay.control.forwarding_budget.available(t0), "one scan would have spent it all");
    // A response needs a new entry too.
    assert_eq!(relay.handle(listed(0), &response(0x300, 0x100), t0), full);
    relay.tick(t0 + PENDING_TTL);
    let later = t0 + PENDING_TTL;
    assert_eq!(
        relay.handle(src(20), &init_for(&relay, 1, 0x200), later),
        Verdict::Forward(listed(1))
    );
    relay.control.assert_forwarder_in_step();
}

#[test]
fn forwarding_never_writes_to_the_session_entry() {
    let t0 = Instant::now();
    let limits = SessionLimits { pending_per_peer: 4, per_peer: 100, total: 100 };
    let mut relay = limited(limits, t0);
    assert_eq!(relay.handle(src(1), &init_for(&relay, 0, 0x10), t0), Verdict::Forward(listed(0)));
    let pending = relay.control.sessions.get(0x10.into(), t0);
    for s in 1..10 {
        let t = t0 + Duration::from_secs(s);
        assert_eq!(relay.handle(listed(0), &cookie(0x10), t), Verdict::Forward(src(1)));
        assert_eq!(relay.control.sessions.get(0x10.into(), t), pending, "cookie at {s} s");
    }
    assert_eq!(
        relay.handle(listed(0), &cookie(0x10), t0 + PENDING_TTL),
        Verdict::Drop(Reason::UnknownIndex)
    );

    assert_eq!(relay.handle(src(2), &init_for(&relay, 0, 0x20), t0), Verdict::Forward(listed(0)));
    assert_eq!(relay.handle(listed(0), &response(0x21, 0x20), t0), Verdict::Forward(src(2)));
    let entries = |relay: &Relay, t| {
        (relay.control.sessions.get(0x20.into(), t), relay.control.sessions.get(0x21.into(), t))
    };
    let open = entries(&relay, t0);
    for s in (10..200).step_by(10) {
        let t = t0 + Duration::from_secs(s);
        assert_eq!(relay.handle(listed(0), &data(0x20), t), Verdict::Forward(src(2)));
        assert_eq!(relay.handle(src(2), &data(0x21), t), Verdict::Forward(listed(0)));
        assert_eq!(entries(&relay, t), open, "data at {s} s");
    }
    let expired = Verdict::Drop(Reason::UnknownIndex);
    assert_eq!(relay.handle(listed(0), &data(0x20), t0 + SESSION_TTL), expired);
    relay.control.assert_forwarder_in_step();
}

#[test]
fn pending_evictions_are_counted_and_logged() {
    let t0 = Instant::now();
    let limits = SessionLimits { pending_per_peer: 2, per_peer: 100, total: 100 };
    let mut relay = limited(limits, t0);
    for i in 0..5u8 {
        let init = init_for(&relay, 0, 0x100 + u32::from(i));
        assert_eq!(relay.handle(src(i), &init, t0), Verdict::Forward(listed(0)));
    }
    assert_eq!(relay.metrics().pending_evicted, 3);
    assert!(relay.metrics().to_string().contains(" pending_evicted=3"), "{}", relay.metrics());
    relay.control.assert_forwarder_in_step();
}

#[test]
fn unreplyable_sources_are_dropped_before_parsing() {
    let t0 = Instant::now();
    let mut relay = relay();
    let bad = [
        "192.0.2.1:0",
        "0.0.0.0:1",
        "[::]:1",
        "224.0.0.1:1",
        "[ff02::1]:1",
        "255.255.255.255:1",
        "[::ffff:0.0.0.0]:1",
        "[::ffff:239.1.2.3]:1",
        "[::ffff:255.255.255.255]:1",
    ];
    for a in bad {
        let a: SocketAddr = a.parse().unwrap();
        assert_eq!(relay.handle(a, &[0xff], t0), Verdict::Drop(Reason::InvalidSource), "{a}");
    }
    let fine: SocketAddr = "[::ffff:192.0.2.1]:1".parse().unwrap();
    assert_eq!(relay.handle(fine, &[0xff], t0), Verdict::Drop(Reason::Malformed));
    assert_eq!(relay.metrics().rejected(Reason::InvalidSource), bad.len() as u64);
}

/// What the forwarding half alone makes of a datagram.
fn fast(relay: &Relay, from: SocketAddr, datagram: &[u8], now: Instant) -> Result<Lookup, Reason> {
    relay.control.forwarder().lookup(from, datagram, now)
}

#[test]
fn forwarder_follows_every_control_change() {
    let t0 = Instant::now();
    let limits = SessionLimits { pending_per_peer: 2, per_peer: 100, total: 100 };
    let mut relay = limited(limits, t0);
    let peers = relay.control.mac1.peers.clone();
    let to_control = |p: &[u8]| Ok(Lookup::ToControl(packet::parse(p).unwrap()));

    // A pending session stays with the control half.
    assert_eq!(relay.handle(src(1), &init_for(&relay, 0, 0x10), t0), Verdict::Forward(listed(0)));
    assert_eq!(fast(&relay, listed(0), &data(0x10), t0), to_control(&data(0x10)));
    assert_eq!(fast(&relay, listed(0), &cookie(0x10), t0), to_control(&cookie(0x10)));
    relay.control.assert_forwarder_in_step();

    // Opening publishes both indexes.
    assert_eq!(relay.handle(listed(0), &response(0x11, 0x10), t0), Verdict::Forward(src(1)));
    assert_eq!(fast(&relay, listed(0), &data(0x10), t0), Ok(Lookup::Forward(src(1))));
    assert_eq!(fast(&relay, src(1), &cookie(0x11), t0), Ok(Lookup::Forward(listed(0))));
    assert_eq!(fast(&relay, src(2), &data(0x11), t0), Err(Reason::WrongSource));
    relay.control.assert_forwarder_in_step();

    // Evicting pending entries leaves open ones alone.
    for i in 0..3 {
        let init = init_for(&relay, 0, 0x20 + i);
        assert_eq!(relay.handle(src(3), &init, t0), Verdict::Forward(listed(0)));
    }
    assert_eq!(relay.metrics().pending_evicted, 1);
    relay.control.assert_forwarder_in_step();

    // Roaming rewrites both directions.
    let moved = SocketAddr::from(([203, 0, 113, 77], 4000));
    relay.control.register(peers[0], moved, t0);
    assert_eq!(fast(&relay, src(1), &data(0x11), t0), Ok(Lookup::Forward(moved)));
    assert_eq!(fast(&relay, moved, &data(0x10), t0), Ok(Lookup::Forward(src(1))));
    assert_eq!(fast(&relay, listed(0), &data(0x10), t0), Err(Reason::WrongSource));
    relay.control.assert_forwarder_in_step();

    // A new peer's registration tunnel reserves its prefix at once.
    let extra: PeerKey = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).into();
    reload_listing(&mut relay, &[peers[0], peers[1], peers[2], extra]);
    let prefix = relay.control.reserved.iter().find(|(_, k)| **k == extra).unwrap().0;
    let in_prefix = prefix.get() << 8 | 7;
    assert_eq!(fast(&relay, src(1), &data(in_prefix), t0), to_control(&data(in_prefix)));
    relay.control.assert_forwarder_in_step();

    // Removing a peer revokes its open sessions and frees its prefix.
    assert_eq!(relay.handle(src(4), &init_for(&relay, 1, 0x30), t0), Verdict::Forward(listed(1)));
    assert_eq!(relay.handle(listed(1), &response(0x31, 0x30), t0), Verdict::Forward(src(4)));
    reload_listing(&mut relay, &[peers[0], peers[2]]);
    assert_eq!(fast(&relay, listed(1), &data(0x30), t0), to_control(&data(0x30)));
    assert_eq!(relay.handle(listed(1), &data(0x30), t0), Verdict::Drop(Reason::UnknownIndex));
    assert_eq!(fast(&relay, moved, &data(0x10), t0), Ok(Lookup::Forward(src(1))), "kept");
    assert!(relay.control.reserved.values().all(|k| *k != extra));
    relay.control.assert_forwarder_in_step();

    // Expiry withdraws the rest, and lookups stop before the sweep.
    let late = t0 + SESSION_TTL;
    assert_eq!(fast(&relay, moved, &data(0x10), late), to_control(&data(0x10)));
    assert_eq!(relay.handle(moved, &data(0x10), late), Verdict::Drop(Reason::UnknownIndex));
    relay.tick(late);
    assert_eq!(relay.control.forwarder.open.len(), 0);
    relay.control.assert_forwarder_in_step();
}

#[test]
fn verdicts_are_counted_by_the_half_that_decides() {
    let t0 = Instant::now();
    let limits = SessionLimits { pending_per_peer: 4, per_peer: 100, total: 100 };
    let mut relay = limited(limits, t0);
    assert_eq!(relay.handle(src(1), &init_for(&relay, 0, 0x10), t0), Verdict::Forward(listed(0)));
    assert_eq!(relay.handle(listed(0), &response(0x11, 0x10), t0), Verdict::Forward(src(1)));
    assert_eq!(relay.handle(src(1), &data(0x11), t0), Verdict::Forward(listed(0)));
    assert_eq!(relay.handle(src(2), &data(0x11), t0), Verdict::Drop(Reason::WrongSource));
    assert_eq!(relay.handle(src(2), &data(0x99), t0), Verdict::Drop(Reason::UnknownIndex));
    let (fast, control) = (&relay.counters, relay.control.metrics());
    assert_eq!((fast.rx, fast.forwarded, fast.rejected(Reason::WrongSource)), (2, 1, 1));
    assert_eq!((control.rx, control.forwarded, control.rejected(Reason::UnknownIndex)), (3, 2, 1));
    let all = relay.metrics();
    assert_eq!((all.rx, all.forwarded), (5, 3));
    assert!(all.to_string().starts_with("rx=5 forwarded=3 "), "{all}");
}

/// A small xorshift generator, so failures reproduce.
fn rng(seed: u64) -> impl FnMut() -> u64 {
    let mut x = seed;
    move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    }
}

#[test]
fn forwarder_stays_in_step_through_random_changes() {
    let mut now = Instant::now();
    // Small limits, so quotas, eviction and the global cap all come into play.
    let limits = SessionLimits { pending_per_peer: 3, per_peer: 12, total: 30 };
    let mut relay = limited(limits, now);
    relay.control.limiter = RateLimiter::new(1e9);
    let peers = relay.control.mac1.peers.clone();
    let keys = relay.control.mac1.keys.clone();
    let mut addrs: Vec<SocketAddr> = (0..3).map(listed).collect();
    let mut rnd = rng(0x9e37_79b9_7f4a_7c15);
    for step in 0..20_000 {
        let mut pick = |n: u64| (rnd() % n) as usize;
        // Mostly forwarded indexes, some in a reserved prefix.
        let tunnel = relay.control.reserved.keys().next().copied();
        let idx = match (pick(8), tunnel) {
            (0, Some(prefix)) => prefix.get() << 8 | pick(4) as u32,
            _ => 0x100 + pick(48) as u32,
        };
        let from = match pick(2) {
            0 => addrs[pick(3)],
            _ => src(1 + pick(4) as u8),
        };
        match pick(16) {
            0..=4 => {
                let init = init_keyed(&keys[pick(3)], idx);
                relay.handle(src(1 + pick(4) as u8), &init, now);
            }
            5..=7 => {
                let sender = 0x100 + pick(48) as u32;
                relay.handle(from, &response(sender, idx), now);
            }
            8..=12 => {
                let (datagram, is_data) = match pick(2) {
                    0 => (data(idx), true),
                    _ => (cookie(idx), false),
                };
                // The control half alone reaches the same verdict as the two halves.
                let message = packet::parse(&datagram).unwrap();
                let decided = match fast(&relay, from, &datagram, now) {
                    Ok(Lookup::ToControl(_)) => None,
                    Ok(Lookup::Forward(dst)) => Some(Ok(Accepted::Forward(dst))),
                    Err(reason) => Some(Err(reason)),
                };
                let alone = Verdict::from(relay.control.decide(from, &datagram, message, now));
                match decided {
                    Some(decided) => assert_eq!(Verdict::from(decided), alone, "step {step}"),
                    // Only a live open session forwards transport data, and the
                    // forwarding half holds all of those.
                    None if is_data => {
                        assert!(!matches!(alone, Verdict::Forward(_)), "step {step}: {alone:?}")
                    }
                    None => {}
                }
                relay.handle(from, &datagram, now);
            }
            13 => {
                now += Duration::from_secs(pick(30) as u64);
                relay.tick(now);
            }
            14 => {
                let i = pick(3);
                let moved = SocketAddr::from(([203, 0, 113, 100 + pick(50) as u8], 1));
                if relay.control.peers.contains_key(&peers[i]) {
                    addrs[i] = moved;
                    relay.control.register(peers[i], moved, now);
                }
            }
            _ => match pick(2) {
                0 => reload_listing(&mut relay, &peers[..2]),
                _ => reload_listing(&mut relay, &peers),
            },
        }
        relay.take_outbox();
        relay.control.assert_forwarder_in_step();
    }
    let all = relay.metrics();
    assert!(all.forwarded > 1000 && all.rejected(Reason::WrongSource) > 100, "{all}");
}
