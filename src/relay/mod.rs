//! The relay state machine: registration tunnels plus opaque forwarding.
//!
//! `Relay::handle` does no I/O: it returns a `Verdict` for the datagram and
//! queues the relay's own tunnel output for `take_outbox`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use tracing::{debug, info};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::Config;
use crate::key::PeerKey;
use crate::packet::{self, IdxPrefix, Mac1Key, Packet, SessionIdx};
use crate::tables::{
    PENDING_TTL, REGISTRY_TTL, RateLimiter, Registry, SESSION_TTL, SessionTable, WorkBudget,
};

mod forward;
mod metrics;
mod reason;
mod registration;
mod reload;

use forward::Indexed;
pub use metrics::Metrics;
pub use reason::{Reason, Verdict};

const SCRATCH_LEN: usize = 65536 + 256;
/// Expiry scans every table, so it runs less often than the tunnel timers.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// Mac1 checks per second for finding forwarded initiations' destinations;
/// separate from registration so a flood of either cannot starve the other.
const FORWARD_WORK_PER_SEC: f64 = 1_000_000.0;
/// Registration work per second from sources that are not a registered
/// peer's address, in mac1 checks: 500 attempts.
const REGISTRATION_WORK_PER_SEC: f64 = 200_000.0;
/// What a registration attempt costs: its X25519 work, measured in mac1 checks.
const REGISTRATION_WORK: usize = 400;
/// Most handshakes one listed peer may have awaiting a response; a new one
/// evicts its oldest, so a flood aimed at one peer only disturbs that peer.
const MAX_PENDING_PER_PEER: usize = 1_024;
/// Most handshakes awaiting a response at once (about 70 MB of table), a
/// memory backstop; the forwarding budget keeps floods well below it.
const MAX_PENDING: usize = 262_144;

/// What the relay holds for each listed peer.
struct PeerState {
    name: String,
    /// The peer's registration tunnel with the relay.
    tunn: Box<Tunn>,
}

/// The listed peers' mac1 keys in one contiguous list, for batched scans.
#[derive(Default)]
struct Mac1Index {
    peers: Vec<PeerKey>,
    keys: Vec<Mac1Key>,
}

pub struct Relay {
    secret: StaticSecret,
    public: PublicKey,
    relay_mac1: Mac1Key,
    tunnel_ip: Ipv4Addr,
    peers: HashMap<PeerKey, PeerState>,
    mac1: Mac1Index,
    /// Index prefix of each relay tunnel. Forwarded sessions may never use
    /// these (see `reserved`).
    tunn_by_prefix: HashMap<IdxPrefix, PeerKey>,
    /// Where each listed peer last proved it can be reached.
    registry: Registry,
    sessions: SessionTable,
    limiter: RateLimiter,
    forward_budget: WorkBudget,
    registration_budget: WorkBudget,
    metrics: Metrics,
    /// Datagrams produced by the relay's own tunnels, to be sent by the caller.
    outbox: Vec<(SocketAddr, Vec<u8>)>,
    scratch: Vec<u8>,
    last_sweep: Option<Instant>,
}

impl Relay {
    pub fn new(cfg: &Config) -> Self {
        let secret = cfg.private_key.secret().clone();
        let public = PublicKey::from(&secret);
        let mut relay = Relay {
            relay_mac1: Mac1Key::new(public.as_bytes()),
            secret,
            public,
            tunnel_ip: cfg.tunnel_ip,
            peers: HashMap::new(),
            mac1: Mac1Index::default(),
            tunn_by_prefix: HashMap::new(),
            registry: Registry::new(REGISTRY_TTL),
            sessions: SessionTable::new(SESSION_TTL, PENDING_TTL, MAX_PENDING_PER_PEER),
            limiter: RateLimiter::new(cfg.handshake_rate.per_sec()),
            forward_budget: WorkBudget::new(FORWARD_WORK_PER_SEC),
            registration_budget: WorkBudget::new(REGISTRATION_WORK_PER_SEC),
            metrics: Metrics::default(),
            outbox: Vec::new(),
            scratch: vec![0; SCRATCH_LEN],
            last_sweep: None,
        };
        relay.reload(cfg);
        relay
    }

    pub fn public_key(&self) -> PeerKey {
        self.public.into()
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Where `key` is currently registered, if anywhere.
    pub fn registered_addr(&self, key: &PeerKey, now: Instant) -> Option<SocketAddr> {
        self.registry.addr(key, now)
    }

    /// Hand over the datagrams the relay's own tunnels want to send.
    pub fn take_outbox(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let out = std::mem::take(&mut self.outbox);
        self.metrics.tunnel_tx += out.len() as u64;
        out
    }

    /// Count a datagram the caller failed to send.
    pub fn record_send_error(&mut self) {
        self.metrics.send_errors += 1;
    }

    /// Process one datagram, counting and logging the outcome.
    pub fn handle(&mut self, src: SocketAddr, pkt: &[u8], now: Instant) -> Verdict {
        let verdict = self.route(src, pkt, now);
        self.metrics.record(verdict);
        if let Verdict::Drop(reason) = verdict {
            debug!(%reason, %src, "reject");
        }
        verdict
    }

    fn route(&mut self, src: SocketAddr, pkt: &[u8], now: Instant) -> Verdict {
        let Ok(p) = packet::parse(pkt) else { return Verdict::Drop(Reason::Malformed) };
        match p {
            Packet::Init { .. } if !self.limiter.allow(src.ip(), now) => {
                Verdict::Drop(Reason::RateLimited)
            }
            Packet::Init { .. } if self.relay_mac1.matches(pkt) => {
                match self.admit_registration(src, now) {
                    Ok(()) => self.register_init(src, pkt, now),
                    Err(reason) => Verdict::Drop(reason),
                }
            }
            Packet::Init { sender } => self.forward_init(src, pkt, sender, now).into(),
            Packet::Response { receiver, .. }
            | Packet::Cookie { receiver }
            | Packet::Data { receiver }
                if let Some(k) = self.relay_tunnel(receiver) =>
            {
                self.tunnel_rx(k, src, pkt, now)
            }
            Packet::Response { sender, receiver } => {
                self.forward_response(src, sender, receiver, now).into()
            }
            Packet::Cookie { receiver } => {
                self.forward_indexed(src, Indexed::Cookie, receiver, now).into()
            }
            Packet::Data { receiver } => {
                self.forward_indexed(src, Indexed::Data, receiver, now).into()
            }
        }
    }

    /// Run relay tunnel timers and expire soft state. Call a few times a second.
    pub fn tick(&mut self, now: Instant) {
        for (key, peer) in &mut self.peers {
            let TunnResult::WriteToNetwork(out) = peer.tunn.update_timers(&mut self.scratch) else {
                continue;
            };
            if let Some(addr) = self.registry.addr(key, now) {
                self.outbox.push((addr, out.to_vec()));
            }
        }
        let swept_recently =
            self.last_sweep.is_some_and(|t| now.saturating_duration_since(t) < SWEEP_INTERVAL);
        if swept_recently {
            return;
        }
        self.last_sweep = Some(now);
        for k in self.registry.expire(now) {
            info!(peer = %self.peers.get(&k).map_or("?", |p| &p.name), "registration expired");
        }
        let gone = self.sessions.expire(now);
        if gone > 0 {
            debug!(gone, live = self.sessions.len(), "expired sessions");
        }
    }

    fn reserved(&self, idx: SessionIdx) -> bool {
        self.tunn_by_prefix.contains_key(&idx.prefix())
    }

    /// The registration tunnel that owns this receiver index, if any.
    fn relay_tunnel(&self, idx: SessionIdx) -> Option<PeerKey> {
        self.tunn_by_prefix.get(&idx.prefix()).copied()
    }

    /// Decide whether a relay-bound initiation may cost an X25519 operation.
    /// A registered peer's address skips the registration budget, so a flood from
    /// elsewhere cannot stop it re-handshaking; its per-source limit still applies.
    fn admit_registration(&mut self, src: SocketAddr, now: Instant) -> Result<(), Reason> {
        if self.registry.is_registered(src, now) {
            return Ok(());
        }
        if !self.registration_budget.available(now) {
            return Err(Reason::RegistrationBudget);
        }
        self.registration_budget.spend(REGISTRATION_WORK);
        Ok(())
    }

    /// Find the listed peer whose key the packet's mac1 was made for,
    /// charging the scan to the forwarding budget.
    fn mac1_peer(&mut self, pkt: &[u8], now: Instant) -> Result<PeerKey, Reason> {
        if !self.forward_budget.available(now) {
            return Err(Reason::HandshakeBudget);
        }
        let search = packet::find_mac1(&self.mac1.keys, pkt);
        self.forward_budget.spend(search.tried);
        search.found.map(|i| self.mac1.peers[i]).ok_or(Reason::NoMac1Match)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use rand_core::OsRng;

    /// A relay listing three random peers, none of them registered.
    fn relay() -> Relay {
        let b64 = |b: [u8; 32]| base64::engine::general_purpose::STANDARD.encode(b);
        let mut cfg =
            format!("private_key = \"{}\"\n", b64(StaticSecret::random_from_rng(OsRng).to_bytes()));
        for i in 0..3 {
            let pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
            cfg += &format!("[[peer]]\nname = \"p{i}\"\npubkey = \"{}\"\n", b64(pk.to_bytes()));
        }
        Relay::new(&Config::parse(&cfg).unwrap())
    }

    fn src(i: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, i], 1))
    }

    /// An initiation matching no listed key, so it costs a scan of all three.
    fn junk() -> Vec<u8> {
        let mut p = vec![0u8; packet::INIT_LEN];
        p[0] = 1;
        p
    }

    /// An initiation whose mac1 is for the relay but whose body is garbage.
    fn junk_for_relay(relay: &Relay) -> Vec<u8> {
        let mut p = junk();
        let mac = relay.relay_mac1.mac(&p[..116]);
        p[116..132].copy_from_slice(&mac);
        p
    }

    #[test]
    fn handshake_budget_sheds_initiations_once_spent() {
        let mut relay = relay();
        relay.forward_budget = WorkBudget::new(10.0);
        let t0 = Instant::now();
        let junk = junk();
        let verdicts: Vec<Verdict> = (0..5).map(|i| relay.handle(src(i), &junk, t0)).collect();
        let (miss, shed) =
            (Verdict::Drop(Reason::NoMac1Match), Verdict::Drop(Reason::HandshakeBudget));
        assert_eq!(verdicts, [miss, miss, miss, miss, shed], "10 -> 7 -> 4 -> 1 -> -2");
        assert_eq!(relay.handle(src(9), &junk, t0 + Duration::from_millis(300)), miss, "refilled");
        assert_eq!(relay.metrics().rejected(Reason::HandshakeBudget), 1);
    }

    /// A relay whose forwarding budget allows one scan and whose registration
    /// budget allows one attempt, plus a relay-bound initiation for it.
    fn tiny_budgets() -> (Relay, Vec<u8>) {
        let mut relay = relay();
        relay.forward_budget = WorkBudget::new(3.0);
        relay.registration_budget = WorkBudget::new(REGISTRATION_WORK as f64);
        let reg = junk_for_relay(&relay);
        (relay, reg)
    }

    const MISS: Verdict = Verdict::Drop(Reason::NoMac1Match);
    const FWD_SHED: Verdict = Verdict::Drop(Reason::HandshakeBudget);
    const ATTEMPT: Verdict = Verdict::Drop(Reason::TunnelAuth);
    const REG_SHED: Verdict = Verdict::Drop(Reason::RegistrationBudget);

    #[test]
    fn spent_forwarding_budget_leaves_registration_admitted() {
        let (t0, fwd) = (Instant::now(), junk());
        let (mut relay, reg) = tiny_budgets();
        assert_eq!(
            [relay.handle(src(1), &fwd, t0), relay.handle(src(2), &fwd, t0)],
            [MISS, FWD_SHED]
        );
        assert_eq!(relay.handle(src(3), &reg, t0), ATTEMPT);
        assert_eq!(relay.handle(src(4), &reg, t0), REG_SHED);
        assert_eq!(relay.handle(src(5), &fwd, t0), FWD_SHED);
    }

    #[test]
    fn spent_registration_budget_leaves_forwarding_scanning() {
        let (t0, fwd) = (Instant::now(), junk());
        let (mut relay, reg) = tiny_budgets();
        assert_eq!(
            [relay.handle(src(1), &reg, t0), relay.handle(src(2), &reg, t0)],
            [ATTEMPT, REG_SHED]
        );
        assert_eq!(relay.handle(src(3), &fwd, t0), MISS);
        assert_eq!(relay.handle(src(4), &fwd, t0), FWD_SHED);
    }

    #[test]
    fn registered_address_skips_the_spent_registration_budget() {
        let t0 = Instant::now();
        let (mut relay, reg) = tiny_budgets();
        let listed = relay.mac1.peers[0];
        relay.registry.update(listed, src(7), t0);
        assert_eq!(
            [relay.handle(src(1), &reg, t0), relay.handle(src(2), &reg, t0)],
            [ATTEMPT, REG_SHED]
        );
        assert_eq!(relay.handle(src(7), &reg, t0), ATTEMPT, "registered");
        // Once the registration expires, the address competes for the budget again.
        let later = t0 + REGISTRY_TTL;
        relay.registration_budget = WorkBudget::new(REGISTRATION_WORK as f64);
        assert_eq!(
            [relay.handle(src(2), &reg, later), relay.handle(src(7), &reg, later)],
            [ATTEMPT, REG_SHED]
        );
    }

    #[test]
    fn full_pending_table_refuses_initiations_before_the_scan() {
        let mut relay = relay();
        relay.forward_budget = WorkBudget::new(10.0);
        let (now, a, b) = (Instant::now(), src(1), src(2));
        // Spread over enough peers that no quota evicts anything.
        for i in 0..MAX_PENDING as u32 {
            let mut key = [0; 32];
            key[..4].copy_from_slice(&(i / MAX_PENDING_PER_PEER as u32).to_le_bytes());
            let s = crate::tables::Session::pending(a, b, PeerKey::from(key), now);
            assert!(relay.sessions.insert(i.into(), s));
        }
        assert_eq!(relay.sessions.pending(), MAX_PENDING);
        let mut junk = junk();
        junk[4] = 0xee; // a sender index none of the entries uses
        junk[7] = 0xee;
        let verdicts: Vec<Verdict> = (0..5).map(|_| relay.handle(a, &junk, now)).collect();
        assert_eq!(verdicts, [Verdict::Drop(Reason::TooManyPending); 5], "and no budget spent");
        relay.tick(now + PENDING_TTL + SWEEP_INTERVAL);
        assert_eq!(relay.sessions.pending(), 0);
        let later = now + PENDING_TTL + SWEEP_INTERVAL;
        assert_eq!(relay.handle(a, &junk, later), Verdict::Drop(Reason::NoMac1Match));
    }
}
