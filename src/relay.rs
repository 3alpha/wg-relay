//! The relay state machine: registration tunnels plus opaque forwarding.
//!
//! `Relay::handle` does no I/O: it returns a `Verdict` for the datagram and
//! queues the relay's own tunnel output in `outbox`.

use crate::config::{Config, Gate, Role};
use crate::key::PeerKey;
use crate::packet::{self, Mac1Key, Packet};
use crate::tables::{REGISTRY_TTL, RateLimiter, Registry, SESSION_TTL, Session, SessionTable};
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Tunn, TunnResult};
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;
use tracing::{debug, info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

const SCRATCH_LEN: usize = 65536 + 256;

macro_rules! reasons {
    ($($v:ident => $s:literal),* $(,)?) => {
        /// Why a datagram was dropped. Each has its own counter.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Reason { $($v),* }
        impl Reason {
            pub const ALL: &'static [Reason] = &[$(Reason::$v),*];
            pub const COUNT: usize = Self::ALL.len();
        }
        impl fmt::Display for Reason {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(match self { $(Reason::$v => $s),* })
            }
        }
    };
}

reasons! {
    Malformed => "malformed",
    RateLimited => "rate_limited",
    ReservedIndex => "reserved_index",
    NoMac1Match => "no_mac1_match",
    ServerNotRegistered => "server_not_registered",
    SrcNotRegisteredClient => "src_not_registered_client",
    Acl => "acl",
    Loop => "loop",
    RekeyNotFromServer => "rekey_not_from_server",
    ClientAddrUnknown => "client_addr_unknown",
    UnknownIndex => "unknown_index",
    WrongSource => "wrong_source",
    ClientAddrMismatch => "client_addr_mismatch",
    ResponseUnknownClient => "response_unknown_client",
    ResponseNotForServer => "response_not_for_server",
    SessionNotOpen => "session_not_open",
    UnknownKey => "registration_unknown_key",
    ClientRegistrationOff => "client_registration_disabled",
    TunnelAuth => "tunnel_auth_failed",
}

/// What happened to one datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Send the datagram, unchanged, to this address.
    Forward(SocketAddr),
    /// Handled by the relay's own registration tunnel.
    Consumed,
    Drop(Reason),
}

impl From<Result<SocketAddr, Reason>> for Verdict {
    fn from(r: Result<SocketAddr, Reason>) -> Self {
        match r {
            Ok(dst) => Verdict::Forward(dst),
            Err(reason) => Verdict::Drop(reason),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Metrics {
    pub rx: u64,
    pub forwarded: u64,
    pub tunnel_rx: u64,
    pub tunnel_tx: u64,
    pub send_errors: u64,
    pub idx_collisions: u64,
    pub rejects: [u64; Reason::COUNT],
}

impl Metrics {
    pub fn rejected(&self, r: Reason) -> u64 {
        self.rejects[r as usize]
    }
}

impl fmt::Display for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rx={} forwarded={} tunnel_rx={} tunnel_tx={} send_errors={} idx_collisions={}",
            self.rx, self.forwarded, self.tunnel_rx, self.tunnel_tx, self.send_errors, self.idx_collisions
        )?;
        for r in Reason::ALL.iter().filter(|r| self.rejected(**r) > 0) {
            write!(f, " reject.{r}={}", self.rejected(*r))?;
        }
        Ok(())
    }
}

struct PeerState {
    name: String,
    role: Role,
    mac1: Mac1Key,
    servers: Vec<PeerKey>,
    /// Registration tunnel: servers always, clients only with `client_gate = "register"`.
    tunn: Option<Tunn>,
}

pub struct Relay {
    secret: StaticSecret,
    public: PublicKey,
    relay_mac1: Mac1Key,
    tunnel_ip: Ipv4Addr,
    gate: Gate,
    peers: HashMap<PeerKey, PeerState>,
    /// Upper 24 bits of each relay tunnel's local indexes. Forwarded sessions
    /// may never use these (see `reserved`).
    tunn_by_base: HashMap<u32, PeerKey>,
    pub registry: Registry<PeerKey>,
    /// Client addresses learned from accepted server responses (gates none/response).
    learned: HashMap<PeerKey, SocketAddr>,
    pub sessions: SessionTable,
    limiter: RateLimiter,
    pub metrics: Metrics,
    /// Datagrams produced by the relay's own tunnels, to be sent by the caller.
    pub outbox: Vec<(SocketAddr, Vec<u8>)>,
    scratch: Vec<u8>,
}

impl Relay {
    pub fn new(cfg: &Config) -> Self {
        let secret = cfg.private_key.secret().clone();
        let public = PublicKey::from(&secret);
        let mut relay = Relay {
            relay_mac1: packet::mac1_key(public.as_bytes()),
            secret,
            public,
            tunnel_ip: cfg.tunnel_ip,
            gate: cfg.gate,
            peers: HashMap::new(),
            tunn_by_base: HashMap::new(),
            registry: Registry::new(REGISTRY_TTL),
            learned: HashMap::new(),
            sessions: SessionTable::new(SESSION_TTL),
            limiter: RateLimiter::new(cfg.handshake_rate.per_sec()),
            metrics: Metrics::default(),
            outbox: Vec::new(),
            scratch: vec![0; SCRATCH_LEN],
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

    /// Apply a (re)loaded config. Removed keys, and clients that lost access,
    /// lose their registration and sessions immediately.
    pub fn reload(&mut self, cfg: &Config) {
        if cfg.private_key.public_key() != self.public_key() {
            warn!("changing private_key requires a restart; keeping the current key");
        }
        self.gate = cfg.gate;
        self.tunnel_ip = cfg.tunnel_ip;
        self.limiter.set_rate(cfg.handshake_rate.per_sec());
        let mut old = std::mem::take(&mut self.peers);
        for p in &cfg.peers {
            let registrable = p.role == Role::Server || cfg.gate == Gate::Register;
            let prev = old.remove(&p.pubkey).filter(|o| o.role == p.role).and_then(|o| o.tunn);
            let tunn = match (registrable, prev) {
                (true, Some(t)) => Some(t),
                (true, None) => Some(self.new_tunn(p.pubkey)),
                (false, _) => None,
            };
            let state = PeerState {
                name: p.name.clone(),
                role: p.role,
                mac1: packet::mac1_key(p.pubkey.as_bytes()),
                servers: p.servers.clone(),
                tunn,
            };
            self.peers.insert(p.pubkey, state);
        }
        for o in old.values() {
            info!(peer = %o.name, "peer removed from config");
        }
        let peers = &self.peers;
        self.tunn_by_base.retain(|_, k| peers.get(k).is_some_and(|p| p.tunn.is_some()));
        for k in self.registry.keys() {
            if !peers.get(&k).is_some_and(|p| p.tunn.is_some()) {
                self.registry.remove(&k);
            }
        }
        self.learned.retain(|k, _| peers.get(k).is_some_and(|p| p.role == Role::Client));
        let gate = self.gate;
        let dropped = self.sessions.retain(|s| session_allowed(peers, gate, s));
        info!(peers = peers.len(), gate = ?gate, dropped_sessions = dropped, "config applied");
    }

    /// A relay tunnel whose index range no live session uses.
    fn new_tunn(&mut self, peer: PeerKey) -> Tunn {
        let base = loop {
            let b = OsRng.next_u32() & 0x00ff_ffff;
            if !self.tunn_by_base.contains_key(&b) && !self.sessions.has_prefix(b) {
                break b;
            }
        };
        self.tunn_by_base.insert(base, peer);
        Tunn::new(self.secret.clone(), PublicKey::from(peer), None, None, base, None)
    }

    fn reserved(&self, idx: u32) -> bool {
        self.tunn_by_base.contains_key(&(idx >> 8))
    }

    /// The registration tunnel that owns this receiver index, if any.
    fn relay_tunnel(&self, idx: u32) -> Option<PeerKey> {
        self.tunn_by_base.get(&(idx >> 8)).copied()
    }

    fn role_of(&self, k: &PeerKey) -> Option<Role> {
        self.peers.get(k).map(|p| p.role)
    }

    /// Find the peer with this role whose key the packet's mac1 was made for.
    fn mac1_peer(&self, pkt: &[u8], role: Role) -> Option<PeerKey> {
        self.peers.iter().find(|(_, p)| p.role == role && packet::mac1_matches(&p.mac1, pkt)).map(|(k, _)| *k)
    }

    fn may_reach(&self, client: &PeerKey, server: &PeerKey) -> bool {
        self.peers.get(client).is_some_and(|p| p.role == Role::Client && p.servers.contains(server))
    }

    fn server_at(&self, src: SocketAddr, now: Instant) -> Option<PeerKey> {
        self.registry.key_at(src, now).filter(|k| self.role_of(k) == Some(Role::Server))
    }

    fn client_addr(&self, c: &PeerKey, now: Instant) -> Option<SocketAddr> {
        match self.gate {
            Gate::Register => self.registry.addr(c, now),
            Gate::None | Gate::Response => self.learned.get(c).copied(),
        }
    }

    /// Process one datagram, counting and logging the outcome.
    pub fn handle(&mut self, src: SocketAddr, pkt: &[u8], now: Instant) -> Verdict {
        self.metrics.rx += 1;
        let verdict = self.route(src, pkt, now);
        match verdict {
            Verdict::Forward(_) => self.metrics.forwarded += 1,
            Verdict::Consumed => self.metrics.tunnel_rx += 1,
            Verdict::Drop(r) => {
                self.metrics.rejects[r as usize] += 1;
                debug!(reason = %r, %src, "reject");
            }
        }
        verdict
    }

    fn route(&mut self, src: SocketAddr, pkt: &[u8], now: Instant) -> Verdict {
        let Ok(p) = packet::parse(pkt) else { return Verdict::Drop(Reason::Malformed) };
        match p {
            Packet::Init { .. } if !self.limiter.allow(src.ip(), now) => Verdict::Drop(Reason::RateLimited),
            Packet::Init { .. } if packet::mac1_matches(&self.relay_mac1, pkt) => {
                self.register_init(src, pkt, now)
            }
            Packet::Init { sender } => self.forward_init(src, pkt, sender, now).into(),
            Packet::Response { receiver, .. } | Packet::Cookie { receiver } | Packet::Data { receiver }
                if let Some(k) = self.relay_tunnel(receiver) =>
            {
                self.tunnel_rx(k, src, pkt, now)
            }
            Packet::Response { sender, receiver } => {
                self.forward_response(src, pkt, sender, receiver, now).into()
            }
            Packet::Cookie { receiver } => self.forward_indexed(src, false, receiver, now).into(),
            Packet::Data { receiver } => self.forward_indexed(src, true, receiver, now).into(),
        }
    }

    /// Identify the sender of a relay-bound initiation, then let its
    /// registration tunnel fully authenticate it.
    fn register_init(&mut self, src: SocketAddr, pkt: &[u8], now: Instant) -> Verdict {
        let half = match Tunn::parse_incoming_packet(pkt) {
            Ok(boringtun::noise::Packet::HandshakeInit(h)) => {
                parse_handshake_anon(&self.secret, &self.public, &h).ok()
            }
            _ => None,
        };
        let Some(key) = half.map(|h| PeerKey::from(h.peer_static_public)) else {
            return Verdict::Drop(Reason::TunnelAuth);
        };
        match self.peers.get(&key) {
            None => {
                debug!(%src, %key, "registration from key not in allowlist");
                Verdict::Drop(Reason::UnknownKey)
            }
            Some(PeerState { tunn: None, .. }) => Verdict::Drop(Reason::ClientRegistrationOff),
            Some(PeerState { tunn: Some(_), .. }) => self.tunnel_rx(key, src, pkt, now),
        }
    }

    /// Feed a datagram to `key`'s registration tunnel; on authentication,
    /// (re-)register the source address.
    fn tunnel_rx(&mut self, key: PeerKey, src: SocketAddr, pkt: &[u8], now: Instant) -> Verdict {
        let Some(PeerState { name, tunn: Some(tunn), .. }) = self.peers.get_mut(&key) else {
            return Verdict::Drop(Reason::TunnelAuth);
        };
        let (authenticated, reply) = match tunn.decapsulate(Some(src.ip()), pkt, &mut self.scratch) {
            TunnResult::Err(e) => {
                debug!(%src, peer = %name, ?e, "registration tunnel rejected packet");
                return Verdict::Drop(Reason::TunnelAuth);
            }
            TunnResult::WriteToNetwork(out) => {
                // A cookie reply we emit under load proves nothing about the sender.
                let auth = out.first() != Some(&3);
                self.outbox.push((src, out.to_vec()));
                while let TunnResult::WriteToNetwork(q) = tunn.decapsulate(None, &[], &mut self.scratch) {
                    self.outbox.push((src, q.to_vec()));
                }
                (auth, None)
            }
            TunnResult::WriteToTunnelV4(ip, _) => (true, icmp_echo_reply(ip, self.tunnel_ip)),
            TunnResult::WriteToTunnelV6(..) => (true, None),
            // Keepalive (authenticated) or an incoming cookie reply (not).
            TunnResult::Done => (pkt.first() == Some(&4), None),
        };
        if let Some(reply) = reply
            && let TunnResult::WriteToNetwork(out) = tunn.encapsulate(&reply, &mut self.scratch)
        {
            self.outbox.push((src, out.to_vec()));
        }
        if authenticated && let Some(old) = self.registry.update(key, src, now) {
            info!(peer = %name, addr = %src, old = ?old, "registered");
            if let Some(old) = old {
                self.sessions.migrate(old, src);
            }
        }
        Verdict::Consumed
    }

    fn forward_init(
        &mut self,
        src: SocketAddr,
        pkt: &[u8],
        sender: u32,
        now: Instant,
    ) -> Result<SocketAddr, Reason> {
        if self.reserved(sender) {
            return Err(Reason::ReservedIndex);
        }
        if let Some(server) = self.mac1_peer(pkt, Role::Server) {
            // A client (or, without `register`, anyone) initiating to a server.
            let dst = self.registry.addr(&server, now).ok_or(Reason::ServerNotRegistered)?;
            if dst == src {
                return Err(Reason::Loop);
            }
            let client = match self.gate {
                Gate::Register => {
                    let c = self
                        .registry
                        .key_at(src, now)
                        .filter(|c| self.role_of(c) == Some(Role::Client))
                        .ok_or(Reason::SrcNotRegisteredClient)?;
                    if !self.may_reach(&c, &server) {
                        return Err(Reason::Acl);
                    }
                    Some(c)
                }
                Gate::None | Gate::Response => None,
            };
            let s = Session { dest: src, expected_src: dst, open: false, last: now, server, client };
            return Ok(self.insert_session(sender, s));
        }
        if let Some(client) = self.mac1_peer(pkt, Role::Client) {
            // A server re-keying towards a client.
            let server = self.server_at(src, now).ok_or(Reason::RekeyNotFromServer)?;
            if !self.may_reach(&client, &server) {
                return Err(Reason::Acl);
            }
            let dst = self.client_addr(&client, now).ok_or(Reason::ClientAddrUnknown)?;
            let s = Session {
                dest: src,
                expected_src: dst,
                open: false,
                last: now,
                server,
                client: Some(client),
            };
            return Ok(self.insert_session(sender, s));
        }
        Err(Reason::NoMac1Match)
    }

    /// Store a session and return its counterpart's address, where the
    /// handshake message that created it goes.
    fn insert_session(&mut self, idx: u32, s: Session) -> SocketAddr {
        if self.sessions.insert(idx, s) {
            self.metrics.idx_collisions += 1;
        }
        s.expected_src
    }

    fn forward_response(
        &mut self,
        src: SocketAddr,
        pkt: &[u8],
        sender: u32,
        receiver: u32,
        now: Instant,
    ) -> Result<SocketAddr, Reason> {
        let init = self.sessions.get(receiver, now).ok_or(Reason::UnknownIndex)?;
        if src != init.expected_src {
            return Err(Reason::WrongSource);
        }
        if self.reserved(sender) {
            return Err(Reason::ReservedIndex);
        }
        let client = match self.server_at(src, now) {
            // Server answering a client: mac1 names the client the server authenticated.
            Some(server) if server != init.server => return Err(Reason::WrongSource),
            Some(server) => match (self.mac1_peer(pkt, Role::Client), self.gate) {
                (Some(c), _) if !self.may_reach(&c, &server) => return Err(Reason::Acl),
                (Some(c), Gate::Register) if self.registry.addr(&c, now) != Some(init.dest) => {
                    return Err(Reason::ClientAddrMismatch);
                }
                (Some(c), Gate::Register) => Some(c),
                (Some(c), Gate::None | Gate::Response) => {
                    self.learned.insert(c, init.dest);
                    Some(c)
                }
                (None, Gate::None) => None,
                (None, Gate::Response | Gate::Register) => return Err(Reason::ResponseUnknownClient),
            },
            // Client answering a server-initiated handshake.
            None => {
                let for_server =
                    self.peers.get(&init.server).is_some_and(|p| packet::mac1_matches(&p.mac1, pkt));
                if !for_server {
                    return Err(Reason::ResponseNotForServer);
                }
                init.client
            }
        };
        self.sessions.touch(receiver, now, true, client);
        let s = Session {
            dest: src,
            expected_src: init.dest,
            open: true,
            last: now,
            server: init.server,
            client,
        };
        self.insert_session(sender, s);
        Ok(init.dest)
    }

    /// Cookie replies and data: only from the expected source; data only on open sessions.
    fn forward_indexed(
        &mut self,
        src: SocketAddr,
        data: bool,
        receiver: u32,
        now: Instant,
    ) -> Result<SocketAddr, Reason> {
        let s = self.sessions.get(receiver, now).ok_or(Reason::UnknownIndex)?;
        if src != s.expected_src {
            return Err(Reason::WrongSource);
        }
        if data && !s.open {
            return Err(Reason::SessionNotOpen);
        }
        self.sessions.touch(receiver, now, false, None);
        Ok(s.dest)
    }

    /// Run relay tunnel timers and expire soft state. Call a few times a second.
    pub fn tick(&mut self, now: Instant) {
        for (k, p) in self.peers.iter_mut() {
            if let Some(t) = &mut p.tunn
                && let TunnResult::WriteToNetwork(out) = t.update_timers(&mut self.scratch)
                && let Some(a) = self.registry.addr(k, now)
            {
                self.outbox.push((a, out.to_vec()));
            }
        }
        for k in self.registry.expire(now) {
            info!(peer = %self.peers.get(&k).map_or("?", |p| &p.name), "registration expired");
        }
        let gone = self.sessions.expire(now);
        if gone > 0 {
            debug!(gone, live = self.sessions.len(), "expired sessions");
        }
        let live = self.sessions.clients();
        self.learned.retain(|k, _| live.contains(k));
        self.limiter.prune(now);
    }
}

/// May this session survive a config change?
fn session_allowed(peers: &HashMap<PeerKey, PeerState>, gate: Gate, s: &Session) -> bool {
    if !peers.get(&s.server).is_some_and(|p| p.role == Role::Server) {
        return false;
    }
    match s.client {
        Some(c) => peers.get(&c).is_some_and(|p| p.role == Role::Client && p.servers.contains(&s.server)),
        None => gate == Gate::None || !s.open,
    }
}

/// If `ip` is an ICMP echo request to `me`, build the echo reply.
fn icmp_echo_reply(ip: &[u8], me: Ipv4Addr) -> Option<Vec<u8>> {
    let ihl = usize::from(*ip.first()? & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]));
    if ip[0] >> 4 != 4 || ihl < 20 || total > ip.len() || total < ihl + 8 {
        return None;
    }
    if ip[9] != 1 || ip[16..20] != me.octets() || ip[ihl] != 8 {
        return None;
    }
    let mut r = ip[..total].to_vec();
    let (src, dst) = ([r[12], r[13], r[14], r[15]], [r[16], r[17], r[18], r[19]]);
    r[12..16].copy_from_slice(&dst);
    r[16..20].copy_from_slice(&src);
    r[8] = 64;
    r[ihl] = 0;
    r[ihl + 2..ihl + 4].fill(0);
    let c = checksum(&r[ihl..]);
    r[ihl + 2..ihl + 4].copy_from_slice(&c.to_be_bytes());
    r[10..12].fill(0);
    let c = checksum(&r[..ihl]);
    r[10..12].copy_from_slice(&c.to_be_bytes());
    Some(r)
}

fn checksum(b: &[u8]) -> u16 {
    let mut sum: u32 =
        b.chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))).sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_reply_roundtrip() {
        let me = Ipv4Addr::new(10, 99, 0, 1);
        let mut req = vec![0x45, 0, 0, 28, 0, 1, 0, 0, 64, 1, 0, 0, 10, 99, 0, 2, 10, 99, 0, 1];
        req.extend_from_slice(&[8, 0, 0, 0, 0x12, 0x34, 0, 1]);
        let c = checksum(&req[..20]);
        req[10..12].copy_from_slice(&c.to_be_bytes());
        let r = icmp_echo_reply(&req, me).unwrap();
        assert_eq!(&r[12..16], &[10, 99, 0, 1]);
        assert_eq!(&r[16..20], &[10, 99, 0, 2]);
        assert_eq!(r[20], 0);
        assert_eq!(checksum(&r[..20]), 0);
        assert_eq!(checksum(&r[20..]), 0);
        assert!(icmp_echo_reply(&req[..10], me).is_none());
        assert!(icmp_echo_reply(&req, Ipv4Addr::new(1, 2, 3, 4)).is_none());
    }
}
