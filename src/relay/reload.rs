use std::collections::HashMap;

use boringtun::noise::Tunn;
use rand_core::{OsRng, RngCore};
use tracing::{info, warn};
use x25519_dalek::PublicKey;

use super::{PeerKind, PeerState, Relay};
use crate::config::{Config, Gate, Role};
use crate::key::PeerKey;
use crate::packet::{self, IdxPrefix};
use crate::tables::{Session, SessionState};

impl Relay {
    /// Apply a (re)loaded config. Removed keys, and clients that lost access,
    /// lose their registrations and sessions immediately.
    pub fn reload(&mut self, cfg: &Config) {
        if cfg.private_key.public_key() != self.public_key() {
            warn!("changing private_key requires a restart; keeping the current key");
        }
        self.gate = cfg.gate;
        self.tunnel_ip = cfg.tunnel_ip;
        self.limiter.set_rate(cfg.handshake_rate.per_sec());
        let mut old = std::mem::take(&mut self.peers);
        for p in &cfg.peers {
            let prev_tunn = match old.remove(&p.pubkey).map(|o| o.kind) {
                Some(PeerKind::Server { tunn }) => Some(tunn),
                Some(PeerKind::Client { .. }) | None => None,
            };
            let kind = match (&p.role, prev_tunn) {
                (Role::Server, Some(tunn)) => PeerKind::Server { tunn },
                (Role::Server, None) => {
                    PeerKind::Server { tunn: Box::new(self.new_tunn(p.pubkey)) }
                }
                (Role::Client { servers }, _) => PeerKind::Client { servers: servers.clone() },
            };
            let state = PeerState {
                name: p.name.clone(),
                mac1: packet::mac1_key(p.pubkey.as_bytes()),
                kind,
            };
            self.peers.insert(p.pubkey, state);
        }
        for o in old.values() {
            info!(peer = %o.name, "peer removed from config");
        }
        let peers = &self.peers;
        self.tunn_by_prefix.retain(|_, k| peers.get(k).is_some_and(|p| p.kind.is_server()));
        for k in self.registry.keys() {
            if !peers.get(&k).is_some_and(|p| p.kind.is_server()) {
                self.registry.remove(&k);
            }
        }
        self.learned.retain(|k, _| peers.get(k).is_some_and(|p| p.kind.is_client()));
        let gate = self.gate;
        let dropped = self.sessions.retain(|s| session_allowed(peers, gate, s));
        info!(peers = peers.len(), gate = ?gate, dropped_sessions = dropped, "config applied");
    }

    /// Build a relay tunnel whose index range no live session uses.
    fn new_tunn(&mut self, peer: PeerKey) -> Tunn {
        let prefix = loop {
            let p = IdxPrefix::from_bits(OsRng.next_u32());
            if !self.tunn_by_prefix.contains_key(&p) && !self.sessions.has_prefix(p) {
                break p;
            }
        };
        self.tunn_by_prefix.insert(prefix, peer);
        Tunn::new(self.secret.clone(), PublicKey::from(peer), None, None, prefix.get(), None)
    }
}

/// May this session survive a config change?
fn session_allowed(peers: &HashMap<PeerKey, PeerState>, gate: Gate, s: &Session) -> bool {
    if !peers.get(&s.server).is_some_and(|p| p.kind.is_server()) {
        return false;
    }
    match (s.client, gate, s.state) {
        (Some(c), _, _) => peers.get(&c).is_some_and(|p| p.kind.may_reach(&s.server)),
        // Only `none` lets a session open without identifying its client.
        (None, Gate::None, _) | (None, Gate::Response, SessionState::Pending) => true,
        (None, Gate::Response, SessionState::Open) => false,
    }
}
