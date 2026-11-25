use boringtun::noise::Tunn;
use rand_core::{OsRng, RngCore};
use tracing::{info, warn};
use x25519_dalek::PublicKey;

use super::{PeerState, Relay};
use crate::config::Config;
use crate::key::PeerKey;
use crate::packet::{self, IdxPrefix};

impl Relay {
    /// Apply a (re)loaded config. Removed peers lose their registrations, and
    /// every session routed to them, immediately.
    pub fn reload(&mut self, cfg: &Config) {
        if cfg.private_key.public_key() != self.public_key() {
            warn!("changing private_key requires a restart; keeping the current key");
        }
        self.tunnel_ip = cfg.tunnel_ip;
        self.limiter.set_rate(cfg.handshake_rate.per_sec());
        let mut old = std::mem::take(&mut self.peers);
        for p in &cfg.peers {
            let tunn = match old.remove(&p.pubkey) {
                Some(o) => o.tunn,
                None => Box::new(self.new_tunn(p.pubkey)),
            };
            let state = PeerState {
                name: p.name.clone(),
                mac1: packet::mac1_key(p.pubkey.as_bytes()),
                tunn,
            };
            self.peers.insert(p.pubkey, state);
        }
        for o in old.values() {
            info!(peer = %o.name, "peer removed from config");
        }
        let peers = &self.peers;
        self.tunn_by_prefix.retain(|_, k| peers.contains_key(k));
        for k in self.registry.keys() {
            if !peers.contains_key(&k) {
                self.registry.remove(&k);
            }
        }
        let dropped = self.sessions.retain(|s| peers.contains_key(&s.peer));
        info!(peers = peers.len(), dropped_sessions = dropped, "config applied");
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
