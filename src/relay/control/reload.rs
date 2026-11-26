use boringtun::noise::Tunn;
use rand_core::{OsRng, RngCore};
use tracing::{info, warn};
use x25519_dalek::PublicKey;

use super::{Control, Mac1Index, PeerState};
use crate::config::Config;
use crate::key::PeerKey;
use crate::packet::{IdxPrefix, Mac1Key};

impl Control {
    /// Apply a (re)loaded config. Removed peers lose their registrations, and
    /// every session routed to them, immediately.
    pub(in crate::relay) fn reload(&mut self, cfg: &Config) {
        if cfg.private_key.public_key() != self.public_key() {
            warn!("changing private_key requires a restart; keeping the current key");
        }
        self.tunnel_ip = cfg.tunnel_ip;
        self.limiter.set_rate(cfg.handshake_rate.per_sec());
        let mut old = std::mem::take(&mut self.peers);
        for p in &cfg.peers {
            let tunnel = match old.remove(&p.pubkey) {
                Some(o) => o.tunnel,
                None => Box::new(self.new_tunnel(p.pubkey)),
            };
            self.peers.insert(p.pubkey, PeerState { name: p.name.clone(), tunnel });
        }
        self.mac1 = Mac1Index {
            peers: cfg.peers.iter().map(|p| p.pubkey).collect(),
            keys: cfg.peers.iter().map(|p| Mac1Key::new(p.pubkey.as_bytes())).collect(),
        };
        for o in old.values() {
            info!(peer = %o.name, "peer removed from config");
        }
        let peers = &self.peers;
        self.forwarder.reserved.retain(|k| peers.contains_key(k));
        self.registry.retain(|k, _| peers.contains_key(k));
        let dropped = self.sessions.retain(|s| peers.contains_key(&s.peer), &self.forwarder.open);
        info!(peers = peers.len(), dropped_sessions = dropped, "config applied");
    }

    /// Build a registration tunnel in a new reserved prefix that no live session uses.
    fn new_tunnel(&mut self, peer: PeerKey) -> Tunn {
        let prefix = loop {
            let p = IdxPrefix::from_bits(OsRng.next_u32());
            if !self.forwarder.reserved.contains(p) && !self.sessions.has_prefix(p) {
                break p;
            }
        };
        self.forwarder.reserved.reserve(prefix, peer);
        Tunn::new(self.secret.clone(), PublicKey::from(peer), None, None, prefix.get(), None)
    }
}
