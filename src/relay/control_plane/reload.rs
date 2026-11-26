use boringtun::noise::Tunn;
use rand_core::{OsRng, RngCore};
use tracing::{info, warn};

use super::{ControlPlane, Mac1Table, PeerState};
use crate::config::Config;
use crate::key::PublicKey;
use crate::message::{IndexPrefix, Mac1Key};

impl ControlPlane {
    /// Apply a (re)loaded config. Removed peers lose their registrations, and
    /// every session routed to them, immediately.
    pub(in crate::relay) fn reload(&mut self, config: &Config) {
        if config.private_key.public_key() != self.public_key() {
            warn!("changing private_key requires a restart; keeping the current key");
        }
        self.tunnel_ip = config.tunnel_ip;
        self.limiter.set_rate(config.handshake_rate.per_sec());
        let mut old = std::mem::take(&mut self.peers);
        for p in &config.peers {
            let state = match old.remove(&p.pubkey) {
                Some(o) => PeerState { name: p.name.clone(), ..o },
                None => PeerState {
                    name: p.name.clone(),
                    tunnel: Box::new(self.new_tunnel(p.pubkey)),
                    initiations_forwarded: 0,
                    initiations_dropped: 0,
                },
            };
            self.peers.insert(p.pubkey, state);
        }
        self.mac1 = Mac1Table {
            peers: config.peers.iter().map(|p| p.pubkey).collect(),
            keys: config.peers.iter().map(|p| Mac1Key::new(p.pubkey.as_bytes())).collect(),
        };
        for o in old.values() {
            info!(peer = %o.name, "peer removed from config");
        }
        let peers = &self.peers;
        self.data_plane.reserved.retain(|k| peers.contains_key(k));
        self.registry.retain(|k, _| peers.contains_key(k));
        let dropped =
            self.sessions.retain(|s| peers.contains_key(&s.peer), &self.data_plane.established);
        self.counters.sessions_revoked += dropped as u64;
        info!(peers = peers.len(), dropped_sessions = dropped, "config applied");
    }

    /// Build a registration tunnel in a new reserved prefix that no live session uses.
    fn new_tunnel(&mut self, peer: PublicKey) -> Tunn {
        let prefix = loop {
            let p = IndexPrefix::from_bits(OsRng.next_u32());
            if !self.data_plane.reserved.contains(p) && !self.sessions.has_prefix(p) {
                break p;
            }
        };
        self.data_plane.reserved.reserve(prefix, peer);
        let public = x25519_dalek::PublicKey::from(peer);
        Tunn::new(self.secret.clone(), public, None, None, prefix.get(), None)
    }
}
