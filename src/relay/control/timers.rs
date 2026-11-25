use std::time::Instant;

use boringtun::noise::TunnResult;
use tracing::{debug, info};

use super::{Control, SWEEP_INTERVAL};

impl Control {
    /// Run relay tunnel timers and expire soft state.
    pub(in crate::relay) fn tick(&mut self, now: Instant) {
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
        let gone = self.sessions.expire(now, &mut self.forwarder.open);
        if gone > 0 {
            debug!(gone, live = self.sessions.len(), "expired sessions");
        }
    }
}
