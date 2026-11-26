use std::time::{Duration, Instant};

use boringtun::noise::TunnResult;
use tracing::{debug, info};

use super::ControlPlane;

/// A step that runs at most once per interval, however often it is offered.
pub(super) struct Throttle {
    interval: Duration,
    last: Option<Instant>,
}

impl Throttle {
    pub(super) fn new(interval: Duration) -> Self {
        Throttle { interval, last: None }
    }

    /// May the step run at `now`? If it may, it counts as run.
    fn try_run(&mut self, now: Instant) -> bool {
        let due = self.last.is_none_or(|t| now.saturating_duration_since(t) >= self.interval);
        if due {
            self.last = Some(now);
        }
        due
    }
}

impl ControlPlane {
    /// Run the registration tunnels' timers and, less often, expire soft state.
    /// A tick that comes sooner than `TICK_INTERVAL` after the last one does nothing.
    pub(in crate::relay) fn tick(&mut self, now: Instant) {
        if !self.ticks.try_run(now) {
            return;
        }
        self.run_tunnel_timers(now);
        if self.gc.try_run(now) {
            self.collect_garbage(now);
        }
    }

    /// Queue whatever the registration tunnels' timers send, to registered peers only.
    fn run_tunnel_timers(&mut self, now: Instant) {
        for (key, peer) in &mut self.peers {
            let TunnResult::WriteToNetwork(out) = peer.tunnel.update_timers(&mut self.scratch)
            else {
                continue;
            };
            if let Some(endpoint) = self.registry.endpoint(key, now) {
                self.tx_queue.push((endpoint, out.to_vec()));
            }
        }
    }

    /// Expire stale registrations and sessions.
    fn collect_garbage(&mut self, now: Instant) {
        for k in self.registry.expire(now) {
            info!(peer = %self.peers.get(&k).map_or("?", |p| &p.name), "registration expired");
        }
        let gone = self.sessions.expire(now, &self.data_plane.established);
        if gone > 0 {
            debug!(gone, live = self.sessions.len(), "expired sessions");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttle_takes_one_offer_per_interval() {
        let (t0, ms) = (Instant::now(), Duration::from_millis);
        let mut throttle = Throttle::new(ms(250));
        let offered = [0, 10, 249, 250, 260, 499, 500, 900, 900];
        let ran = offered.map(|t| throttle.try_run(t0 + ms(t)));
        assert_eq!(ran, [true, false, false, true, false, false, true, true, false]);
    }
}
