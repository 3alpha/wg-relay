//! The Prometheus endpoint: what one scrape reports, rendered as text, and
//! the HTTP server that serves it at `/metrics`.

use std::time::{Duration, SystemTime};

use super::workers::Snapshot;

mod encoder;
mod handshakes;
pub(super) mod http;
mod peers;
mod process;
mod state;
mod traffic;

use encoder::Encoder;
pub(super) use process::Process;

/// Reloads since startup, as the main thread applied them.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct Reloads {
    pub(super) succeeded: u64,
    pub(super) failed: u64,
    pub(super) last_successful: bool,
    /// When the config was last applied: startup, or the last successful reload.
    pub(super) last_success: SystemTime,
}

impl Reloads {
    /// No reload yet: the config applied at `started` counts as the last success.
    pub(super) fn new(started: SystemTime) -> Self {
        Reloads { succeeded: 0, failed: 0, last_successful: true, last_success: started }
    }

    pub(super) fn record_success(&mut self, at: SystemTime) {
        self.succeeded += 1;
        self.last_successful = true;
        self.last_success = at;
    }

    pub(super) fn record_failure(&mut self) {
        self.failed += 1;
        self.last_successful = false;
    }
}

/// Everything one scrape reports, gathered when the request arrives.
pub(super) struct Scrape {
    pub(super) snapshot: Snapshot,
    /// Handshake initiations per second each source may send, as last applied.
    pub(super) handshake_rate_per_sec: f64,
    pub(super) reloads: Reloads,
    pub(super) started: SystemTime,
    pub(super) now: SystemTime,
    /// The process's resources, where the platform tells them.
    pub(super) process: Option<Process>,
}

/// Time since the Unix epoch; zero for a clock set before it.
fn unix(t: SystemTime) -> Duration {
    t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default()
}

/// Render a scrape in the Prometheus text format.
pub(super) fn render(scrape: &Scrape) -> String {
    let mut enc = Encoder::default();
    let control = &scrape.snapshot.control;
    traffic::encode(&mut enc, &scrape.snapshot);
    state::encode(&mut enc, scrape);
    handshakes::encode(&mut enc, control, scrape.handshake_rate_per_sec);
    peers::encode(&mut enc, control, unix(scrape.now));
    process::encode(&mut enc, scrape.process.as_ref(), unix(scrape.started));
    enc.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use wg_relay::relay::{ControlSnapshot, DropReason, Metrics};

    #[test]
    fn every_sample_belongs_to_one_announced_family_and_every_drop_reason_is_there() {
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let control = ControlSnapshot::default();
        let snapshot =
            Snapshot { control, workers: vec![Metrics::default(); 2], total: Metrics::default() };
        let scrape = Scrape {
            snapshot,
            handshake_rate_per_sec: 10.0,
            reloads: Reloads::new(started),
            started,
            now: started,
            process: None,
        };
        let text = render(&scrape);
        let (mut announced, mut typed) = (HashSet::new(), HashSet::new());
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("# HELP ") {
                let name = rest.split(' ').next().unwrap();
                assert!(announced.insert(name), "{name} announced twice");
            } else if let Some(rest) = line.strip_prefix("# TYPE ") {
                assert!(typed.insert(rest.split(' ').next().unwrap()), "{line}");
            } else {
                let name = line.split(['{', ' ']).next().unwrap();
                assert!(announced.contains(name) && typed.contains(name), "{line}");
                assert!(name.starts_with("wg_relay_") || name.starts_with("process_"), "{line}");
            }
        }
        for r in DropReason::ALL {
            let line = format!("wg_relay_datagrams_dropped_total{{reason=\"{r}\"}} 0");
            assert!(text.lines().any(|l| l == line), "{line} missing");
        }
        assert!(text.contains("\nwg_relay_worker_datagrams_total{worker=\"1\"} 0\n"));
        assert!(text.contains("\nprocess_start_time_seconds 1000\n"));
    }
}
