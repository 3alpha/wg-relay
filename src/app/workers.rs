//! The forwarding threads as a group: start them, notice one that ended,
//! read their counters, stop and join them.

use std::io;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use tokio::sync::watch;
use tracing::warn;
use wg_relay::config::Config;
use wg_relay::error::AppError;
use wg_relay::relay::{ControlSnapshot, Metrics, Relay};

use super::forwarding;
use crate::udp::Bound;

/// The relay's counters and state at one instant: the control plane's, copied
/// in one hold of its lock, and each forwarding thread's as of its last wake-up.
pub(super) struct Snapshot {
    pub(super) control: ControlSnapshot,
    /// Each thread's counters: what its data plane decided, and its socket errors.
    pub(super) workers: Vec<Metrics>,
    /// The control plane's and every thread's counters, merged.
    pub(super) total: Metrics,
}

/// The forwarding threads: thread `i` runs on socket `i` and keeps `counters[i]`.
pub(super) struct Workers {
    threads: Vec<JoinHandle<io::Result<()>>>,
    /// Each thread's counters as of its last batch.
    counters: Vec<Arc<Mutex<Metrics>>>,
    /// A handle on the relay the threads share, for the control plane's counters.
    relay: Relay,
    stop: watch::Sender<bool>,
}

impl Workers {
    /// Start one thread per socket; if one fails to start, stop the others.
    pub(super) fn start(sockets: Vec<Bound>, relay: &Relay) -> Result<Self, AppError> {
        let (stop, stopped) = watch::channel(false);
        let counters: Vec<Arc<Mutex<Metrics>>> = sockets.iter().map(|_| Arc::default()).collect();
        let mut workers = Workers {
            threads: Vec::with_capacity(sockets.len()),
            counters: counters.clone(),
            relay: relay.share(),
            stop,
        };
        for (index, (socket, counters)) in sockets.into_iter().zip(counters).enumerate() {
            let (relay, stopped) = (relay.share(), stopped.clone());
            let spawned = thread::Builder::new()
                .name(format!("worker-{index}"))
                .spawn(move || forwarding::run(socket, relay, stopped, &counters));
            match spawned {
                Ok(thread) => workers.threads.push(thread),
                Err(source) => {
                    // Failing to start is the error worth reporting.
                    let _ = workers.stop();
                    return Err(AppError::WorkerSpawn { index, source });
                }
            }
        }
        Ok(workers)
    }

    pub(super) fn len(&self) -> usize {
        self.threads.len()
    }

    /// The first thread that has ended, though none was told to.
    pub(super) fn exited(&self) -> Option<usize> {
        self.threads.iter().position(JoinHandle::is_finished)
    }

    /// Every thread's counters as of its last batch, and the control plane's, merged.
    pub(super) fn metrics(&self) -> Metrics {
        let mut all = self.relay.metrics();
        for c in self.local_metrics() {
            all += &c;
        }
        all
    }

    /// Each thread's counters as of its last batch.
    fn local_metrics(&self) -> Vec<Metrics> {
        self.counters
            .iter()
            .map(|c| c.lock().unwrap_or_else(PoisonError::into_inner).clone())
            .collect()
    }

    /// The control plane's state and every thread's counters, for the stats line and scrapes.
    pub(super) fn snapshot(&self, now: Instant) -> Snapshot {
        let control = self.relay.snapshot(now);
        let workers = self.local_metrics();
        let mut total = control.metrics.clone();
        for w in &workers {
            total += w;
        }
        Snapshot { control, workers, total }
    }

    /// Stop every thread and wait for each: the final counters, and the first
    /// failure, if any.
    pub(super) fn stop(mut self) -> (Metrics, Result<(), AppError>) {
        // Fails only once every thread has dropped its receiver, so has ended.
        let _ = self.stop.send(true);
        let threads = std::mem::take(&mut self.threads).into_iter().enumerate();
        let joined = threads.map(|(index, thread)| join(index, thread)).fold(Ok(()), Result::and);
        (self.metrics(), joined)
    }
}

/// Wait for thread `index` to end, and tell how it did.
fn join(index: usize, thread: JoinHandle<io::Result<()>>) -> Result<(), AppError> {
    match thread.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(source)) => Err(AppError::WorkerFailed { index, source }),
        Err(_) => Err(AppError::WorkerPanicked { index }),
    }
}

/// The configured thread count, or one where `SO_REUSEPORT` does not spread UDP flows.
pub(super) fn count(config: &Config) -> NonZeroUsize {
    if cfg!(target_os = "linux") || config.workers == NonZeroUsize::MIN {
        return config.workers;
    }
    warn!(workers = config.workers, "only Linux spreads one port's flows across sockets, using 1");
    NonZeroUsize::MIN
}
