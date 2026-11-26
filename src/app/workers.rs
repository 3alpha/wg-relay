//! The forwarding threads as a group: start them, notice one that ended,
//! read their counters, stop and join them.

use std::io;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};

use tokio::sync::watch;
use tracing::warn;
use wg_relay::config::Config;
use wg_relay::error::AppError;
use wg_relay::relay::{Metrics, Relay};

use super::forwarding;
use crate::udp::Bound;

/// The forwarding threads: thread `i` runs on socket `i` and keeps `counters[i]`.
pub(super) struct Workers {
    threads: Vec<JoinHandle<io::Result<()>>>,
    /// Each thread's counters as of its last batch.
    counters: Vec<Arc<Mutex<Metrics>>>,
    /// A handle on the relay the threads share, for the control half's counters.
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
                .name(format!("forward-{index}"))
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

    /// Every thread's counters as of its last batch, and the control half's, merged.
    pub(super) fn metrics(&self) -> Metrics {
        let mut all = self.relay.metrics();
        for c in &self.counters {
            all += &*c.lock().unwrap_or_else(PoisonError::into_inner);
        }
        all
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
pub(super) fn count(cfg: &Config) -> NonZeroUsize {
    if cfg!(target_os = "linux") || cfg.workers == NonZeroUsize::MIN {
        return cfg.workers;
    }
    warn!(workers = cfg.workers, "only Linux spreads one port's flows across sockets, using 1");
    NonZeroUsize::MIN
}
