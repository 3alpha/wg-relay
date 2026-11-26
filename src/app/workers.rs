//! The forwarding threads besides the main one: each runs the same socket
//! loop on its own socket and runtime until told to stop.

use std::io;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};

use tokio::sync::watch;
use tracing::warn;
use wg_relay::config::Config;
use wg_relay::error::AppError;
use wg_relay::relay::{Metrics, Relay};

use super::forwarding::SocketLoop;
use crate::udp::Bound;

/// A thread's counters as of its last batch, for the stats line.
type SharedCounters = Arc<Mutex<Metrics>>;

/// One started forwarding thread.
struct Worker {
    thread: JoinHandle<io::Result<Metrics>>,
    counters: SharedCounters,
}

/// The forwarding threads besides the main one. Socket `i` of `sockets` runs
/// as thread `i + 1`; the main thread is thread 0.
pub(super) struct Workers {
    workers: Vec<Worker>,
    stop: watch::Sender<bool>,
}

impl Workers {
    /// Start one thread per socket; if one fails to start, stop the others.
    pub(super) fn start(sockets: Vec<Bound>, relay: &Relay) -> Result<Self, AppError> {
        let (stop, stopped) = watch::channel(false);
        let mut started = Workers { workers: Vec::with_capacity(sockets.len()), stop };
        for (i, socket) in sockets.into_iter().enumerate() {
            let counters = SharedCounters::default();
            let (relay, stopped, shared) = (relay.share(), stopped.clone(), Arc::clone(&counters));
            let spawned = thread::Builder::new()
                .name(format!("forward-{}", i + 1))
                .spawn(move || run(socket, relay, stopped, &shared));
            match spawned {
                Ok(thread) => started.workers.push(Worker { thread, counters }),
                Err(source) => {
                    // Failing to start is the error worth reporting.
                    let _ = started.stop();
                    return Err(AppError::WorkerSpawn { index: i + 1, source });
                }
            }
        }
        Ok(started)
    }

    pub(super) fn len(&self) -> usize {
        self.workers.len()
    }

    /// The first thread that has ended, though none was told to.
    pub(super) fn exited(&self) -> Option<usize> {
        self.workers.iter().position(|w| w.thread.is_finished()).map(|i| i + 1)
    }

    /// Every thread's counters as of its last batch, merged.
    pub(super) fn counters(&self) -> Metrics {
        let mut all = Metrics::default();
        for w in &self.workers {
            all += &*w.counters.lock().unwrap_or_else(PoisonError::into_inner);
        }
        all
    }

    /// Stop every thread and wait for each: their final counters, merged, and
    /// the first failure, if any.
    pub(super) fn stop(self) -> (Metrics, Result<(), AppError>) {
        // Fails only once every thread has dropped its receiver, so has ended.
        let _ = self.stop.send(true);
        let (mut all, mut outcome) = (Metrics::default(), Ok(()));
        for (i, w) in self.workers.into_iter().enumerate() {
            let index = i + 1;
            let failure = match w.thread.join() {
                Ok(Ok(counters)) => {
                    all += &counters;
                    continue;
                }
                Ok(Err(source)) => AppError::WorkerFailed { index, source },
                Err(_) => AppError::WorkerPanicked { index },
            };
            outcome = outcome.and(Err(failure));
        }
        (all, outcome)
    }
}

/// Run one thread's socket loop on a runtime of its own until `stop` changes.
fn run(
    socket: Bound,
    relay: Relay,
    mut stop: watch::Receiver<bool>,
    counters: &Mutex<Metrics>,
) -> io::Result<Metrics> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_io().build()?;
    rt.block_on(async {
        let mut lp = SocketLoop::new(socket.register()?, relay);
        loop {
            tokio::select! {
                biased;
                _ = stop.changed() => break,
                r = lp.sock.readable() => lp.on_readable(r).await,
            }
            counters.lock().unwrap_or_else(PoisonError::into_inner).clone_from(lp.relay.counters());
        }
        Ok(lp.relay.counters().clone())
    })
}

/// The configured thread count, or one where `SO_REUSEPORT` does not spread UDP flows.
pub(super) fn count(cfg: &Config) -> NonZeroUsize {
    if cfg!(target_os = "linux") || cfg.workers == NonZeroUsize::MIN {
        return cfg.workers;
    }
    warn!(workers = cfg.workers, "only Linux spreads one port's flows across sockets, using 1");
    NonZeroUsize::MIN
}
