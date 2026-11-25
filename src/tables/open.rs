use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::entry::Session;
use super::{live, shrink_if_sparse};
use crate::packet::SessionIdx;

/// What forwarding needs of an open session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// Where packets carrying this index are sent.
    pub dest: SocketAddr,
    /// The only address allowed to send packets carrying this index.
    pub expected_src: SocketAddr,
    /// When the session opened; its lifetime runs from here.
    pub opened: Instant,
}

impl From<&Session> for Route {
    fn from(s: &Session) -> Self {
        Route { dest: s.dest, expected_src: s.expected_src, opened: s.since }
    }
}

/// The open entries of a `SessionTable`, as the forwarding half reads them.
/// Only the table writes it, in the same calls that change its open entries,
/// so the two cannot disagree.
pub struct OpenSessions {
    ttl: Duration,
    map: HashMap<SessionIdx, Route>,
}

impl OpenSessions {
    pub(super) fn new(ttl: Duration) -> Self {
        OpenSessions { ttl, map: HashMap::new() }
    }

    /// The open session `idx` names, unless its lifetime is over.
    pub fn get(&self, idx: SessionIdx, now: Instant) -> Option<&Route> {
        self.map.get(&idx).filter(|r| live(r.opened, now, self.ttl))
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub(super) fn publish(&mut self, idx: SessionIdx, route: Route) {
        self.map.insert(idx, route);
    }

    pub(super) fn withdraw(&mut self, idx: SessionIdx) {
        self.map.remove(&idx);
    }

    pub(super) fn shrink(&mut self) {
        shrink_if_sparse(&mut self.map);
    }

    /// Does this view hold exactly these routes, with this lifetime?
    #[cfg(test)]
    pub(super) fn holds(&self, ttl: Duration, routes: &HashMap<SessionIdx, Route>) -> bool {
        self.ttl == ttl && self.map == *routes
    }
}
