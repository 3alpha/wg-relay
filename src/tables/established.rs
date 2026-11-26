use std::net::SocketAddr;
use std::time::{Duration, Instant};

use papaya::HashMap;

use super::entry::Session;
use super::live;
use crate::packet::SessionIdx;

/// What forwarding needs of an established session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// Where messages carrying this index are sent.
    pub dest: SocketAddr,
    /// The only address allowed to send messages carrying this index.
    pub expected_src: SocketAddr,
    /// When the session was established; its lifetime runs from here.
    pub established_at: Instant,
}

impl From<&Session> for Route {
    fn from(s: &Session) -> Self {
        Route { dest: s.dest, expected_src: s.expected_src, established_at: s.since }
    }
}

/// The established entries of a `SessionTable`, as the forwarding half reads
/// them. Only the table writes it, in the same calls that change its
/// established entries, so the two cannot disagree. Every thread reads it
/// without a lock; the map shrinks itself once mostly empty.
pub struct EstablishedSessions {
    ttl: Duration,
    map: HashMap<SessionIdx, Route>,
}

impl EstablishedSessions {
    pub(super) fn new(ttl: Duration) -> Self {
        EstablishedSessions { ttl, map: HashMap::new() }
    }

    /// The established session `idx` names, unless its lifetime is over.
    pub fn get(&self, idx: SessionIdx, now: Instant) -> Option<Route> {
        self.map.pin().get(&idx).filter(|r| live(r.established_at, now, self.ttl)).copied()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Make `route` the established session at `idx`.
    pub(super) fn publish(&self, idx: SessionIdx, route: Route) {
        self.map.pin().insert(idx, route);
    }

    /// Remove the established session at `idx`, if there is one.
    pub(super) fn withdraw(&self, idx: SessionIdx) {
        self.map.pin().remove(&idx);
    }

    /// Does this view hold exactly these routes, with this lifetime?
    #[cfg(test)]
    pub(super) fn holds(
        &self,
        ttl: Duration,
        routes: &std::collections::HashMap<SessionIdx, Route>,
    ) -> bool {
        let map = self.map.pin();
        let mine: std::collections::HashMap<SessionIdx, Route> =
            map.iter().map(|(i, r)| (*i, *r)).collect();
        self.ttl == ttl && mine == *routes
    }
}
