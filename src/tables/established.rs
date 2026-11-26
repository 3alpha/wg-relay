use std::net::SocketAddr;
use std::time::{Duration, Instant};

use papaya::HashMap;

use super::live;
use super::session::Session;
use crate::message::SessionIndex;

/// What forwarding needs of an established session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// Where messages carrying this index are sent.
    pub dst: SocketAddr,
    /// The only address allowed to send messages carrying this index.
    pub src: SocketAddr,
    /// When the session was established; its lifetime runs from here.
    pub established_at: Instant,
}

impl From<&Session> for Route {
    fn from(s: &Session) -> Self {
        Route { dst: s.dst, src: s.src, established_at: s.since }
    }
}

/// The established entries of a `SessionTable`, as the data plane reads
/// them. Only the table writes it, in the same calls that change its
/// established entries, so the two cannot disagree. Every thread reads it
/// without a lock; the map shrinks itself once mostly empty.
pub struct EstablishedSessions {
    timeout: Duration,
    map: HashMap<SessionIndex, Route>,
}

impl EstablishedSessions {
    pub(super) fn new(timeout: Duration) -> Self {
        EstablishedSessions { timeout, map: HashMap::new() }
    }

    /// The established session `index` names, unless its lifetime is over.
    pub fn get(&self, index: SessionIndex, now: Instant) -> Option<Route> {
        self.map.pin().get(&index).filter(|r| live(r.established_at, now, self.timeout)).copied()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Make `route` the established session at `index`.
    pub(super) fn publish(&self, index: SessionIndex, route: Route) {
        self.map.pin().insert(index, route);
    }

    /// Remove the established session at `index`, if there is one.
    pub(super) fn withdraw(&self, index: SessionIndex) {
        self.map.pin().remove(&index);
    }

    /// Does this view hold exactly these routes, with this lifetime?
    #[cfg(test)]
    pub(super) fn holds(
        &self,
        timeout: Duration,
        routes: &std::collections::HashMap<SessionIndex, Route>,
    ) -> bool {
        let map = self.map.pin();
        let mine: std::collections::HashMap<SessionIndex, Route> =
            map.iter().map(|(i, r)| (*i, *r)).collect();
        self.timeout == timeout && mine == *routes
    }
}
