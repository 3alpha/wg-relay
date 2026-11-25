use std::collections::{HashMap, VecDeque};

use super::entry::{Session, SessionState};
use super::sessions::SessionLimits;
use super::shrink_if_sparse;
use crate::key::PeerKey;
use crate::packet::SessionIdx;

/// The per-peer and pending accounts of a session table, kept exact so its
/// quotas never need a scan.
pub(super) struct Ledger {
    limits: SessionLimits,
    /// Entries in the pending state, live or not yet swept.
    pending: usize,
    /// Each listed peer's pending indexes, oldest first, so a flood aimed at one
    /// peer evicts its own entries instead of crowding out other peers.
    pending_by_peer: HashMap<PeerKey, VecDeque<SessionIdx>>,
    /// Entries of any state, live or not yet swept, per listed peer.
    count_by_peer: HashMap<PeerKey, usize>,
}

impl Ledger {
    pub(super) fn new(limits: SessionLimits) -> Self {
        Ledger {
            limits,
            pending: 0,
            pending_by_peer: HashMap::new(),
            count_by_peer: HashMap::new(),
        }
    }

    pub(super) fn pending(&self) -> usize {
        self.pending
    }

    /// Would another entry for `peer` exceed its quota?
    pub(super) fn at_quota(&self, peer: &PeerKey) -> bool {
        self.count_by_peer.get(peer).is_some_and(|n| *n >= self.limits.per_peer)
    }

    /// Count an entry just stored at `idx`.
    pub(super) fn added(&mut self, idx: SessionIdx, s: &Session) {
        *self.count_by_peer.entry(s.peer).or_default() += 1;
        match s.state {
            SessionState::Pending => {
                self.pending += 1;
                self.pending_by_peer.entry(s.peer).or_default().push_back(idx);
            }
            SessionState::Open => {}
        }
    }

    /// Account for the entry at `idx`, routed to `peer`, no longer being pending.
    pub(super) fn left_pending(&mut self, idx: SessionIdx, peer: &PeerKey) {
        self.pending -= 1;
        let Some(queue) = self.pending_by_peer.get_mut(peer) else { return };
        if let Some(i) = queue.iter().position(|q| *q == idx) {
            queue.remove(i);
        }
        if queue.is_empty() {
            self.pending_by_peer.remove(peer);
        }
    }

    /// Uncount the entry at `idx`, just replaced or evicted.
    pub(super) fn removed(&mut self, idx: SessionIdx, s: &Session) {
        match s.state {
            SessionState::Pending => self.left_pending(idx, &s.peer),
            SessionState::Open => {}
        }
        self.uncount(&s.peer);
    }

    /// The pending entry `peer` must give up, its oldest, if it is over its pending quota.
    pub(super) fn evictable(&self, peer: &PeerKey) -> Option<SessionIdx> {
        let queue = self.pending_by_peer.get(peer)?;
        queue.front().copied().filter(|_| queue.len() > self.limits.pending_per_peer)
    }

    /// Remove every entry of `map` that `keep` rejects, with the accounts.
    /// Queues are pruned in one pass afterwards, not searched once per entry.
    pub(super) fn retain(
        &mut self,
        map: &mut HashMap<SessionIdx, Session>,
        mut keep: impl FnMut(SessionIdx, &Session) -> bool,
    ) {
        let pending_before = self.pending;
        map.retain(|idx, s| {
            let kept = keep(*idx, s);
            if !kept {
                self.forget(s);
            }
            kept
        });
        if self.pending < pending_before {
            self.pending_by_peer.retain(|peer, queue| {
                queue.retain(|i| {
                    map.get(i).is_some_and(|s| s.state == SessionState::Pending && s.peer == *peer)
                });
                !queue.is_empty()
            });
            shrink_if_sparse(&mut self.pending_by_peer);
        }
        shrink_if_sparse(&mut self.count_by_peer);
    }

    /// Uncount an entry `retain` removes, leaving its queue to the pass after.
    fn forget(&mut self, s: &Session) {
        match s.state {
            SessionState::Pending => self.pending -= 1,
            SessionState::Open => {}
        }
        self.uncount(&s.peer);
    }

    fn uncount(&mut self, peer: &PeerKey) {
        let Some(n) = self.count_by_peer.get_mut(peer) else { return };
        *n -= 1;
        if *n == 0 {
            self.count_by_peer.remove(peer);
        }
    }
}

#[cfg(test)]
use std::collections::HashSet;

#[cfg(test)]
impl Ledger {
    /// Do the accounts describe `map` exactly, with no duplicate, empty queue or zero count?
    pub(super) fn matches(&self, map: &HashMap<SessionIdx, Session>) -> bool {
        let mut counts: HashMap<PeerKey, usize> = HashMap::new();
        let mut pending: HashMap<PeerKey, HashSet<SessionIdx>> = HashMap::new();
        for (idx, s) in map {
            *counts.entry(s.peer).or_default() += 1;
            if s.state == SessionState::Pending {
                pending.entry(s.peer).or_default().insert(*idx);
            }
        }
        let queued: HashMap<PeerKey, HashSet<SessionIdx>> = self
            .pending_by_peer
            .iter()
            .map(|(peer, queue)| (*peer, queue.iter().copied().collect()))
            .collect();
        let queued_once = self.pending_by_peer.iter().all(|(p, q)| queued[p].len() == q.len());
        let total: usize = pending.values().map(HashSet::len).sum();
        counts == self.count_by_peer && queued == pending && queued_once && total == self.pending
    }

    /// The pending indexes of `peer`, oldest first.
    pub(super) fn queue(&self, peer: &PeerKey) -> Vec<SessionIdx> {
        self.pending_by_peer.get(peer).map(|q| q.iter().copied().collect()).unwrap_or_default()
    }

    pub(super) fn count(&self, peer: &PeerKey) -> usize {
        self.count_by_peer.get(peer).copied().unwrap_or_default()
    }

    /// How many peers have a pending queue and an entry count.
    pub(super) fn peers(&self) -> (usize, usize) {
        (self.pending_by_peer.len(), self.count_by_peer.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Instant;

    fn entry(peer: u8, state: SessionState) -> Session {
        let a = SocketAddr::from(([192, 0, 2, 1], 1));
        Session { state, ..Session::pending(a, a, [peer; 32].into(), Instant::now()) }
    }

    #[test]
    fn ledger_tracks_counts_queues_and_the_entry_to_evict() {
        let limits = SessionLimits { pending_per_peer: 2, per_peer: 3, total: usize::MAX };
        let mut l = Ledger::new(limits);
        let (p, o) = (SessionState::Pending, SessionState::Open);
        let peer = PeerKey::from([1; 32]);
        for i in 1..=3u32 {
            l.added(i.into(), &entry(1, p));
        }
        assert_eq!((l.pending(), l.count(&peer), l.at_quota(&peer)), (3, 3, true));
        assert_eq!(l.evictable(&peer), Some(1.into()), "over its pending quota: oldest first");
        l.removed(1.into(), &entry(1, p));
        assert_eq!(l.evictable(&peer), None);
        l.left_pending(2.into(), &peer);
        assert_eq!((l.queue(&peer), l.pending(), l.count(&peer)), (vec![3.into()], 1, 2));
        l.added(4.into(), &entry(1, o));
        l.removed(4.into(), &entry(1, o));
        l.removed(3.into(), &entry(1, p));
        l.removed(2.into(), &entry(1, o));
        assert_eq!((l.pending(), l.peers()), (0, (0, 0)), "nothing left behind");
    }
}
