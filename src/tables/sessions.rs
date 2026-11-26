use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::accounting::SessionAccounting;
use super::established::{EstablishedSessions, Route};
use super::session::{Expired, Session, SessionState, Timeouts};
use super::shrink_if_sparse;
use crate::key::PublicKey;
use crate::message::{IndexPrefix, SessionIndex};

/// Size limits of the session table.
#[derive(Debug, Clone, Copy)]
pub struct SessionLimits {
    /// Most entries one configured peer may have pending; beyond it, its oldest goes.
    pub pending_per_peer: usize,
    /// Most entries, pending or established, routed to one configured peer.
    pub per_peer: usize,
    /// Most entries in the whole table.
    pub total: usize,
}

/// Why the session table refused an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertError {
    /// A live entry of another address pair, or a live established entry, holds the index.
    IndexInUse,
    /// The entry's configured peer is at `SessionLimits::per_peer`.
    PeerQuota,
    /// The table is at `SessionLimits::total`.
    Full,
}

/// Every session, pending or established: the control plane's source of truth.
pub struct SessionTable {
    timeouts: Timeouts,
    total: usize,
    map: HashMap<SessionIndex, Session>,
    accounting: SessionAccounting,
}

impl SessionTable {
    pub fn new(pending: Duration, established: Duration, limits: SessionLimits) -> Self {
        SessionTable {
            timeouts: Timeouts { pending, established },
            total: limits.total,
            map: HashMap::new(),
            accounting: SessionAccounting::new(limits),
        }
    }

    /// An empty view of this table's established entries, for every call that changes them.
    pub fn new_view(&self) -> EstablishedSessions {
        EstablishedSessions::new(self.timeouts.established)
    }

    /// Store `s` at `index` if the index is free to take and there is room;
    /// returns the pending entry this evicted, if any.
    pub fn insert(
        &mut self,
        index: SessionIndex,
        s: Session,
        view: &EstablishedSessions,
    ) -> Result<Option<SessionIndex>, InsertError> {
        let old = self.replaceable(index, &s)?;
        self.check_room(&s, old.as_ref())?;
        self.store(index, s, old, view);
        Ok(self.evict_over_pending_quota(&s.peer))
    }

    /// The entry `s` would replace at `index`. A live entry owns its index against
    /// another address pair, so nobody can take it over, and an established one
    /// against its own pair too, so re-sending its initiation cannot reset or
    /// extend it.
    fn replaceable(
        &self,
        index: SessionIndex,
        s: &Session,
    ) -> Result<Option<Session>, InsertError> {
        let Some(old) = self.map.get(&index).copied() else { return Ok(None) };
        if !self.timeouts.live(&old, s.since) {
            return Ok(Some(old));
        }
        match old.state {
            SessionState::Pending if old.same_pair(s) => Ok(Some(old)),
            SessionState::Pending | SessionState::Established => Err(InsertError::IndexInUse),
        }
    }

    /// Refuse an entry that would grow its peer past its quota or the table past its cap.
    fn check_room(&self, s: &Session, old: Option<&Session>) -> Result<(), InsertError> {
        let peer_grows = old.is_none_or(|o| o.peer != s.peer);
        if peer_grows && self.accounting.at_quota(&s.peer) {
            return Err(InsertError::PeerQuota);
        }
        if old.is_none() && self.is_full() {
            return Err(InsertError::Full);
        }
        Ok(())
    }

    /// Put `s` at `index` in place of `old`: in the entries, the accounts and the view.
    fn store(
        &mut self,
        index: SessionIndex,
        s: Session,
        old: Option<Session>,
        view: &EstablishedSessions,
    ) {
        self.map.insert(index, s);
        if let Some(old) = old {
            self.accounting.removed(index, &old);
        }
        self.accounting.added(index, &s);
        match s.state {
            // It may replace a stale established entry, which forwarding must forget.
            SessionState::Pending => view.withdraw(index),
            SessionState::Established => view.publish(index, Route::from(&s)),
        }
    }

    /// Evict `peer`'s oldest pending entry if the new one put it over its
    /// pending quota; one insert adds one pending entry, so at most one goes.
    fn evict_over_pending_quota(&mut self, peer: &PublicKey) -> Option<SessionIndex> {
        let oldest = self.accounting.evictable(peer)?;
        let gone = self.map.remove(&oldest)?;
        self.accounting.removed(oldest, &gone);
        Some(oldest)
    }

    /// The session `index` names, unless its lifetime is over.
    pub fn get(&self, index: SessionIndex, now: Instant) -> Option<Session> {
        self.map.get(&index).filter(|s| self.timeouts.live(s, now)).copied()
    }

    /// Mark a pending index established once the response is accepted; its
    /// established lifetime starts now.
    pub fn establish(&mut self, index: SessionIndex, now: Instant, view: &EstablishedSessions) {
        let Some(s) = self.map.get_mut(&index) else { return };
        let was = s.state;
        s.since = now;
        s.state = SessionState::Established;
        view.publish(index, Route::from(&*s));
        let peer = s.peer;
        match was {
            SessionState::Pending => self.accounting.left_pending(index, &peer),
            SessionState::Established => {}
        }
    }

    /// A registered peer roamed to a new endpoint: rewrite its address in every
    /// session; returns how many were rewritten.
    pub fn roam(&mut self, old: SocketAddr, new: SocketAddr, view: &EstablishedSessions) -> usize {
        let mut rewritten = 0;
        for (index, s) in &mut self.map {
            let before = (s.dst, s.src);
            if s.dst == old {
                s.dst = new;
            }
            if s.src == old {
                s.src = new;
            }
            if (s.dst, s.src) == before {
                continue;
            }
            rewritten += 1;
            if s.state == SessionState::Established {
                view.publish(*index, Route::from(&*s));
            }
        }
        rewritten
    }

    /// Keep only the sessions `keep` accepts; returns how many were removed.
    pub fn retain(
        &mut self,
        mut keep: impl FnMut(&Session) -> bool,
        view: &EstablishedSessions,
    ) -> usize {
        let before = self.map.len();
        self.accounting.retain(&mut self.map, |index, s| {
            let kept = keep(s);
            if !kept && s.state == SessionState::Established {
                view.withdraw(index);
            }
            kept
        });
        shrink_if_sparse(&mut self.map);
        before - self.map.len()
    }

    /// Drop expired sessions; returns how many were removed in each state.
    pub fn expire(&mut self, now: Instant, view: &EstablishedSessions) -> Expired {
        let timeouts = self.timeouts;
        let mut gone = Expired::default();
        let keep = |s: &Session| {
            let live = timeouts.live(s, now);
            match (live, s.state) {
                (true, _) => {}
                (false, SessionState::Pending) => gone.pending += 1,
                (false, SessionState::Established) => gone.established += 1,
            }
            live
        };
        self.retain(keep, view);
        gone
    }

    /// Is any index with these upper 24 bits in use?
    pub fn has_prefix(&self, prefix: IndexPrefix) -> bool {
        self.map.keys().any(|i| i.prefix() == prefix)
    }

    /// How many sessions there are, pending or established.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// How many sessions await a response.
    pub fn pending_len(&self) -> usize {
        self.accounting.pending()
    }

    /// How many sessions, pending or established, are routed to `peer`.
    pub fn peer_len(&self, peer: &PublicKey) -> usize {
        self.accounting.count(peer)
    }

    /// How many of `peer`'s sessions await a response.
    pub fn peer_pending_len(&self, peer: &PublicKey) -> usize {
        self.accounting.pending_of(peer)
    }

    /// Would a new entry for `peer` exceed its quota?
    pub fn peer_at_quota(&self, peer: &PublicKey) -> bool {
        self.accounting.at_quota(peer)
    }

    /// Would a new index exceed the table's cap?
    pub fn is_full(&self) -> bool {
        self.map.len() >= self.total
    }

    /// Do the per-peer and pending accounts describe the entries exactly?
    #[cfg(test)]
    pub fn accounts_exact(&self) -> bool {
        self.accounting.matches(&self.map)
    }

    /// Does `view` hold exactly this table's established entries, expired or not,
    /// with the same lifetime?
    #[cfg(test)]
    pub fn matches_view(&self, view: &EstablishedSessions) -> bool {
        let established = self.map.iter().filter(|(_, s)| s.state == SessionState::Established);
        let routes: HashMap<_, _> = established.map(|(i, s)| (*i, Route::from(s))).collect();
        view.holds(self.timeouts.established, &routes)
    }

    /// Each established entry's index, expected source and destination.
    #[cfg(test)]
    pub fn established_pairs(
        &self,
    ) -> impl Iterator<Item = (SessionIndex, SocketAddr, SocketAddr)> {
        let established = self.map.iter().filter(|(_, s)| s.state == SessionState::Established);
        established.map(|(i, s)| (*i, s.src, s.dst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::{ESTABLISHED_TIMEOUT, PENDING_TIMEOUT};

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn key(n: u8) -> PublicKey {
        [n; 32].into()
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn index(i: u32) -> SessionIndex {
        i.into()
    }

    fn pending(dst: &str, src: &str, t: Instant) -> Session {
        Session::pending(addr(dst), addr(src), key(1), t)
    }

    fn established(dst: &str, src: &str, t: Instant) -> Session {
        Session::established(addr(dst), addr(src), key(1), t)
    }

    const UNLIMITED: SessionLimits =
        SessionLimits { pending_per_peer: usize::MAX, per_peer: usize::MAX, total: usize::MAX };

    fn table() -> Checked {
        Checked::new(SessionTable::new(PENDING_TIMEOUT, ESTABLISHED_TIMEOUT, UNLIMITED))
    }

    /// A table and its established view, checking after every change that they agree.
    struct Checked {
        table: SessionTable,
        view: EstablishedSessions,
    }

    impl Checked {
        fn new(table: SessionTable) -> Self {
            let view = table.new_view();
            Checked { table, view }
        }

        fn checked<T>(&self, out: T) -> T {
            assert!(self.table.matches_view(&self.view), "the view diverged from the table");
            assert!(counts_exact(&self.table), "the accounting diverged from the table");
            out
        }

        fn insert(
            &mut self,
            i: SessionIndex,
            s: Session,
        ) -> Result<Option<SessionIndex>, InsertError> {
            let out = self.table.insert(i, s, &self.view);
            self.checked(out)
        }

        fn establish(&mut self, i: SessionIndex, now: Instant) {
            self.table.establish(i, now, &self.view);
            self.checked(());
        }

        fn roam(&mut self, old: SocketAddr, new: SocketAddr) -> usize {
            let out = self.table.roam(old, new, &self.view);
            self.checked(out)
        }

        fn retain(&mut self, keep: impl FnMut(&Session) -> bool) -> usize {
            let out = self.table.retain(keep, &self.view);
            self.checked(out)
        }

        fn expire(&mut self, now: Instant) -> Expired {
            let out = self.table.expire(now, &self.view);
            self.checked(out)
        }
    }

    impl std::ops::Deref for Checked {
        type Target = SessionTable;

        fn deref(&self) -> &SessionTable {
            &self.table
        }
    }

    /// Do the per-peer and pending accounts match the entries exactly?
    fn counts_exact(t: &SessionTable) -> bool {
        t.accounts_exact()
    }

    /// The pending indexes of peer `n`, oldest first.
    fn queue(t: &SessionTable, n: u8) -> Vec<SessionIndex> {
        t.accounting.queue(&key(n))
    }

    #[test]
    fn established_session_expires_a_fixed_time_after_it_was_established() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(index(42), established("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.insert(index(43), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.establish(index(43), t0 + secs(5));
        assert!(t.get(index(42), t0 + secs(199)).is_some());
        assert_eq!(t.get(index(42), t0 + secs(200)), None);
        assert!(t.get(index(43), t0 + secs(204)).is_some(), "counted from establishment");
        assert_eq!(t.expire(t0 + secs(200)), Expired { pending: 0, established: 1 });
        assert_eq!(t.expire(t0 + secs(205)), Expired { pending: 0, established: 1 });
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn pending_session_expires_sooner_than_established() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(index(1), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.insert(index(2), established("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        assert!(t.get(index(1), t0 + secs(9)).is_some());
        assert_eq!(t.get(index(1), t0 + secs(10)), None);
        assert_eq!(t.expire(t0 + secs(10)), Expired { pending: 1, established: 0 }, "half-open");
        assert!(t.get(index(2), t0 + secs(10)).is_some());
    }

    #[test]
    fn establish_marks_session_established_and_starts_its_lifetime() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(index(42), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.establish(index(42), t0 + secs(1));
        assert_eq!(
            t.get(index(42), t0 + secs(1)),
            Some(established("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1)))
        );
    }

    #[test]
    fn insert_refuses_live_established_index_or_another_pairs_but_replaces_own_pending_or_stale() {
        let t0 = Instant::now();
        let mut t = table();
        assert_eq!(t.insert(index(6), pending("192.0.2.1:1", "192.0.2.2:2", t0)), Ok(None));
        let resent = pending("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1));
        assert_eq!(t.insert(index(6), resent), Ok(None), "re-sent initiation");
        assert_eq!(t.get(index(6), t0 + secs(10)), Some(resent));

        let live = established("192.0.2.1:1", "192.0.2.2:2", t0);
        assert_eq!(t.insert(index(7), live), Ok(None));
        // Neither the same pair nor another may reset or take over a live established entry.
        let same = [
            established("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1)),
            pending("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1)),
        ];
        for s in same {
            assert_eq!(t.insert(index(7), s), Err(InsertError::IndexInUse), "same pair");
        }
        let other = pending("192.0.2.3:3", "192.0.2.4:4", t0 + secs(2));
        assert_eq!(t.insert(index(7), other), Err(InsertError::IndexInUse));
        assert_eq!(t.get(index(7), t0 + secs(2)), Some(live));
        let expiry = t0 + ESTABLISHED_TIMEOUT;
        assert_eq!(t.get(index(7), expiry), None, "still expires on time");
        let late = pending("192.0.2.5:5", "192.0.2.6:6", expiry);
        assert_eq!(t.insert(index(7), late), Ok(None), "stale");
        assert_eq!(t.get(index(7), expiry).map(|s| s.dst), Some(addr("192.0.2.5:5")));
        assert_eq!(t.len(), 2);
        assert!(counts_exact(&t));
    }

    #[test]
    fn view_holds_established_entries_only_as_forwarding_needs_them() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(index(1), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        assert_eq!(t.view.get(index(1), t0), None, "pending");
        t.establish(index(1), t0 + secs(5));
        let route = Route {
            dst: addr("192.0.2.1:1"),
            src: addr("192.0.2.2:2"),
            established_at: t0 + secs(5),
        };
        assert_eq!(t.view.get(index(1), t0 + secs(204)), Some(route));
        assert_eq!(t.view.get(index(1), t0 + secs(205)), None, "counted from establishment");
        // A stale established entry replaced by a pending one leaves the view at once.
        t.insert(index(1), pending("192.0.2.3:3", "192.0.2.4:4", t0 + secs(205))).unwrap();
        assert_eq!(t.view.len(), 0);
        // Roaming rewrites established entries in the view; pending ones stay out of it.
        t.insert(index(2), established("192.0.2.1:1", "192.0.2.3:3", t0)).unwrap();
        t.roam(addr("192.0.2.3:3"), addr("192.0.2.9:9"));
        assert_eq!(t.view.get(index(2), t0).map(|r| r.src), Some(addr("192.0.2.9:9")));
        assert_eq!(t.view.len(), 1);
    }

    #[test]
    fn session_roam_rewrites_both_directions() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(index(0x00ab_cd01), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.insert(index(0x0011_2201), pending("192.0.2.2:2", "192.0.2.1:1", t0)).unwrap();
        assert_eq!(t.roam(addr("192.0.2.1:1"), addr("192.0.2.9:9")), 2);
        assert_eq!(t.roam(addr("192.0.2.1:1"), addr("192.0.2.9:9")), 0, "nothing left there");
        assert_eq!(t.get(index(0x00ab_cd01), t0).map(|s| s.dst), Some(addr("192.0.2.9:9")));
        assert_eq!(t.get(index(0x0011_2201), t0).map(|s| s.src), Some(addr("192.0.2.9:9")));
        assert_eq!(t.retain(|s| s.dst.port() == 9), 1);
    }

    #[test]
    fn has_prefix_matches_upper_24_bits_only() {
        let mut t = table();
        let t0 = Instant::now();
        t.insert(index(0x00ab_cd01), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        assert!(t.has_prefix(index(0x00ab_cdff).prefix()));
        assert!(!t.has_prefix(index(0x00ab_ce01).prefix()));
    }

    #[test]
    fn pending_over_quota_evicts_that_peers_oldest_only() {
        let t0 = Instant::now();
        let limits = SessionLimits { pending_per_peer: 2, ..UNLIMITED };
        let mut t = Checked::new(SessionTable::new(PENDING_TIMEOUT, ESTABLISHED_TIMEOUT, limits));
        let for_peer = |n: u8, port: u16| {
            Session::pending(addr(&format!("192.0.2.1:{port}")), addr("192.0.2.9:9"), key(n), t0)
        };
        assert_eq!(t.insert(index(1), for_peer(1, 1)), Ok(None));
        assert_eq!(t.insert(index(2), for_peer(1, 2)), Ok(None));
        assert_eq!(t.insert(index(10), for_peer(2, 10)), Ok(None));
        assert_eq!(t.insert(index(11), for_peer(2, 11)), Ok(None));
        assert_eq!(t.insert(index(3), for_peer(1, 3)), Ok(Some(index(1))));
        assert_eq!(t.get(index(1), t0), None, "peer 1's oldest went");
        assert_eq!(queue(&t, 1), vec![index(2), index(3)]);
        assert_eq!(queue(&t, 2), vec![index(10), index(11)]);
        assert_eq!((t.pending_len(), t.len()), (4, 4));

        // An established entry no longer counts, so the next one evicts nothing.
        t.establish(index(2), t0);
        assert_eq!(t.insert(index(4), for_peer(1, 4)), Ok(None));
        assert!(t.get(index(2), t0).is_some() && t.get(index(3), t0).is_some());
        assert_eq!((queue(&t, 1), t.pending_len()), (vec![index(3), index(4)], 4));

        // Re-sending a pending index moves it to the back instead of duplicating it.
        assert_eq!(t.insert(index(3), for_peer(1, 3)), Ok(None));
        assert_eq!(t.insert(index(5), for_peer(1, 5)), Ok(Some(index(4))));
        assert_eq!(t.get(index(4), t0), None);
        assert_eq!((queue(&t, 1), t.pending_len()), (vec![index(3), index(5)], 4));

        // Established, expired and removed entries leave the queues, and empty queues go.
        let est = Session::established(addr("192.0.2.1:5"), addr("192.0.2.9:9"), key(1), t0);
        assert_eq!(t.insert(index(5), est), Ok(None));
        assert!(counts_exact(&t));
        assert_eq!((queue(&t, 1), t.pending_len()), (vec![index(3)], 3));
        assert_eq!(t.retain(|s| s.peer != key(2)), 2);
        assert_eq!((queue(&t, 2), t.pending_len()), (vec![], 1));
        assert_eq!(t.expire(t0 + PENDING_TIMEOUT).total(), 1);
        assert_eq!((t.pending_len(), t.accounting.peers().0), (0, 0));
        assert_eq!(t.len(), 2, "the established entries");
        assert!(counts_exact(&t));
    }

    #[test]
    fn session_table_counts_pending_through_every_transition() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(index(1), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.insert(index(2), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.insert(index(3), established("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        assert_eq!(t.pending_len(), 2);
        t.insert(index(1), pending("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1))).unwrap();
        assert_eq!(t.pending_len(), 2, "replacing a pending entry");
        let other = pending("192.0.2.3:3", "192.0.2.4:4", t0);
        assert_eq!(t.insert(index(1), other), Err(InsertError::IndexInUse), "refused");
        assert_eq!(t.pending_len(), 2);
        t.establish(index(2), t0);
        t.establish(index(2), t0);
        assert_eq!(t.pending_len(), 1, "established once");
        assert_eq!(t.expire(t0 + secs(30)).total(), 1);
        assert_eq!(t.pending_len(), 0, "expired");
        t.insert(index(4), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        assert_eq!(t.retain(|s| s.state == SessionState::Established), 1);
        assert_eq!(t.pending_len(), 0, "removed by retain");
    }

    #[test]
    fn session_table_gives_memory_back_after_a_flood() {
        let t0 = Instant::now();
        let mut t = table();
        // Unchecked one by one: checking compares whole tables.
        for i in 0..100_000 {
            let s = pending("192.0.2.1:1", "192.0.2.2:2", t0);
            t.table.insert(index(i), s, &t.view).unwrap();
        }
        let peak = t.map.capacity();
        t.insert(index(1 << 31), established("192.0.2.1:1", "192.0.2.2:2", t0 + secs(5))).unwrap();
        assert_eq!(t.expire(t0 + secs(11)).total(), 100_000);
        assert!(t.map.capacity() < peak / 50, "{} of {peak}", t.map.capacity());
        assert_eq!((t.len(), t.pending_len()), (1, 0));
    }

    #[test]
    fn peer_quota_counts_pending_and_established_and_spares_other_peers() {
        let t0 = Instant::now();
        let limits = SessionLimits { pending_per_peer: 2, per_peer: 3, total: usize::MAX };
        let mut t = Checked::new(SessionTable::new(PENDING_TIMEOUT, ESTABLISHED_TIMEOUT, limits));
        let s = |n: u8, port: u16, state: SessionState| Session {
            state,
            ..Session::pending(addr(&format!("192.0.2.1:{port}")), addr("192.0.2.9:9"), key(n), t0)
        };
        let (p, e) = (SessionState::Pending, SessionState::Established);
        t.insert(index(1), s(1, 1, e)).unwrap();
        t.insert(index(2), s(1, 2, p)).unwrap();
        t.insert(index(3), s(1, 3, p)).unwrap();
        assert!(t.peer_at_quota(&key(1)) && !t.peer_at_quota(&key(2)));
        // At quota, a new index is refused, even one that would only evict.
        assert_eq!(t.insert(index(4), s(1, 4, p)), Err(InsertError::PeerQuota));
        assert_eq!(t.insert(index(4), s(1, 4, e)), Err(InsertError::PeerQuota));
        assert_eq!(t.get(index(2), t0).map(|s| s.state), Some(p), "nothing evicted");
        // Replacing one of its own entries does not grow it, and another peer is unaffected.
        assert_eq!(t.insert(index(3), s(1, 3, p)), Ok(None));
        assert_eq!(t.insert(index(10), s(2, 10, e)), Ok(None));
        // A stale entry of peer 1 taken over by peer 2 moves the count.
        assert_eq!(t.insert(index(1), s(2, 1, p)), Err(InsertError::IndexInUse), "live");
        let late = Session { since: t0 + ESTABLISHED_TIMEOUT, ..s(2, 1, p) };
        assert_eq!(t.insert(index(1), late), Ok(None), "stale");
        assert!(counts_exact(&t));
        assert!(!t.peer_at_quota(&key(1)) && t.accounting.count(&key(2)) == 2);
        // Expiry and retain free quota.
        assert_eq!(t.expire(t0 + PENDING_TIMEOUT).total(), 2);
        assert!(counts_exact(&t));
        assert_eq!(t.retain(|s| s.peer != key(2)), 2);
        assert!(counts_exact(&t) && t.accounting.peers().1 == 0 && t.len() == 0);
    }

    #[test]
    fn total_cap_refuses_new_indexes_but_not_replacements() {
        let t0 = Instant::now();
        let limits = SessionLimits { pending_per_peer: 1, per_peer: usize::MAX, total: 3 };
        let mut t = Checked::new(SessionTable::new(PENDING_TIMEOUT, ESTABLISHED_TIMEOUT, limits));
        let for_peer = |n: u8, port: u16| {
            Session::pending(addr(&format!("192.0.2.1:{port}")), addr("192.0.2.9:9"), key(n), t0)
        };
        for n in 1..=3 {
            t.insert(index(u32::from(n)), for_peer(n, 1)).unwrap();
        }
        assert!(t.is_full());
        assert_eq!(t.insert(index(4), for_peer(4, 4)), Err(InsertError::Full));
        assert_eq!(t.insert(index(1), for_peer(1, 1)), Ok(None), "replacement");
        // A peer at its pending quota still cannot add an index to a full table.
        assert_eq!(t.insert(index(5), for_peer(1, 5)), Err(InsertError::Full));
        assert_eq!(t.get(index(1), t0).map(|s| s.dst), Some(addr("192.0.2.1:1")));
        assert_eq!(t.expire(t0 + PENDING_TIMEOUT).total(), 3);
        assert_eq!(t.insert(index(4), for_peer(4, 4)), Ok(None), "room after expiry");
        assert!(counts_exact(&t));
    }

    #[test]
    fn pending_eviction_keeps_peer_counts_exact() {
        let t0 = Instant::now();
        let limits = SessionLimits { pending_per_peer: 2, per_peer: 4, total: usize::MAX };
        let mut t = Checked::new(SessionTable::new(PENDING_TIMEOUT, ESTABLISHED_TIMEOUT, limits));
        let mut evicted = 0;
        for i in 0..100 {
            let s = Session::pending(addr("192.0.2.1:1"), addr("192.0.2.9:9"), key(1), t0);
            evicted += usize::from(t.insert(index(i), s).unwrap().is_some());
        }
        assert_eq!((evicted, t.len(), t.accounting.count(&key(1))), (98, 2, 2));
        assert!(!t.peer_at_quota(&key(1)), "evictions free quota");
        assert!(counts_exact(&t));
    }
}
