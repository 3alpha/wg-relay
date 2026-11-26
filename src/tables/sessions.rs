use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::entry::{Session, SessionState, Ttls};
use super::ledger::Ledger;
use super::open::{OpenSessions, Route};
use super::shrink_if_sparse;
use crate::key::PeerKey;
use crate::packet::{IdxPrefix, SessionIdx};

/// Size limits of the session table.
#[derive(Debug, Clone, Copy)]
pub struct SessionLimits {
    /// Most entries one listed peer may have pending; beyond it, its oldest goes.
    pub pending_per_peer: usize,
    /// Most entries, pending or open, routed to one listed peer.
    pub per_peer: usize,
    /// Most entries in the whole table.
    pub total: usize,
}

/// Why the session table refused an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A live entry of another address pair, or a live open entry, holds the index.
    IndexInUse,
    /// The entry's listed peer is at `SessionLimits::per_peer`.
    PeerQuota,
    /// The table is at `SessionLimits::total`.
    Full,
}

/// Every session, pending or open: the control half's source of truth.
pub struct SessionTable {
    ttls: Ttls,
    total: usize,
    map: HashMap<SessionIdx, Session>,
    ledger: Ledger,
}

impl SessionTable {
    pub fn new(open_ttl: Duration, pending_ttl: Duration, limits: SessionLimits) -> Self {
        SessionTable {
            ttls: Ttls { open: open_ttl, pending: pending_ttl },
            total: limits.total,
            map: HashMap::new(),
            ledger: Ledger::new(limits),
        }
    }

    /// An empty view of this table's open entries, to pass to every call that changes them.
    pub fn new_view(&self) -> OpenSessions {
        OpenSessions::new(self.ttls.open)
    }

    /// Store `s` at `idx` if the index is free to take and there is room;
    /// returns the pending entry this evicted, if any.
    pub fn insert(
        &mut self,
        idx: SessionIdx,
        s: Session,
        view: &OpenSessions,
    ) -> Result<Option<SessionIdx>, Refusal> {
        let old = self.replaceable(idx, &s)?;
        self.check_room(&s, old.as_ref())?;
        self.store(idx, s, old, view);
        Ok(self.evict_over_pending_quota(&s.peer))
    }

    /// The entry `s` would replace at `idx`. A live entry owns its index against
    /// another address pair, so nobody can take it over, and an open one against
    /// its own pair too, so re-sending its initiation cannot reset or extend it.
    fn replaceable(&self, idx: SessionIdx, s: &Session) -> Result<Option<Session>, Refusal> {
        let Some(old) = self.map.get(&idx).copied() else { return Ok(None) };
        if !self.ttls.live(&old, s.since) {
            return Ok(Some(old));
        }
        match old.state {
            SessionState::Pending if old.same_pair(s) => Ok(Some(old)),
            SessionState::Pending | SessionState::Open => Err(Refusal::IndexInUse),
        }
    }

    /// Refuse an entry that would grow its peer past its quota or the table past its cap.
    fn check_room(&self, s: &Session, old: Option<&Session>) -> Result<(), Refusal> {
        let peer_grows = old.is_none_or(|o| o.peer != s.peer);
        if peer_grows && self.ledger.at_quota(&s.peer) {
            return Err(Refusal::PeerQuota);
        }
        if old.is_none() && self.is_full() {
            return Err(Refusal::Full);
        }
        Ok(())
    }

    /// Put `s` at `idx` in place of `old`: in the entries, the accounts and the view.
    fn store(&mut self, idx: SessionIdx, s: Session, old: Option<Session>, view: &OpenSessions) {
        self.map.insert(idx, s);
        if let Some(old) = old {
            self.ledger.removed(idx, &old);
        }
        self.ledger.added(idx, &s);
        match s.state {
            SessionState::Open => view.publish(idx, Route::from(&s)),
            // It may replace a stale open entry, which forwarding must forget.
            SessionState::Pending => view.withdraw(idx),
        }
    }

    /// Evict `peer`'s oldest pending entry if the new one put it over its
    /// pending quota; one insert adds one pending entry, so at most one goes.
    fn evict_over_pending_quota(&mut self, peer: &PeerKey) -> Option<SessionIdx> {
        let oldest = self.ledger.evictable(peer)?;
        let gone = self.map.remove(&oldest)?;
        self.ledger.removed(oldest, &gone);
        Some(oldest)
    }

    pub fn get(&self, idx: SessionIdx, now: Instant) -> Option<Session> {
        self.map.get(&idx).filter(|s| self.ttls.live(s, now)).copied()
    }

    /// Mark a pending index open once the response is accepted; its open
    /// lifetime starts now.
    pub fn open(&mut self, idx: SessionIdx, now: Instant, view: &OpenSessions) {
        let Some(s) = self.map.get_mut(&idx) else { return };
        let was = s.state;
        s.since = now;
        s.state = SessionState::Open;
        view.publish(idx, Route::from(&*s));
        let peer = s.peer;
        match was {
            SessionState::Pending => self.ledger.left_pending(idx, &peer),
            SessionState::Open => {}
        }
    }

    /// A registered peer moved: rewrite its address in every session.
    pub fn migrate(&mut self, old: SocketAddr, new: SocketAddr, view: &OpenSessions) {
        for (idx, s) in &mut self.map {
            let before = (s.dest, s.expected_src);
            if s.dest == old {
                s.dest = new;
            }
            if s.expected_src == old {
                s.expected_src = new;
            }
            if s.state == SessionState::Open && (s.dest, s.expected_src) != before {
                view.publish(*idx, Route::from(&*s));
            }
        }
    }

    /// Keep only matching sessions; returns how many were removed.
    pub fn retain(&mut self, mut keep: impl FnMut(&Session) -> bool, view: &OpenSessions) -> usize {
        let before = self.map.len();
        self.ledger.retain(&mut self.map, |idx, s| {
            let kept = keep(s);
            if !kept && s.state == SessionState::Open {
                view.withdraw(idx);
            }
            kept
        });
        shrink_if_sparse(&mut self.map);
        before - self.map.len()
    }

    pub fn expire(&mut self, now: Instant, view: &OpenSessions) -> usize {
        let ttls = self.ttls;
        self.retain(|s| ttls.live(s, now), view)
    }

    /// Is any index with these upper 24 bits in use?
    pub fn has_prefix(&self, prefix: IdxPrefix) -> bool {
        self.map.keys().any(|i| i.prefix() == prefix)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// How many sessions await a response.
    pub fn pending(&self) -> usize {
        self.ledger.pending()
    }

    /// Would a new entry for `peer` exceed its quota?
    pub fn peer_at_quota(&self, peer: &PeerKey) -> bool {
        self.ledger.at_quota(peer)
    }

    /// Would a new index exceed the table's cap?
    pub fn is_full(&self) -> bool {
        self.map.len() >= self.total
    }

    /// Do the per-peer and pending accounts describe the entries exactly?
    #[cfg(test)]
    pub fn accounts_exact(&self) -> bool {
        self.ledger.matches(&self.map)
    }

    /// Does `view` hold exactly this table's open entries, swept or not, with
    /// the same lifetime?
    #[cfg(test)]
    pub fn matches_view(&self, view: &OpenSessions) -> bool {
        let open = self.map.iter().filter(|(_, s)| s.state == SessionState::Open);
        let routes: HashMap<SessionIdx, Route> = open.map(|(i, s)| (*i, Route::from(s))).collect();
        view.holds(self.ttls.open, &routes)
    }

    /// Each open entry's index, expected source and destination.
    #[cfg(test)]
    pub fn open_pairs(&self) -> impl Iterator<Item = (SessionIdx, SocketAddr, SocketAddr)> {
        let open = self.map.iter().filter(|(_, s)| s.state == SessionState::Open);
        open.map(|(i, s)| (*i, s.expected_src, s.dest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::{PENDING_TTL, SESSION_TTL};

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn key(n: u8) -> PeerKey {
        [n; 32].into()
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn idx(i: u32) -> SessionIdx {
        i.into()
    }

    fn pending(dest: &str, src: &str, t: Instant) -> Session {
        Session::pending(addr(dest), addr(src), key(1), t)
    }

    fn open(dest: &str, src: &str, t: Instant) -> Session {
        Session::open(addr(dest), addr(src), key(1), t)
    }

    const UNLIMITED: SessionLimits =
        SessionLimits { pending_per_peer: usize::MAX, per_peer: usize::MAX, total: usize::MAX };

    fn table() -> Checked {
        Checked::new(SessionTable::new(SESSION_TTL, PENDING_TTL, UNLIMITED))
    }

    /// A table and its open view, checking after every change that they agree.
    struct Checked {
        table: SessionTable,
        view: OpenSessions,
    }

    impl Checked {
        fn new(table: SessionTable) -> Self {
            let view = table.new_view();
            Checked { table, view }
        }

        fn checked<T>(&self, out: T) -> T {
            assert!(self.table.matches_view(&self.view), "the view diverged from the table");
            assert!(counts_exact(&self.table), "the ledger diverged from the table");
            out
        }

        fn insert(&mut self, i: SessionIdx, s: Session) -> Result<Option<SessionIdx>, Refusal> {
            let out = self.table.insert(i, s, &self.view);
            self.checked(out)
        }

        fn open(&mut self, i: SessionIdx, now: Instant) {
            self.table.open(i, now, &self.view);
            self.checked(());
        }

        fn migrate(&mut self, old: SocketAddr, new: SocketAddr) {
            self.table.migrate(old, new, &self.view);
            self.checked(());
        }

        fn retain(&mut self, keep: impl FnMut(&Session) -> bool) -> usize {
            let out = self.table.retain(keep, &self.view);
            self.checked(out)
        }

        fn expire(&mut self, now: Instant) -> usize {
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
    fn queue(t: &SessionTable, n: u8) -> Vec<SessionIdx> {
        t.ledger.queue(&key(n))
    }

    #[test]
    fn open_session_expires_a_fixed_time_after_it_opened() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(idx(42), open("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.insert(idx(43), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.open(idx(43), t0 + secs(5));
        assert!(t.get(idx(42), t0 + secs(199)).is_some());
        assert_eq!(t.get(idx(42), t0 + secs(200)), None);
        assert!(t.get(idx(43), t0 + secs(204)).is_some(), "counted from opening");
        assert_eq!(t.expire(t0 + secs(200)), 1);
        assert_eq!(t.expire(t0 + secs(205)), 1);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn pending_session_expires_sooner_than_open() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(idx(1), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.insert(idx(2), open("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        assert!(t.get(idx(1), t0 + secs(9)).is_some());
        assert_eq!(t.get(idx(1), t0 + secs(10)), None);
        assert_eq!(t.expire(t0 + secs(10)), 1);
        assert!(t.get(idx(2), t0 + secs(10)).is_some());
    }

    #[test]
    fn open_marks_session_open_and_starts_its_lifetime() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(idx(42), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.open(idx(42), t0 + secs(1));
        assert_eq!(
            t.get(idx(42), t0 + secs(1)),
            Some(open("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1)))
        );
    }

    #[test]
    fn insert_refuses_live_open_index_or_another_pairs_but_replaces_own_pending_or_stale() {
        let t0 = Instant::now();
        let mut t = table();
        assert_eq!(t.insert(idx(6), pending("192.0.2.1:1", "192.0.2.2:2", t0)), Ok(None));
        let resent = pending("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1));
        assert_eq!(t.insert(idx(6), resent), Ok(None), "re-sent initiation");
        assert_eq!(t.get(idx(6), t0 + secs(10)), Some(resent));

        assert_eq!(t.insert(idx(7), open("192.0.2.1:1", "192.0.2.2:2", t0)), Ok(None));
        // Neither the same pair nor another may reset or take over a live open entry.
        let same = [
            open("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1)),
            pending("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1)),
        ];
        for s in same {
            assert_eq!(t.insert(idx(7), s), Err(Refusal::IndexInUse), "same pair");
        }
        let other = pending("192.0.2.3:3", "192.0.2.4:4", t0 + secs(2));
        assert_eq!(t.insert(idx(7), other), Err(Refusal::IndexInUse));
        assert_eq!(t.get(idx(7), t0 + secs(2)), Some(open("192.0.2.1:1", "192.0.2.2:2", t0)));
        assert_eq!(t.get(idx(7), t0 + SESSION_TTL), None, "still expires on time");
        let late = pending("192.0.2.5:5", "192.0.2.6:6", t0 + SESSION_TTL);
        assert_eq!(t.insert(idx(7), late), Ok(None), "stale");
        assert_eq!(t.get(idx(7), t0 + SESSION_TTL).map(|s| s.dest), Some(addr("192.0.2.5:5")));
        assert_eq!(t.len(), 2);
        assert!(counts_exact(&t));
    }

    #[test]
    fn view_holds_open_entries_only_as_forwarding_needs_them() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(idx(1), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        assert_eq!(t.view.get(idx(1), t0), None, "pending");
        t.open(idx(1), t0 + secs(5));
        let route = Route {
            dest: addr("192.0.2.1:1"),
            expected_src: addr("192.0.2.2:2"),
            opened: t0 + secs(5),
        };
        assert_eq!(t.view.get(idx(1), t0 + secs(204)), Some(route));
        assert_eq!(t.view.get(idx(1), t0 + secs(205)), None, "counted from opening");
        // A stale open entry replaced by a pending one leaves the view at once.
        t.insert(idx(1), pending("192.0.2.3:3", "192.0.2.4:4", t0 + secs(205))).unwrap();
        assert_eq!(t.view.len(), 0);
        // Roaming rewrites open entries in the view; pending ones stay out of it.
        t.insert(idx(2), open("192.0.2.1:1", "192.0.2.3:3", t0)).unwrap();
        t.migrate(addr("192.0.2.3:3"), addr("192.0.2.9:9"));
        assert_eq!(t.view.get(idx(2), t0).map(|r| r.expected_src), Some(addr("192.0.2.9:9")));
        assert_eq!(t.view.len(), 1);
    }

    #[test]
    fn session_migrate_rewrites_both_directions() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(idx(0x00ab_cd01), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.insert(idx(0x0011_2201), pending("192.0.2.2:2", "192.0.2.1:1", t0)).unwrap();
        t.migrate(addr("192.0.2.1:1"), addr("192.0.2.9:9"));
        assert_eq!(t.get(idx(0x00ab_cd01), t0).map(|s| s.dest), Some(addr("192.0.2.9:9")));
        assert_eq!(t.get(idx(0x0011_2201), t0).map(|s| s.expected_src), Some(addr("192.0.2.9:9")));
        assert_eq!(t.retain(|s| s.dest.port() == 9), 1);
    }

    #[test]
    fn has_prefix_matches_upper_24_bits_only() {
        let mut t = table();
        t.insert(idx(0x00ab_cd01), pending("192.0.2.1:1", "192.0.2.2:2", Instant::now())).unwrap();
        assert!(t.has_prefix(idx(0x00ab_cdff).prefix()));
        assert!(!t.has_prefix(idx(0x00ab_ce01).prefix()));
    }

    #[test]
    fn pending_over_quota_evicts_that_peers_oldest_only() {
        let t0 = Instant::now();
        let limits = SessionLimits { pending_per_peer: 2, ..UNLIMITED };
        let mut t = Checked::new(SessionTable::new(SESSION_TTL, PENDING_TTL, limits));
        let for_peer = |n: u8, port: u16| {
            Session::pending(addr(&format!("192.0.2.1:{port}")), addr("192.0.2.9:9"), key(n), t0)
        };
        assert_eq!(t.insert(idx(1), for_peer(1, 1)), Ok(None));
        assert_eq!(t.insert(idx(2), for_peer(1, 2)), Ok(None));
        assert_eq!(t.insert(idx(10), for_peer(2, 10)), Ok(None));
        assert_eq!(t.insert(idx(11), for_peer(2, 11)), Ok(None));
        assert_eq!(t.insert(idx(3), for_peer(1, 3)), Ok(Some(idx(1))));
        assert_eq!(t.get(idx(1), t0), None, "peer 1's oldest went");
        assert_eq!((queue(&t, 1), queue(&t, 2)), (vec![idx(2), idx(3)], vec![idx(10), idx(11)]));
        assert_eq!((t.pending(), t.len()), (4, 4));

        // An opened entry no longer counts, so the next one evicts nothing.
        t.open(idx(2), t0);
        assert_eq!(t.insert(idx(4), for_peer(1, 4)), Ok(None));
        assert!(t.get(idx(2), t0).is_some() && t.get(idx(3), t0).is_some());
        assert_eq!((queue(&t, 1), t.pending()), (vec![idx(3), idx(4)], 4));

        // Re-sending a pending index moves it to the back instead of duplicating it.
        assert_eq!(t.insert(idx(3), for_peer(1, 3)), Ok(None));
        assert_eq!(t.insert(idx(5), for_peer(1, 5)), Ok(Some(idx(4))));
        assert_eq!(t.get(idx(4), t0), None);
        assert_eq!((queue(&t, 1), t.pending()), (vec![idx(3), idx(5)], 4));

        // Opened, expired and removed entries leave the queues, and empty queues go.
        let opened = Session::open(addr("192.0.2.1:5"), addr("192.0.2.9:9"), key(1), t0);
        assert_eq!(t.insert(idx(5), opened), Ok(None));
        assert!(counts_exact(&t));
        assert_eq!((queue(&t, 1), t.pending()), (vec![idx(3)], 3));
        assert_eq!(t.retain(|s| s.peer != key(2)), 2);
        assert_eq!((queue(&t, 2), t.pending()), (vec![], 1));
        assert_eq!(t.expire(t0 + PENDING_TTL), 1);
        assert_eq!((t.pending(), t.ledger.peers().0), (0, 0));
        assert_eq!(t.len(), 2, "the open entries");
        assert!(counts_exact(&t));
    }

    #[test]
    fn session_table_counts_pending_through_every_transition() {
        let t0 = Instant::now();
        let mut t = table();
        t.insert(idx(1), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.insert(idx(2), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        t.insert(idx(3), open("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        assert_eq!(t.pending(), 2);
        t.insert(idx(1), pending("192.0.2.1:1", "192.0.2.2:2", t0 + secs(1))).unwrap();
        assert_eq!(t.pending(), 2, "replacing a pending entry");
        let other = pending("192.0.2.3:3", "192.0.2.4:4", t0);
        assert_eq!(t.insert(idx(1), other), Err(Refusal::IndexInUse), "refused");
        assert_eq!(t.pending(), 2);
        t.open(idx(2), t0);
        t.open(idx(2), t0);
        assert_eq!(t.pending(), 1, "opened once");
        assert_eq!(t.expire(t0 + secs(30)), 1);
        assert_eq!(t.pending(), 0, "expired");
        t.insert(idx(4), pending("192.0.2.1:1", "192.0.2.2:2", t0)).unwrap();
        assert_eq!(t.retain(|s| s.state == SessionState::Open), 1);
        assert_eq!(t.pending(), 0, "removed by retain");
    }

    #[test]
    fn session_table_gives_memory_back_after_a_flood() {
        let t0 = Instant::now();
        let mut t = table();
        // Unchecked one by one: checking compares whole tables.
        for i in 0..100_000 {
            let s = pending("192.0.2.1:1", "192.0.2.2:2", t0);
            t.table.insert(idx(i), s, &t.view).unwrap();
        }
        let peak = t.map.capacity();
        t.insert(idx(1 << 31), open("192.0.2.1:1", "192.0.2.2:2", t0 + secs(5))).unwrap();
        assert_eq!(t.expire(t0 + secs(11)), 100_000);
        assert!(t.map.capacity() < peak / 50, "{} of {peak}", t.map.capacity());
        assert_eq!((t.len(), t.pending()), (1, 0));
    }

    #[test]
    fn peer_quota_counts_pending_and_open_and_spares_other_peers() {
        let t0 = Instant::now();
        let limits = SessionLimits { pending_per_peer: 2, per_peer: 3, total: usize::MAX };
        let mut t = Checked::new(SessionTable::new(SESSION_TTL, PENDING_TTL, limits));
        let s = |n: u8, port: u16, state: SessionState| Session {
            state,
            ..Session::pending(addr(&format!("192.0.2.1:{port}")), addr("192.0.2.9:9"), key(n), t0)
        };
        let (p, o) = (SessionState::Pending, SessionState::Open);
        t.insert(idx(1), s(1, 1, o)).unwrap();
        t.insert(idx(2), s(1, 2, p)).unwrap();
        t.insert(idx(3), s(1, 3, p)).unwrap();
        assert!(t.peer_at_quota(&key(1)) && !t.peer_at_quota(&key(2)));
        // At quota, a new index is refused, even one that would only evict.
        assert_eq!(t.insert(idx(4), s(1, 4, p)), Err(Refusal::PeerQuota));
        assert_eq!(t.insert(idx(4), s(1, 4, o)), Err(Refusal::PeerQuota));
        assert_eq!(t.get(idx(2), t0).map(|s| s.state), Some(p), "nothing evicted");
        // Replacing one of its own entries does not grow it, and another peer is unaffected.
        assert_eq!(t.insert(idx(3), s(1, 3, p)), Ok(None));
        assert_eq!(t.insert(idx(10), s(2, 10, o)), Ok(None));
        // A stale entry of peer 1 taken over by peer 2 moves the count.
        assert_eq!(t.insert(idx(1), s(2, 1, p)), Err(Refusal::IndexInUse), "live");
        let late = Session { since: t0 + SESSION_TTL, ..s(2, 1, p) };
        assert_eq!(t.insert(idx(1), late), Ok(None), "stale");
        assert!(counts_exact(&t));
        assert!(!t.peer_at_quota(&key(1)) && t.ledger.count(&key(2)) == 2);
        // Expiry and retain free quota.
        assert_eq!(t.expire(t0 + PENDING_TTL), 2);
        assert!(counts_exact(&t));
        assert_eq!(t.retain(|s| s.peer != key(2)), 2);
        assert!(counts_exact(&t) && t.ledger.peers().1 == 0 && t.len() == 0);
    }

    #[test]
    fn total_cap_refuses_new_indexes_but_not_replacements() {
        let t0 = Instant::now();
        let limits = SessionLimits { pending_per_peer: 1, per_peer: usize::MAX, total: 3 };
        let mut t = Checked::new(SessionTable::new(SESSION_TTL, PENDING_TTL, limits));
        let for_peer = |n: u8, port: u16| {
            Session::pending(addr(&format!("192.0.2.1:{port}")), addr("192.0.2.9:9"), key(n), t0)
        };
        for n in 1..=3 {
            t.insert(idx(u32::from(n)), for_peer(n, 1)).unwrap();
        }
        assert!(t.is_full());
        assert_eq!(t.insert(idx(4), for_peer(4, 4)), Err(Refusal::Full));
        assert_eq!(t.insert(idx(1), for_peer(1, 1)), Ok(None), "replacement");
        // A peer at its pending quota still cannot add an index to a full table.
        assert_eq!(t.insert(idx(5), for_peer(1, 5)), Err(Refusal::Full));
        assert_eq!(t.get(idx(1), t0).map(|s| s.dest), Some(addr("192.0.2.1:1")));
        assert_eq!(t.expire(t0 + PENDING_TTL), 3);
        assert_eq!(t.insert(idx(4), for_peer(4, 4)), Ok(None), "room after expiry");
        assert!(counts_exact(&t));
    }

    #[test]
    fn pending_eviction_keeps_peer_counts_exact() {
        let t0 = Instant::now();
        let limits = SessionLimits { pending_per_peer: 2, per_peer: 4, total: usize::MAX };
        let mut t = Checked::new(SessionTable::new(SESSION_TTL, PENDING_TTL, limits));
        let mut evicted = 0;
        for i in 0..100 {
            let s = Session::pending(addr("192.0.2.1:1"), addr("192.0.2.9:9"), key(1), t0);
            evicted += usize::from(t.insert(idx(i), s).unwrap().is_some());
        }
        assert_eq!((evicted, t.len(), t.ledger.count(&key(1))), (98, 2, 2));
        assert!(!t.peer_at_quota(&key(1)), "evictions free quota");
        assert!(counts_exact(&t));
    }
}
