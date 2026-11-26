//! Pure planning of how one batch of received datagrams leaves the relay.
//!
//! Consecutive datagrams forwarded to the same destination leave as one GSO
//! send, which the kernel splits back into the very same datagrams. With GRO
//! a receive buffer holds several datagrams from one source back to back, so
//! a run within one buffer is sent straight from it; a run that continues
//! into the next buffer must be copied together first, which still costs far
//! less than a send per datagram.

use std::net::SocketAddr;
use std::ops::Range;

use quinn_udp::EcnCodepoint;
use wg_relay::relay::Verdict;

/// Byte ranges of the datagrams in a receive buffer of `len` bytes whose
/// datagrams are `stride` bytes each (the last may be shorter). A zero-length
/// datagram is still one datagram, so the relay counts it like any other.
pub fn segments(len: usize, stride: usize) -> impl Iterator<Item = Range<usize>> {
    let stride = if stride == 0 { len.max(1) } else { stride };
    (0..len.max(1)).step_by(stride).map(move |start| start..(start + stride).min(len))
}

/// One received datagram and what the relay decided for it.
#[derive(Debug, Clone, Copy)]
pub struct Datagram {
    /// Index of its receive buffer; datagrams of one buffer lie back to back.
    pub buf: usize,
    pub len: usize,
    pub verdict: Verdict,
    pub ecn: Option<EcnCodepoint>,
}

/// Bytes of one receive buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece {
    pub buf: usize,
    pub bytes: Range<usize>,
}

/// Consecutive forwarded datagrams that leave in one send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub dst: SocketAddr,
    pub ecn: Option<EcnCodepoint>,
    /// Length of every datagram in the run but the last, which may be shorter.
    pub segment_bytes: usize,
    pub segments: usize,
    /// Total length of the run.
    pub len: usize,
    /// Where its bytes are, as indexes into `Plan::pieces`; more than one
    /// piece means the run spans receive buffers and must be copied together.
    pub pieces: Range<usize>,
}

impl Run {
    /// The GSO segment size to send the run with, if it holds more than one datagram.
    pub fn gso_segment_bytes(&self) -> Option<usize> {
        (self.segments > 1).then_some(self.segment_bytes)
    }

    /// Can `d`, forwarded to `dst`, be appended? GSO splits a send into equal
    /// segments with only the last one shorter, all to one address with the
    /// same ECN bits.
    fn accepts(&self, dst: SocketAddr, d: &Datagram, limits: Limits) -> bool {
        dst == self.dst
            && d.ecn == self.ecn
            && d.len > 0
            && d.len <= self.segment_bytes
            && self.segments < limits.max_segments
            && self.len + d.len <= limits.max_bytes
    }
}

/// What one GSO send may carry.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_segments: usize,
    pub max_bytes: usize,
}

/// The sends for one batch, in arrival order. Reused across batches.
#[derive(Debug, Default)]
pub struct Plan {
    pub runs: Vec<Run>,
    pub pieces: Vec<Piece>,
}

impl Plan {
    /// Group `datagrams`, in arrival order, into the sends that forward them.
    ///
    /// A run ends when the destination or ECN bits change, a datagram is not
    /// forwarded, a datagram is longer than the run's first, or one shorter
    /// than it was added (only the last segment of a GSO send may be short).
    pub fn make(&mut self, datagrams: &[Datagram], limits: Limits) {
        self.runs.clear();
        self.pieces.clear();
        let mut open: Option<Run> = None;
        let (mut buf, mut offset) = (None, 0);
        for d in datagrams {
            if buf != Some(d.buf) {
                (buf, offset) = (Some(d.buf), 0);
            }
            let bytes = offset..offset + d.len;
            offset = bytes.end;
            let dst = match d.verdict {
                Verdict::Forward(dst) => dst,
                Verdict::DeliveredLocally | Verdict::Drop(_) => {
                    self.runs.extend(open.take());
                    continue;
                }
            };
            match open.as_mut() {
                Some(run) if run.accepts(dst, d, limits) => {
                    run.segments += 1;
                    run.len += d.len;
                    match self.pieces.last_mut() {
                        Some(p) if p.buf == d.buf && p.bytes.end == bytes.start => {
                            p.bytes.end = bytes.end;
                        }
                        _ => self.pieces.push(Piece { buf: d.buf, bytes }),
                    }
                    run.pieces.end = self.pieces.len();
                    if d.len < run.segment_bytes {
                        self.runs.extend(open.take());
                    }
                }
                _ => {
                    self.runs.extend(open.take());
                    let first = self.pieces.len();
                    self.pieces.push(Piece { buf: d.buf, bytes });
                    open = Some(Run {
                        dst,
                        ecn: d.ecn,
                        segment_bytes: d.len,
                        segments: 1,
                        len: d.len,
                        pieces: first..first + 1,
                    });
                }
            }
        }
        self.runs.extend(open);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wg_relay::relay::DropReason;

    const GSO: Limits = Limits { max_segments: 64, max_bytes: 65_507 };
    const DROP: Verdict = Verdict::Drop(DropReason::UnknownIndex);

    fn addr(i: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, i], 51820))
    }

    fn fwd(i: u8) -> Verdict {
        Verdict::Forward(addr(i))
    }

    /// Datagrams of one receive buffer, without ECN.
    fn buffer(buf: usize, d: &[(usize, Verdict)]) -> Vec<Datagram> {
        d.iter().map(|&(len, verdict)| Datagram { buf, len, verdict, ecn: None }).collect()
    }

    /// A run as (destination, segment size, segments, pieces as (buffer, bytes)).
    type Summary = (u8, usize, usize, Vec<(usize, Range<usize>)>);

    fn planned(datagrams: &[Datagram], limits: Limits) -> Vec<Summary> {
        let mut plan = Plan::default();
        plan.make(&buffer(9, &[(1, fwd(9))]), GSO); // stale output must be cleared
        plan.make(datagrams, limits);
        let summary = plan.runs.iter().map(|r| {
            let SocketAddr::V4(dst) = r.dst else { panic!("test addresses are IPv4") };
            let pieces = &plan.pieces[r.pieces.clone()];
            let len: usize = pieces.iter().map(|p| p.bytes.len()).sum();
            assert_eq!(r.len, len, "run length matches its pieces");
            let pieces = pieces.iter().map(|p| (p.buf, p.bytes.clone())).collect();
            (dst.ip().octets()[3], r.segment_bytes, r.segments, pieces)
        });
        summary.collect()
    }

    #[test]
    fn all_forwarded_to_one_destination_is_one_run() {
        let d = buffer(0, &[(100, fwd(1)); 4]);
        assert_eq!(planned(&d, GSO), [(1, 100, 4, vec![(0, 0..400)])]);
    }

    #[test]
    fn destination_change_mid_buffer_splits_the_run() {
        let d = [(100, fwd(1)), (100, fwd(1)), (100, fwd(2)), (100, fwd(2)), (100, fwd(1))];
        let want = [
            (1, 100, 2, vec![(0, 0..200)]),
            (2, 100, 2, vec![(0, 200..400)]),
            (1, 100, 1, vec![(0, 400..500)]),
        ];
        assert_eq!(planned(&buffer(0, &d), GSO), want);
    }

    #[test]
    fn dropped_and_locally_delivered_datagrams_split_the_run() {
        let d = [
            (100, fwd(1)),
            (100, DROP),
            (100, fwd(1)),
            (100, fwd(1)),
            (100, Verdict::DeliveredLocally),
            (100, fwd(1)),
        ];
        let want = [
            (1, 100, 1, vec![(0, 0..100)]),
            (1, 100, 2, vec![(0, 200..400)]),
            (1, 100, 1, vec![(0, 500..600)]),
        ];
        assert_eq!(planned(&buffer(0, &d), GSO), want);
    }

    #[test]
    fn short_last_datagram_ends_the_run() {
        let d = buffer(0, &[(100, fwd(1)), (100, fwd(1)), (60, fwd(1))]);
        assert_eq!(planned(&d, GSO), [(1, 100, 3, vec![(0, 0..260)])]);
    }

    #[test]
    fn short_datagram_in_the_middle_closes_the_run() {
        let d = buffer(0, &[(100, fwd(1)), (60, fwd(1)), (100, fwd(1)), (100, fwd(1))]);
        let want = [(1, 100, 2, vec![(0, 0..160)]), (1, 100, 2, vec![(0, 160..360)])];
        assert_eq!(planned(&d, GSO), want);
    }

    #[test]
    fn longer_datagram_starts_a_new_run() {
        let d = buffer(0, &[(60, fwd(1)), (100, fwd(1)), (100, fwd(1))]);
        let want = [(1, 60, 1, vec![(0, 0..60)]), (1, 100, 2, vec![(0, 60..260)])];
        assert_eq!(planned(&d, GSO), want);
    }

    #[test]
    fn single_datagram_is_sent_without_gso() {
        let mut plan = Plan::default();
        plan.make(&buffer(0, &[(148, fwd(1))]), GSO);
        assert_eq!(plan.runs.len(), 1);
        assert_eq!(plan.runs[0].gso_segment_bytes(), None);
        assert_eq!(planned(&buffer(0, &[(148, fwd(1))]), GSO), [(1, 148, 1, vec![(0, 0..148)])]);
        assert_eq!(planned(&buffer(0, &[(148, DROP)]), GSO), []);
    }

    #[test]
    fn empty_input_plans_nothing() {
        assert_eq!(planned(&[], GSO), []);
    }

    #[test]
    fn runs_continue_across_buffers_as_separate_pieces() {
        let mut d = buffer(0, &[(100, fwd(1)), (100, fwd(1))]);
        d.extend(buffer(1, &[(100, fwd(1))]));
        d.extend(buffer(2, &[(100, fwd(1)), (100, fwd(2))]));
        let want = [
            (1, 100, 4, vec![(0, 0..200), (1, 0..100), (2, 0..100)]),
            (2, 100, 1, vec![(2, 100..200)]),
        ];
        assert_eq!(planned(&d, GSO), want);
    }

    #[test]
    fn ecn_change_splits_the_run() {
        let mut d = buffer(0, &[(100, fwd(1))]);
        let ce = buffer(1, &[(100, fwd(1))]);
        d.extend(ce.into_iter().map(|d| Datagram { ecn: Some(EcnCodepoint::Ce), ..d }));
        let want = [(1, 100, 1, vec![(0, 0..100)]), (1, 100, 1, vec![(1, 0..100)])];
        assert_eq!(planned(&d, GSO), want);
    }

    #[test]
    fn limits_split_long_runs() {
        let d = buffer(0, &[(100, fwd(1)); 3]);
        let singles = [
            (1, 100, 1, vec![(0, 0..100)]),
            (1, 100, 1, vec![(0, 100..200)]),
            (1, 100, 1, vec![(0, 200..300)]),
        ];
        assert_eq!(planned(&d, Limits { max_segments: 1, ..GSO }), singles);
        let pairs = [(1, 100, 2, vec![(0, 0..200)]), (1, 100, 1, vec![(0, 200..300)])];
        assert_eq!(planned(&d, Limits { max_segments: 2, ..GSO }), pairs);
        assert_eq!(planned(&d, Limits { max_bytes: 250, ..GSO }), pairs);
    }

    #[test]
    fn zero_length_datagram_never_joins_a_run() {
        let d = buffer(0, &[(100, fwd(1)), (0, fwd(1)), (100, fwd(1))]);
        let want = [
            (1, 100, 1, vec![(0, 0..100)]),
            (1, 0, 1, vec![(0, 100..100)]),
            (1, 100, 1, vec![(0, 100..200)]),
        ];
        assert_eq!(planned(&d, GSO), want);
    }

    #[test]
    fn segments_follow_the_stride() {
        let all = |len, stride| segments(len, stride).map(|r| (r.start, r.end)).collect::<Vec<_>>();
        assert_eq!(all(300, 100), [(0, 100), (100, 200), (200, 300)]);
        assert_eq!(all(260, 100), [(0, 100), (100, 200), (200, 260)]);
        assert_eq!(all(148, 148), [(0, 148)]);
        assert_eq!(all(148, 1500), [(0, 148)], "stride beyond the length");
        assert_eq!(all(148, 0), [(0, 148)], "no stride reported");
        assert_eq!(all(0, 0), [(0, 0)], "an empty datagram is still one");
    }
}
