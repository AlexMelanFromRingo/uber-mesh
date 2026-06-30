//! Range-based set reconciliation (negentropy-style) over sorted `Cid` sets.
//!
//! Two peers efficiently discover the symmetric difference of their content-id sets in O(diff · log n)
//! bandwidth instead of transferring the full sets (research D10 / mesh-integrity). The id space is
//! covered by segments; each segment carries either a BLAKE3 **fingerprint** (cheap, recurse on
//! mismatch), an explicit **id list** (terminal, for small ranges), or **skip** (already matched).
//!
//! The initiator runs [`Reconciler::refine`] (accumulating its [`Diff`]); the responder runs the
//! stateless [`respond`]. Driven to convergence (all-skip), the initiator learns exactly which ids the
//! responder has that it lacks (`need`) and which it has that the responder lacks (`have_extra`).

use std::collections::BTreeSet;

use umesh_crypto::hash;

/// A 32-byte content id.
pub type Id = [u8; 32];

const FP_LABEL: &str = "uber-mesh v1 reconcile-fp";
/// At or below this many items in a range, send the explicit id list (terminal).
const THRESHOLD: usize = 4;
/// Number of sub-ranges a mismatching range is split into.
const BUCKETS: usize = 8;
/// Safety bound on reconciliation rounds.
const MAX_ROUNDS: usize = 64;

/// What a segment tells the peer about a contiguous id range.
#[derive(Clone, Debug, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub enum Mode {
    /// The range is already reconciled (fingerprints matched).
    Skip,
    /// BLAKE3 fingerprint over the sender's ids in the range.
    Fingerprint([u8; 32]),
    /// The explicit ids the sender holds in the range.
    IdList(Vec<Id>),
}

/// One segment of a reconciliation message, covering `(previous_upper, upper]` where `upper = None`
/// means "to the end of the id space".
#[derive(Clone, Debug, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub struct Segment {
    /// Exclusive upper bound of this segment's range, or `None` for infinity (last segment).
    pub upper: Option<Id>,
    /// What the sender knows about the range.
    pub mode: Mode,
}

/// A reconciliation message: ordered segments covering the whole id space.
pub type Message = Vec<Segment>;

/// The symmetric difference learned by the initiator.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Diff {
    /// Ids the responder has that we lack (fetch these).
    pub need: Vec<Id>,
    /// Ids we have that the responder lacks (offer these).
    pub have_extra: Vec<Id>,
}

fn fingerprint(ids: &[Id]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(ids.len() * 32);
    for id in ids {
        buf.extend_from_slice(id);
    }
    hash::derive_key(FP_LABEL, &buf)
}

/// Items of the sorted slice within `[lower, upper)` (or `[lower, ∞)` when `upper` is `None`).
fn items_in_range<'a>(sorted: &'a [Id], lower: &Id, upper: &Option<Id>) -> &'a [Id] {
    let start = sorted.partition_point(|x| x < lower);
    let end = match upper {
        Some(u) => sorted.partition_point(|x| x < u),
        None => sorted.len(),
    };
    &sorted[start..end.max(start)]
}

/// Split a range's local `items` into segments: an id list if small, else bucketed fingerprints.
fn split(upper: Option<Id>, items: &[Id]) -> Message {
    if items.len() <= THRESHOLD {
        return vec![Segment {
            upper,
            mode: Mode::IdList(items.to_vec()),
        }];
    }
    let buckets = BUCKETS.min(items.len());
    let sz = items.len().div_ceil(buckets);
    let mut segs = Vec::new();
    let mut i = 0;
    while i < items.len() {
        let end = (i + sz).min(items.len());
        let seg_upper = if end == items.len() {
            upper
        } else {
            Some(items[end])
        };
        segs.push(Segment {
            upper: seg_upper,
            mode: Mode::Fingerprint(fingerprint(&items[i..end])),
        });
        i = end;
    }
    segs
}

fn next_lower(upper: &Option<Id>) -> Id {
    upper.unwrap_or([0xff; 32])
}

/// The first message an initiator sends: cover the whole id space from its sorted local ids.
pub fn initiate(local_sorted: &[Id]) -> Message {
    split(None, local_sorted)
}

/// Stateless responder step: answer the peer's message.
pub fn respond(local_sorted: &[Id], incoming: &Message) -> Message {
    let mut out = Message::new();
    let mut lower = [0u8; 32];
    for seg in incoming {
        let items = items_in_range(local_sorted, &lower, &seg.upper);
        match &seg.mode {
            Mode::Skip => out.push(Segment {
                upper: seg.upper,
                mode: Mode::Skip,
            }),
            Mode::Fingerprint(their_fp) => {
                if &fingerprint(items) == their_fp {
                    out.push(Segment {
                        upper: seg.upper,
                        mode: Mode::Skip,
                    });
                } else {
                    out.extend(split(seg.upper, items));
                }
            }
            // Reply to an id list with our own so the initiator can finalize the diff.
            Mode::IdList(_) => {
                out.push(Segment {
                    upper: seg.upper,
                    mode: Mode::IdList(items.to_vec()),
                });
            }
        }
        lower = next_lower(&seg.upper);
    }
    out
}

/// Initiator state: holds the running [`Diff`] across rounds.
#[derive(Default)]
pub struct Reconciler {
    /// The symmetric difference discovered so far.
    pub diff: Diff,
}

impl Reconciler {
    /// Process the responder's message, accumulate the diff, and produce the next message to send.
    /// When the returned message is all-[`Mode::Skip`], reconciliation has converged.
    pub fn refine(&mut self, local_sorted: &[Id], incoming: &Message) -> Message {
        let mut out = Message::new();
        let mut lower = [0u8; 32];
        for seg in incoming {
            let items = items_in_range(local_sorted, &lower, &seg.upper);
            match &seg.mode {
                Mode::Skip => out.push(Segment {
                    upper: seg.upper,
                    mode: Mode::Skip,
                }),
                Mode::Fingerprint(their_fp) => {
                    if &fingerprint(items) == their_fp {
                        out.push(Segment {
                            upper: seg.upper,
                            mode: Mode::Skip,
                        });
                    } else {
                        out.extend(split(seg.upper, items));
                    }
                }
                Mode::IdList(their) => {
                    let have: BTreeSet<&Id> = items.iter().collect();
                    let theirs: BTreeSet<&Id> = their.iter().collect();
                    for id in &theirs {
                        if !have.contains(*id) {
                            self.diff.need.push(**id);
                        }
                    }
                    for id in &have {
                        if !theirs.contains(*id) {
                            self.diff.have_extra.push(**id);
                        }
                    }
                    out.push(Segment {
                        upper: seg.upper,
                        mode: Mode::Skip,
                    });
                }
            }
            lower = next_lower(&seg.upper);
        }
        out
    }
}

/// Whether a message is fully reconciled (all segments are skips).
pub fn is_converged(msg: &Message) -> bool {
    msg.iter().all(|s| s.mode == Mode::Skip)
}

/// Drive a full in-memory reconciliation between two sorted id sets, returning the initiator's diff
/// and the number of rounds. Real peers exchange [`Message`]s over the network instead (see the
/// `/uber-mesh/reconcile` protocol); this is the reference driver used in tests.
pub fn reconcile_local(initiator: &[Id], responder: &[Id]) -> (Diff, usize) {
    let mut rec = Reconciler::default();
    let mut msg = initiate(initiator);
    let mut rounds = 0;
    while rounds < MAX_ROUNDS {
        rounds += 1;
        let resp = respond(responder, &msg);
        msg = rec.refine(initiator, &resp);
        if is_converged(&msg) {
            break;
        }
    }
    rec.diff.need.sort_unstable();
    rec.diff.have_extra.sort_unstable();
    (rec.diff, rounds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> Id {
        // Spread ids across the space so bucketing is meaningful (hash the index).
        hash::hash(&n.to_le_bytes())
    }

    fn sorted(ns: impl IntoIterator<Item = u64>) -> Vec<Id> {
        let mut v: Vec<Id> = ns.into_iter().map(id).collect();
        v.sort_unstable();
        v
    }

    #[test]
    fn identical_sets_converge_with_empty_diff() {
        let a = sorted(0..200);
        let (diff, rounds) = reconcile_local(&a, &a);
        assert!(diff.need.is_empty() && diff.have_extra.is_empty());
        assert!(
            rounds <= 2,
            "identical sets should converge fast, took {rounds}"
        );
    }

    #[test]
    fn discovers_symmetric_difference() {
        let a = sorted(0..200);
        // B = A minus {50} plus {1000, 1001}.
        let mut b: Vec<u64> = (0..200).filter(|&x| x != 50).collect();
        b.push(1000);
        b.push(1001);
        let b = sorted(b);

        let (diff, rounds) = reconcile_local(&a, &b);
        // Initiator A learns: need = ids B has that A lacks = {1000, 1001}; have_extra = {50}.
        assert_eq!(diff.need, sorted([1000, 1001]));
        assert_eq!(diff.have_extra, sorted([50]));
        assert!(rounds < 10, "should converge in few rounds, took {rounds}");
    }

    #[test]
    fn disjoint_sets() {
        let a = sorted(0..50);
        let b = sorted(100..150);
        let (diff, _) = reconcile_local(&a, &b);
        assert_eq!(diff.need, b);
        assert_eq!(diff.have_extra, a);
    }

    #[test]
    fn empty_sets() {
        let (diff, _) = reconcile_local(&[], &[]);
        assert!(diff.need.is_empty() && diff.have_extra.is_empty());
        let a = sorted(0..10);
        let (diff, _) = reconcile_local(&[], &a);
        assert_eq!(diff.need, a);
        assert!(diff.have_extra.is_empty());
    }

    #[test]
    fn small_diff_in_large_set_is_efficient() {
        let a = sorted(0..1000);
        let mut b: Vec<u64> = (0..1000).collect();
        b.push(9999);
        let b = sorted(b);
        let (diff, rounds) = reconcile_local(&a, &b);
        assert_eq!(diff.need, sorted([9999]));
        assert!(diff.have_extra.is_empty());
        // A handful of log-depth rounds, not O(n).
        assert!(
            rounds < 12,
            "1000-item set with 1 diff took {rounds} rounds"
        );
    }
}
