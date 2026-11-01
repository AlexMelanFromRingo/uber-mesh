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
//!
//! Hardening: every message is [`validate`]d (≤ [`MAX_SEGMENTS`] strictly-increasing, non-empty
//! ranges covering the id space once; id lists ≤ [`THRESHOLD`]). Both sides answer under a
//! [`MAX_SEGMENTS`] output budget — ranges that don't fit are answered with one fingerprint and
//! refined in a later round — so a response is bounded regardless of set size or request shape.

use std::collections::BTreeSet;

use thiserror::Error;
use umesh_crypto::hash;

/// A 32-byte content id.
pub type Id = [u8; 32];

const FP_LABEL: &str = "uber-mesh v1 reconcile-fp";
/// At or below this many items in a range, send the explicit id list (terminal). Also the maximum
/// length of any [`Mode::IdList`] on the wire.
pub const THRESHOLD: usize = 4;
/// Number of sub-ranges a mismatching range is split into.
const BUCKETS: usize = 8;
/// Maximum segments in one message (validated on input, enforced as an output budget).
pub const MAX_SEGMENTS: usize = 8192;
/// Safety bound on reconciliation rounds (initiator side).
pub const MAX_ROUNDS: usize = 256;
/// Maximum size of the accumulated diff (`need + have_extra`) per session.
pub const MAX_DIFF: usize = 1 << 18;

/// Why a reconciliation message (or session) was refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReconcileError {
    /// Message has no segments.
    #[error("empty reconcile message")]
    Empty,
    /// More than [`MAX_SEGMENTS`] segments.
    #[error("too many segments")]
    TooManySegments,
    /// Segment upper bounds are not strictly increasing (or a range is empty).
    #[error("segment bounds not strictly increasing")]
    NotIncreasing,
    /// The last segment does not extend to the end of the id space (`upper = None`), or a
    /// non-last segment does.
    #[error("segments do not cover the id space")]
    NotCovering,
    /// An id list longer than [`THRESHOLD`].
    #[error("id list too long")]
    IdListTooLong,
    /// The accumulated diff exceeded [`MAX_DIFF`].
    #[error("diff too large")]
    DiffTooLarge,
}

/// What a segment tells the peer about a contiguous id range.
#[derive(Clone, Debug, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub enum Mode {
    /// The range is already reconciled (fingerprints matched).
    Skip,
    /// BLAKE3 fingerprint over the sender's ids in the range.
    Fingerprint([u8; 32]),
    /// The explicit ids the sender holds in the range (at most [`THRESHOLD`]).
    IdList(Vec<Id>),
}

/// One segment of a reconciliation message, covering `[previous_upper, upper)` (the first segment
/// starts at `[0; 32]`) where `upper = None` means "to the end of the id space" (last segment only).
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

/// Structural validation of a peer's message. Guarantees the segments are disjoint, non-empty,
/// strictly ordered ranges covering the id space exactly once, so processing cost is
/// `O(segments · log n + n)` and the output is bounded — no range (and no id) can be repeated to
/// amplify the response.
pub fn validate(msg: &Message) -> Result<(), ReconcileError> {
    if msg.is_empty() {
        return Err(ReconcileError::Empty);
    }
    if msg.len() > MAX_SEGMENTS {
        return Err(ReconcileError::TooManySegments);
    }
    let mut lower = [0u8; 32];
    let last = msg.len() - 1;
    for (i, seg) in msg.iter().enumerate() {
        match (&seg.upper, i == last) {
            (Some(u), false) => {
                if *u <= lower {
                    return Err(ReconcileError::NotIncreasing);
                }
                lower = *u;
            }
            (None, true) => {}
            _ => return Err(ReconcileError::NotCovering),
        }
        if let Mode::IdList(ids) = &seg.mode
            && ids.len() > THRESHOLD
        {
            return Err(ReconcileError::IdListTooLong);
        }
    }
    Ok(())
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

/// Output builder: coalesces adjacent skips and enforces the [`MAX_SEGMENTS`] budget.
struct Out {
    segs: Message,
}

impl Out {
    fn push(&mut self, seg: Segment) {
        if seg.mode == Mode::Skip
            && let Some(last) = self.segs.last_mut()
            && last.mode == Mode::Skip
        {
            last.upper = seg.upper;
            return;
        }
        self.segs.push(seg);
    }

    /// Emit `split(upper, items)` if it fits in the budget (keeping one slot for each of the
    /// `remaining` input segments still to process); otherwise emit a single fingerprint for the
    /// whole range, deferring its refinement to a later round.
    fn refine_range(&mut self, upper: Option<Id>, items: &[Id], remaining: usize) {
        let parts = split(upper, items);
        if parts.len() == 1 || self.segs.len() + parts.len() + remaining <= MAX_SEGMENTS {
            self.segs.extend(parts);
        } else {
            self.segs.push(Segment {
                upper,
                mode: Mode::Fingerprint(fingerprint(items)),
            });
        }
    }
}

/// The first message an initiator sends: cover the whole id space from its sorted local ids.
pub fn initiate(local_sorted: &[Id]) -> Message {
    split(None, local_sorted)
}

/// Stateless responder step: answer the peer's message. The peer's message is [`validate`]d first;
/// the response holds at most [`MAX_SEGMENTS`] segments and every id list at most [`THRESHOLD`] ids,
/// so its size is bounded independently of the local set and of the request.
pub fn respond(local_sorted: &[Id], incoming: &Message) -> Result<Message, ReconcileError> {
    validate(incoming)?;
    let mut out = Out {
        segs: Message::new(),
    };
    let mut lower = [0u8; 32];
    let n = incoming.len();
    for (i, seg) in incoming.iter().enumerate() {
        let items = items_in_range(local_sorted, &lower, &seg.upper);
        let remaining = n - i - 1;
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
                    out.refine_range(seg.upper, items, remaining);
                }
            }
            // Reply to an id list with ours (if small) so the initiator can finalize the diff, or
            // with bucketed fingerprints if we hold more than THRESHOLD ids in the range.
            Mode::IdList(_) => out.refine_range(seg.upper, items, remaining),
        }
        if let Some(u) = seg.upper {
            lower = u;
        }
    }
    Ok(out.segs)
}

/// Initiator state: holds the running [`Diff`] across rounds.
#[derive(Default)]
pub struct Reconciler {
    /// The symmetric difference discovered so far.
    pub diff: Diff,
}

impl Reconciler {
    /// Process the responder's message, accumulate the diff, and produce the next message to send.
    /// When the returned message is all-[`Mode::Skip`], reconciliation has converged. The
    /// responder's message is [`validate`]d and the diff is capped at [`MAX_DIFF`].
    pub fn refine(
        &mut self,
        local_sorted: &[Id],
        incoming: &Message,
    ) -> Result<Message, ReconcileError> {
        validate(incoming)?;
        let mut out = Out {
            segs: Message::new(),
        };
        let mut lower = [0u8; 32];
        let n = incoming.len();
        for (i, seg) in incoming.iter().enumerate() {
            let items = items_in_range(local_sorted, &lower, &seg.upper);
            let remaining = n - i - 1;
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
                        out.refine_range(seg.upper, items, remaining);
                    }
                }
                Mode::IdList(their) => {
                    let have: BTreeSet<&Id> = items.iter().collect();
                    // Only ids inside this segment's range count (a hostile responder can't
                    // inject the same id via several segments).
                    let theirs: BTreeSet<&Id> = their
                        .iter()
                        .filter(|id| **id >= lower && seg.upper.is_none_or(|u| **id < u))
                        .collect();
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
                    if self.diff.need.len() + self.diff.have_extra.len() > MAX_DIFF {
                        return Err(ReconcileError::DiffTooLarge);
                    }
                    out.push(Segment {
                        upper: seg.upper,
                        mode: Mode::Skip,
                    });
                }
            }
            if let Some(u) = seg.upper {
                lower = u;
            }
        }
        Ok(out.segs)
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
        let resp = respond(responder, &msg).expect("honest initiator message is valid");
        msg = rec
            .refine(initiator, &resp)
            .expect("honest responder message is valid");
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

    /// Audit regression (amplification): alternating segments whose uppers don't increase used to
    /// make the responder copy its whole id set once per pair.
    #[test]
    fn non_increasing_segments_rejected() {
        let local = sorted(0..50);
        let pair = [
            Segment {
                upper: Some([0u8; 32]),
                mode: Mode::Skip,
            },
            Segment {
                upper: None,
                mode: Mode::IdList(vec![]),
            },
        ];
        let req: Message = pair.iter().cycle().take(2000).cloned().collect();
        assert_eq!(respond(&local, &req), Err(ReconcileError::NotIncreasing));
        // Same shape with a non-zero first bound: the mid-message `None` is caught.
        let mut req2 = req.clone();
        req2[0].upper = Some([1u8; 32]);
        assert_eq!(respond(&local, &req2), Err(ReconcileError::NotCovering));
        let req = vec![
            Segment {
                upper: Some([5u8; 32]),
                mode: Mode::Skip,
            },
            Segment {
                upper: Some([5u8; 32]),
                mode: Mode::Skip,
            },
            Segment {
                upper: None,
                mode: Mode::Skip,
            },
        ];
        assert_eq!(respond(&local, &req), Err(ReconcileError::NotIncreasing));
        let zero_first = vec![
            Segment {
                upper: Some([0u8; 32]),
                mode: Mode::Skip,
            },
            Segment {
                upper: None,
                mode: Mode::Skip,
            },
        ];
        assert_eq!(validate(&zero_first), Err(ReconcileError::NotIncreasing));
    }

    #[test]
    fn structural_limits_enforced() {
        assert_eq!(validate(&vec![]), Err(ReconcileError::Empty));
        let long = vec![Segment {
            upper: None,
            mode: Mode::IdList(vec![[1u8; 32]; THRESHOLD + 1]),
        }];
        assert_eq!(validate(&long), Err(ReconcileError::IdListTooLong));
        let ids = sorted(0..(MAX_SEGMENTS as u64 + 1));
        let mut many: Message = ids[1..]
            .iter()
            .map(|u| Segment {
                upper: Some(*u),
                mode: Mode::Skip,
            })
            .collect();
        many.last_mut().unwrap().upper = None;
        assert_eq!(many.len(), MAX_SEGMENTS);
        assert!(validate(&many).is_ok());
        many.insert(
            0,
            Segment {
                upper: Some(ids[0]),
                mode: Mode::Skip,
            },
        );
        assert_eq!(validate(&many), Err(ReconcileError::TooManySegments));
    }

    #[test]
    fn responder_output_bounded_for_any_valid_request() {
        // A request of MAX_SEGMENTS mismatching fingerprints against a large store: every range
        // wants an 8-way split, but the output stays within budget and id lists stay small.
        let local = sorted(0..60_000);
        let bounds = sorted(1_000_000..1_000_000 + MAX_SEGMENTS as u64 - 1);
        let mut req: Message = bounds
            .iter()
            .map(|u| Segment {
                upper: Some(*u),
                mode: Mode::Fingerprint([0xAA; 32]),
            })
            .collect();
        req.push(Segment {
            upper: None,
            mode: Mode::IdList(vec![]),
        });
        let resp = respond(&local, &req).unwrap();
        assert!(resp.len() <= MAX_SEGMENTS);
        assert!(validate(&resp).is_ok(), "responder output is itself valid");
    }

    #[test]
    fn large_one_sided_sync_converges_under_budget() {
        // Empty initiator vs 40k-id responder: the bottom level needs more than MAX_SEGMENTS
        // segments, so the budget defers ranges across rounds — still exact.
        let b = sorted(0..40_000);
        let (diff, rounds) = reconcile_local(&[], &b);
        assert_eq!(diff.need, b);
        assert!(diff.have_extra.is_empty());
        assert!(rounds < MAX_ROUNDS, "took {rounds} rounds");
    }

    #[test]
    fn initiator_ignores_out_of_range_ids() {
        let a = sorted(0..3);
        let mut rec = Reconciler::default();
        let outsider = [0xffu8; 32];
        let resp = vec![
            Segment {
                upper: Some([0x80; 32]),
                mode: Mode::IdList(vec![outsider, outsider]),
            },
            Segment {
                upper: None,
                mode: Mode::IdList(vec![outsider]),
            },
        ];
        rec.refine(&a, &resp).unwrap();
        assert_eq!(
            rec.diff.need,
            vec![outsider],
            "counted once, in its own range"
        );
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
