//! The read API for the UI.
//!
//! Reads are lock-free and safe next to a live writer: an incomplete final line (an append in
//! flight) is skipped. Reads parse records but do not re-verify the chain; use
//! [`crate::verify_dir`] or [`crate::DecisionLog::verify`] for integrity.

use std::path::Path;

use crate::error::Result;
use crate::record::{Entry, StoredRecord};
use crate::seg::{list_segments, read_segment};

/// A decision together with the outcome that closed it, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionView {
    pub decision: StoredRecord,
    pub outcome: Option<StoredRecord>,
}

/// Up to `limit` records, newest first, with `seq` strictly below `before_seq` when given.
pub fn page(dir: &Path, before_seq: Option<u64>, limit: usize) -> Result<Vec<StoredRecord>> {
    let mut out = Vec::new();
    if limit == 0 {
        return Ok(out);
    }
    for (_, path) in list_segments(dir)?.iter().rev() {
        let seg = read_segment(path)?;
        for r in seg.records.into_iter().rev() {
            if before_seq.is_some_and(|b| r.record.seq >= b) {
                continue;
            }
            out.push(r);
            if out.len() == limit {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

/// The record with this `seq`, if it is retained.
pub fn get(dir: &Path, seq: u64) -> Result<Option<StoredRecord>> {
    for (_, path) in list_segments(dir)?.iter().rev() {
        let seg = read_segment(path)?;
        let Some(first) = seg.records.first() else {
            continue;
        };
        if first.record.seq > seq {
            continue;
        }
        return Ok(seg.records.into_iter().find(|r| r.record.seq == seq));
    }
    Ok(None)
}

/// The decision with this `seq` and its outcome. `None` when `seq` is not a retained decision.
pub fn decision_view(dir: &Path, seq: u64) -> Result<Option<DecisionView>> {
    let mut decision = None;
    for (_, path) in list_segments(dir)? {
        for r in read_segment(&path)?.records {
            match &r.record.entry {
                Entry::Decision(_) if r.record.seq == seq => decision = Some(r),
                Entry::Outcome(o) if o.decision_seq == seq && decision.is_some() => {
                    return Ok(decision.map(|d| DecisionView {
                        decision: d,
                        outcome: Some(r),
                    }));
                }
                _ => {}
            }
        }
    }
    Ok(decision.map(|d| DecisionView {
        decision: d,
        outcome: None,
    }))
}
