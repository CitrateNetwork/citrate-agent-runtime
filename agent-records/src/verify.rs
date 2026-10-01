//! The offline verifier.

use std::path::Path;

use crate::error::Result;
use crate::seg::{walk, Mode};

/// What a successful verification saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Records in the retained chain (after any pruning checkpoint).
    pub count: u64,
    pub first_seq: Option<u64>,
    /// `(seq, hash)` of the last record.
    pub tip: Option<(u64, String)>,
    pub segments: usize,
    /// Allowing decisions that have no outcome yet.
    pub open_decisions: Vec<u64>,
    /// The last record is durable but `HEAD` was not yet moved to it: the state a crash between
    /// the segment write and the `HEAD` update leaves. The writer repairs it on open.
    pub head_lag: bool,
}

/// Verify a records directory end to end: every hash, every `prev` link, `seq` continuity across
/// segments and the pruning checkpoint, non-decreasing timestamps, the HIC field policy, outcome
/// references, and the chain tip against `HEAD`.
///
/// Run it on a quiescent directory, or use [`crate::DecisionLog::verify`] while a writer is open:
/// an append in flight looks like a torn tail to an outside reader.
pub fn verify_dir(dir: &Path) -> Result<VerifyReport> {
    let w = walk(dir, Mode::Strict, |_| {})?;
    Ok(VerifyReport {
        count: w.count,
        first_seq: w.first_seq,
        tip: w.tip.map(|(s, h, _)| (s, h)),
        segments: w.segments,
        open_decisions: w.open.into_iter().collect(),
        head_lag: w.head_lag,
    })
}
