//! The nightly job's decisions: which closed days need a batch, what to anchor for a day, and
//! inclusion proofs for past records.

use std::collections::BTreeSet;
use std::path::Path;

use citrate_agent_records::merkle::{retained_leaves, utc_day};

use crate::batch::{build_day_batch, AnchorProof, BatchHeader};
use crate::calldata::{check_address, UnsignedAnchorCall};
use crate::error::{Error, Result};
use crate::ledger::{AnchorLedger, EntryStatus, LedgerEntry};

/// What the nightly job should do about one closed day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NightlyPlan {
    /// The day has no records: nothing to anchor.
    Empty { day: u64 },
    /// Every retained record of the day is gone and some were pruned before batching: nothing
    /// can be proven for that day.
    Pruned { day: u64 },
    /// Some of the day's records were pruned before batching. Reported (recorded in the ledger as
    /// incomplete), never anchored, because a root over part of a day would claim less than the
    /// day.
    Incomplete { day: u64, retained: u64 },
    /// The day's batch is fixed. `call` is the unsigned `anchor(NightlyMerkle, commitment)` for
    /// core's ceremony. Planning a batched but unconfirmed day again returns the same call.
    Ready {
        header: BatchHeader,
        commitment: [u8; 32],
        call: UnsignedAnchorCall,
        /// Whether this call recorded the batch (false: it was already in the ledger).
        newly_recorded: bool,
    },
    /// Core recorded the anchor as confirmed on chain.
    AlreadyAnchored { entry: LedgerEntry },
}

fn ready(header: BatchHeader, registry: Option<&str>, newly_recorded: bool) -> NightlyPlan {
    let commitment = header.commitment();
    NightlyPlan::Ready {
        call: UnsignedAnchorCall::nightly(commitment, registry),
        header,
        commitment,
        newly_recorded,
    }
}

/// Plan UTC day `day` at wall-clock `now_ms`. Only a closed day (before today) is batched, so no
/// record can join a day after its root is fixed. Verifies the record chain first (a broken chain
/// is an error) and records the batch, or the incomplete report, in the ledger. `registry` is the
/// `AnchorRegistry` address for the unsigned call, when known; a malformed address is refused
/// ([`Error::BadCalldata`]) before anything is recorded.
pub fn plan_day(
    records_dir: &Path,
    ledger: &AnchorLedger,
    day: u64,
    now_ms: u64,
    registry: Option<&str>,
) -> Result<NightlyPlan> {
    let today = utc_day(now_ms);
    if day >= today {
        return Err(Error::DayNotClosed { day, today });
    }
    if let Some(to) = registry {
        check_address(to)?;
    }
    let existing = ledger.get(day)?;
    if let Some(e) = &existing {
        if e.confirmed.is_some() {
            return Ok(NightlyPlan::AlreadyAnchored { entry: e.clone() });
        }
        if e.status == EntryStatus::Incomplete {
            return Ok(NightlyPlan::Incomplete {
                day,
                retained: e.count,
            });
        }
    }
    let ret = retained_leaves(records_dir)?;
    let partial = ret.pruned_through_ms.is_some_and(|t| utc_day(t) >= day);
    let batch = build_day_batch(day, &ret.leaves)?;

    if let Some(header) = existing.as_ref().and_then(LedgerEntry::header) {
        // Already batched: recheck against the records when they are all still there.
        if let (Some(b), false) = (&batch, partial) {
            if b.commitment() != header.commitment() {
                return Err(Error::Conflict { day });
            }
        }
        return Ok(ready(header, registry, false));
    }

    match batch {
        None if partial => Ok(NightlyPlan::Pruned { day }),
        None => Ok(NightlyPlan::Empty { day }),
        Some(b) if partial => {
            let h = b.header();
            ledger.record_incomplete(day, h.first_seq, h.last_seq, now_ms)?;
            Ok(NightlyPlan::Incomplete {
                day,
                retained: h.count,
            })
        }
        Some(b) => {
            ledger.record_batched(b.header(), now_ms)?;
            Ok(ready(b.header().clone(), registry, true))
        }
    }
}

/// Closed days (before today) that have retained records and no ledger entry yet, oldest first:
/// the days the nightly job still has to batch or report. Batched days waiting for core's
/// confirmation are listed by [`AnchorLedger::unconfirmed`].
pub fn pending_days(records_dir: &Path, ledger: &AnchorLedger, now_ms: u64) -> Result<Vec<u64>> {
    let today = utc_day(now_ms);
    let recorded: BTreeSet<u64> = ledger.entries()?.iter().map(|e| e.day).collect();
    let days: BTreeSet<u64> = retained_leaves(records_dir)?
        .leaves
        .iter()
        .map(|l| utc_day(l.ts_ms))
        .filter(|d| *d < today && !recorded.contains(d))
        .collect();
    Ok(days.into_iter().collect())
}

/// An inclusion proof for record `seq` against its day's anchored value. `Ok(None)` when `seq`
/// is not retained; [`Error::NotBatched`] when its day has no batch yet; [`Error::Conflict`] when
/// the records no longer match the recorded batch.
///
/// Proofs are built from the retained records. Once any record of a batched day is pruned, the
/// day's tree cannot be rebuilt and this returns [`Error::PrunedDay`]; keep a day's segments until
/// its proofs are no longer needed.
pub fn prove(records_dir: &Path, ledger: &AnchorLedger, seq: u64) -> Result<Option<AnchorProof>> {
    let ret = retained_leaves(records_dir)?;
    let Some(leaf) = ret.leaves.iter().find(|l| l.seq == seq) else {
        return Ok(None);
    };
    let day = utc_day(leaf.ts_ms);
    let Some(header) = ledger.get(day)?.as_ref().and_then(LedgerEntry::header) else {
        return Err(Error::NotBatched { day });
    };
    if ret.pruned_through_ms.is_some_and(|t| utc_day(t) >= day) {
        return Err(Error::PrunedDay { day });
    }
    let Some(batch) = build_day_batch(day, &ret.leaves)? else {
        return Err(Error::NotBatched { day });
    };
    if batch.header() != &header {
        return Err(Error::Conflict { day });
    }
    Ok(batch.proof(seq))
}
