//! Nightly anchor batch over the local decision records (HUP-S7.3, runtime half; D-23).
//!
//! Every HIC-1 / HIC-2 decision is a record in `citrate-agent-records`' hash-chained log. Once a
//! UTC day is over, this crate turns that day's records into one batch and one 32-byte value to
//! anchor on chain, so every record of the day is fixed and can later be proven:
//!
//! 1. **Batch.** The records whose timestamp falls on the day, across segment rotations, in `seq`
//!    order (the log verifies its chain first and refuses a broken one). A day is a contiguous
//!    run of `seq` because record timestamps never go backwards; a gap is refused. Only closed
//!    days are batched (`day < today`), so no record can join a day after its root is fixed.
//! 2. **Tree.** RFC 6962 Merkle tree over the record hashes: leaf `SHA-256(0x00 || record_hash)`,
//!    node `SHA-256(0x01 || left || right)`, odd sizes promote the last node (no duplication).
//!    Same tree and the same hash functions as `citrate_agent_records::merkle`. See [`tree`].
//! 3. **Commitment.** The anchored value binds the day, the `seq` range, the count, and the tree
//!    root under the domain `citrate.agent-anchor.nightly.v1\n`. See [`batch`].
//! 4. **Proofs.** Per-record inclusion proofs ([`AnchorProof`]) checked by [`verify_proof`] (and
//!    [`verify_record_proof`] for a full record) against the value read from `AnchorRegistry`.
//! 5. **Ledger.** [`AnchorLedger`] records each day once: never re-batched with a different root,
//!    no record in two batches, partly pruned days reported as incomplete instead of anchored.
//! 6. **Calldata.** [`UnsignedAnchorCall`]: `AnchorRegistry.anchor(AnchorKind.NightlyMerkle,
//!    commitment)` (selector `0x9e621f4c`, kind `2`), plus `isAnchored` for a read-only check.
//! 7. **Confirmation.** [`OwnAnchorCheck`]: whether *this* committer anchored a value, asked with
//!    `isAnchoredBy(committer, root)` on the next registry version and with the first record's
//!    committer (`getAnchor`) on the deployed one. `isAnchored(root)` alone never confirms an
//!    anchor: anyone can send the same value. See [`confirm`].
//!
//! Counts: zero records is no batch ([`NightlyPlan::Empty`]); one record is a tree whose root is
//! that record's leaf hash and whose proof path is empty; odd counts promote.
//!
//! # Keyless (Rule 3)
//!
//! Nothing here holds a key, signs, or sends. Under the accepted Rule-3 ADR
//! (ADR-2026-09-30-rule3-budgetable-signatures, D-23 as amended by RT-2) the nightly anchor is
//! signed by a separate no-funds anchor key inside citrate-core's signature ceremony. That
//! signing path, the schedule that calls [`plan_day`] each night, and writing the confirmation
//! back with [`AnchorLedger::mark_confirmed`] are a later core WP and are not built here.
//!
//! The formal model is `formal/AnchorBatch.tla` (see `formal/README.md`).

mod batch;
mod calldata;
pub mod confirm;
mod error;
mod hex32;
mod ledger;
mod nightly;
pub mod tree;

pub use batch::{
    build_day_batch, verify_proof, verify_record_proof, AnchorProof, BatchHeader, DayBatch,
    BATCH_VERSION, COMMITMENT_DOMAIN,
};
pub use calldata::{
    anchor_calldata, decode_anchor_calldata, is_anchored_calldata, AnchorKind, UnsignedAnchorCall,
    ANCHOR_SELECTOR, ANCHOR_SIGNATURE, CITRATE_CHAIN_ID, IS_ANCHORED_SELECTOR,
};
pub use confirm::{
    decode_anchor_committer, decode_bool, get_anchor_calldata, is_anchored_by_calldata, CheckStep,
    OwnAnchorCheck, RegistryAnswer, GET_ANCHOR_SELECTOR, IS_ANCHORED_BY_SELECTOR,
};
pub use error::{Error, Result};
pub use ledger::{AnchorLedger, Confirmation, EntryStatus, LedgerEntry, RecordOutcome};
pub use nightly::{pending_days, plan_day, prove, NightlyPlan};
pub use tree::Tree;
