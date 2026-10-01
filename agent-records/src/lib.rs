//! Local decision records for every HIC-1 and HIC-2 event (HUP-S2.6, D-23 / D-28 groundwork).
//!
//! Every gated event (an approval card answered by the member, or an effect allowed inside a
//! live HIC-2 budget) becomes one record in an append-only, hash-chained log on the local disk.
//! Each record carries a `seq`, a timestamp, the previous record's hash, the actor (member, agent,
//! or daemon), the event kind and subject, the decision (approved, denied, auto within budget),
//! a reason, and evidence references.
//!
//! # Storage: JSONL segments, not SQLite
//!
//! Records are newline-delimited JSON in size-bounded segment files (`seg-NNNNNNNN.jsonl`), plus a
//! `HEAD` file naming the last durable record and, after pruning, a `CHECKPOINT` naming where the
//! retained chain starts. JSONL was chosen because the workload is append-only and sequential, a
//! torn final line is easy to detect and quarantine, the files are human-auditable with standard
//! tools, and it adds no new dependency (SQLite would pull in a bundled C library for no query
//! need the UI has today). Reads for the UI scan segments newest first; segments are bounded, so
//! a page read touches at most a few files.
//!
//! # Write-ahead semantics
//!
//! [`DecisionLog::record_decision`] returns only after the record is written and `fsync`ed, so a
//! caller performs the effect only after its decision is durable, and then closes it with
//! [`DecisionLog::record_outcome`]. On open, every allowing decision that has no outcome is closed
//! with [`Outcome::OutcomeUnknown`]: a write-ahead record cannot tell a crash before the effect
//! from a crash after it, so the log says so instead of guessing.
//!
//! # What the chain does and does not prove
//!
//! The verifier ([`verify_dir`]) detects an edited record, reordered or deleted records, a cut-off
//! tail (via `HEAD`), a torn write, injected fields, and records that break the HIC policy (an
//! HIC-1 event marked auto-within-budget, an outcome for a decision that allowed nothing). It does
//! **not** stop someone with write access to the directory from rewriting the whole chain and
//! `HEAD` consistently. That is what the nightly anchor is for: once a day's Merkle root
//! ([`merkle::daily_root`]) is anchored on chain (HUP-S7.3, not this crate), every record of that
//! day is fixed. Nothing here anchors, signs, or holds a key: records are not signed by a wallet,
//! and no device key is used (Rule 3: no sidecar or daemon holds a wallet key or signs).
//!
//! # Hashes
//!
//! Record hash: SHA-256 over a domain prefix and the body's canonical JSON. Merkle tree: RFC 6962
//! (leaf `H(0x00 || record_hash)`, node `H(0x01 || left || right)`, split at the largest power of
//! two). SHA-256 was chosen over BLAKE3 because the EVM has a SHA-256 precompile, so a later
//! on-chain inclusion check is cheap.
//!
//! Not wired yet: no sidecar session writes here today. Wiring is a later WP.

mod error;
pub mod merkle;
pub mod read;
mod record;
mod seg;
mod store;
mod verify;

pub use error::{Error, IntegrityError, Result};
pub use record::{
    Actor, ActorKind, Decision, DecisionEvent, Entry, EvidenceRef, HicTier, Outcome, OutcomeEvent,
    RecordBody, StoredRecord, GENESIS_PREV, MAX_EVIDENCE, MAX_ID_LEN, MAX_KIND_LEN, MAX_REASON_LEN,
    MAX_SUBJECT_LEN, MAX_URI_LEN, SCHEMA_VERSION,
};
pub use store::{Clock, DecisionLog, LogConfig, Receipt, RecoveryReport, SystemClock};
pub use verify::{verify_dir, VerifyReport};
