//! Errors.

use std::path::PathBuf;

/// Why a log failed verification. Each variant names where the chain broke.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntegrityError {
    #[error("segment {segment}: line {line} is not a valid record")]
    Malformed { segment: String, line: usize },
    #[error("segment {segment}: last line is incomplete (torn write)")]
    TornTail { segment: String },
    #[error("record {seq}: unsupported schema version {v}")]
    UnknownVersion { seq: u64, v: u32 },
    #[error("record {seq}: stored hash does not match its body")]
    HashMismatch { seq: u64 },
    #[error("record {seq}: prev does not match the hash of the record before it")]
    PrevMismatch { seq: u64 },
    #[error("expected record {expected}, found {found}")]
    SeqGap { expected: u64, found: u64 },
    #[error("record {seq}: timestamp goes backwards")]
    TimeReversed { seq: u64 },
    #[error("record {seq}: violates record policy: {why}")]
    Policy { seq: u64, why: String },
    #[error("record {seq}: outcome refers to decision {decision_seq}, which is not an open allowing decision")]
    BadOutcomeRef { seq: u64, decision_seq: u64 },
    #[error("records exist but the HEAD file is missing")]
    HeadMissing,
    #[error("HEAD says record {head_seq} is the tip but the log ends at {tip:?} (truncated or rewritten)")]
    Truncated { head_seq: u64, tip: Option<u64> },
    #[error("HEAD hash does not match record {seq}")]
    HeadHashMismatch { seq: u64 },
    #[error("log ends at {tip} but HEAD is at {head_seq}: more than one unacknowledged record")]
    HeadBehind { head_seq: u64, tip: u64 },
    #[error("the checkpoint does not match the records that follow it")]
    CheckpointMismatch,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("json: {0}")]
    Json(#[source] serde_json::Error),
    #[error("invalid record: {0}")]
    Invalid(String),
    #[error("integrity: {0}")]
    Integrity(#[from] IntegrityError),
    #[error("the records directory {0} is locked by another writer")]
    Locked(PathBuf),
    #[error("the decision log's internal lock is poisoned; refusing to write")]
    Poisoned,
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn io_err(path: impl Into<PathBuf>) -> impl FnOnce(std::io::Error) -> Error {
    let path = path.into();
    move |source| Error::Io { path, source }
}
