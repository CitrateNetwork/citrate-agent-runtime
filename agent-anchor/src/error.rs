//! Errors.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("decision records: {0}")]
    Records(#[from] citrate_agent_records::Error),
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("json: {0}")]
    Json(#[source] serde_json::Error),
    #[error("the anchor ledger {0} is locked by another writer")]
    Locked(PathBuf),
    #[error("day {day} is not over yet (today is day {today}); only closed days are batched")]
    DayNotClosed { day: u64, today: u64 },
    #[error("day {day}: expected record {expected}, found {found}")]
    SeqGap { day: u64, expected: u64, found: u64 },
    #[error("day {day} was already batched with a different root; the records changed since")]
    Conflict { day: u64 },
    #[error("day {day} claims records already batched under day {other}")]
    Overlap { day: u64, other: u64 },
    #[error("day {day} has no batch in the anchor ledger")]
    NotBatched { day: u64 },
    #[error("records of day {day} were pruned; its tree can no longer be rebuilt")]
    PrunedDay { day: u64 },
    #[error("malformed anchor calldata: {0}")]
    BadCalldata(String),
    #[error("unexpected AnchorRegistry answer: {0}")]
    Registry(String),
    #[error("the anchor ledger is corrupt: {0}")]
    Corrupt(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn io_err(path: impl Into<PathBuf>) -> impl FnOnce(std::io::Error) -> Error {
    let path = path.into();
    move |source| Error::Io { path, source }
}
