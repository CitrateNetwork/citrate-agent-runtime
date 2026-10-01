//! # citrate-agent-trajectory: verified, redacted training data (HUP-S9.3)
//!
//! US-9.1 AC1: federated-learning workers train on **verified** Hermes trajectories only, redacted.
//!
//! - [`TrajectoryRecorder`] wraps a session's event sink, forwards every event unchanged, and
//!   remembers per loop turn how it ended and what the workflow verifiers said, plus whether the
//!   session was ever tainted. [`TrajectoryRecorder::trajectories`] pairs that with the session
//!   history to yield one [`TurnTrajectory`] per turn.
//! - [`export_verified`] keeps only turns that ended in an answer and passed every verifier
//!   (D-22: the model's own claim never counts), drops every turn of a session that read
//!   untrusted content unless the [`ExportPolicy`] explicitly allows it with a reason, and
//!   redacts what it keeps.
//! - Redaction ([`Redactor`]) is on by default and cannot be turned off: private keys and
//!   provider tokens, `password=`-style values, bearer/basic credentials, BIP-39 seed phrases,
//!   absolute paths outside granted roots (paths inside become `[root:N]/...`), wallet addresses
//!   not on the allow list, and email addresses. The [`RedactionReport`] counts what was removed
//!   and never contains a removed value.
//!
//! The output is a local JSONL file in OpenAI chat fine-tuning shape. Nothing here uploads it;
//! D-29 requires the member's consent per training round before any trajectory is shared.
//!
//! Not wired into sidecar sessions yet: this crate is the library half.

use thiserror::Error;

mod export;
mod policy;
mod recorder;
mod redact;

pub use export::{
    export_verified, ExampleFunction, ExampleMessage, ExampleMeta, ExampleToolCall,
    ExclusionCounts, RedactionReport, TrainingExample, TrainingExport,
};
pub use policy::ExportPolicy;
pub use recorder::{Eligibility, TrajectoryRecorder, TurnTrajectory, VerifierVerdict};
pub use redact::{
    bip39_english_wordlist, Category, RedactionCounts, Redactor, SEED_PHRASE_MIN_WORDS,
};

/// Everything that can go wrong. Messages never carry trajectory content.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrajectoryError {
    #[error("trajectory export I/O failed: {0}")]
    Io(String),
    #[error("could not serialize the training set: {0}")]
    Serialize(String),
    #[error("a redaction pattern failed to compile: {0}")]
    Pattern(String),
    #[error(
        "the history ({segments} user turns) does not line up with the {turns} recorded turns"
    )]
    Misaligned { turns: usize, segments: usize },
    #[error("allowing tainted sessions needs a reason")]
    EmptyReason,
}
