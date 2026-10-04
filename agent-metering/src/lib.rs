//! # citrate-agent-metering: Hermes measures itself (HUP-S7.5, runtime half)
//!
//! Decision D-27 / US-7.3: a metering record per turn, a daily report, and opt-in aggregates for
//! the chain's BenchmarkRegistry.
//!
//! - [`MeteringSink`] is an [`citrate_agent_loop::EventSink`] adapter. It wraps the sink a session
//!   already uses, forwards every event unchanged, and derives one [`TurnRecord`] per loop turn:
//!   model, tokens in/out (only when the model client reports them), latency, steps, tool calls by
//!   name, verifier outcomes, the loop's outcome, and whether the turn tainted the session.
//! - Records hold **no conversation content**: no prompts, answers, tool arguments, tool output,
//!   error text or model-invented tool names.
//! - [`MeteringLog`] is a local append-only JSONL file of records.
//! - [`DailyReport`] aggregates one UTC day into JSON and markdown.
//! - [`EscalationReceipt`] / [`EscalationLog`] / [`EscalationSummary`] (HUP-S1.5, US-1.5 AC3): one
//!   content-free receipt per escalation that may have cost the member money, summed per day.
//! - [`DecisionLog`] / [`DecisionReport`] (HUP-S5.3): the `decide()` slot's content-free decision
//!   records and task outcomes, reported per backend (local, jev) with task success rates.
//! - [`build_benchmark_payload`] turns a report into calldata for
//!   `BenchmarkRegistry.record(uint256,bytes32,bytes32,uint256)`, only for a member who opted in
//!   ([`BenchmarkOptIn`]). It builds calldata and nothing else: no key, no signing, no network
//!   (Rule 3). Submitting goes through citrate-core's SignatureCeremony.
//!
//! Honesty rules carried from the loop: an `answered` turn is **not** a success. Only verifier
//! verdicts make a turn verified; a turn with no verifier is "unverified", counted separately.
//!
//! Not wired into sidecar sessions yet: this crate is the library half. The sidecar wiring, the
//! activity monitor surface and the nightly batch are separate work packages.

use thiserror::Error;

mod benchmark;
mod clock;
mod day;
mod decisions;
mod escalations;
mod log;
mod record;
mod report;
mod sink;

pub use benchmark::{
    build_benchmark_payload, hermes_capsule_id, metric_name_hash, record_selector, BenchmarkCall,
    BenchmarkOptIn, BenchmarkPayload, BENCHMARK_RECORD_SIGNATURE, CITRATE_CHAIN_ID,
    HERMES_CAPSULE_LABEL, METRICS,
};
pub use clock::{Clock, SystemClock};
pub use day::{utc_day_bounds_ms, utc_day_of_ms};
pub use decisions::{
    BackendStats, DecisionLine, DecisionLog, DecisionReport, TaskRecord, DECISION_REPORT_SCHEMA,
};
pub use escalations::{
    EscalationLog, EscalationReceipt, EscalationRoute, EscalationSettlement, EscalationSummary,
    ESCALATION_RECEIPT_SCHEMA,
};
pub use log::MeteringLog;
pub use record::{ToolTally, TurnOutcome, TurnRecord, Verification, VerifierOutcome};
pub use report::{
    DailyReport, LatencyStats, OutcomeCounts, PassFail, TokenTotals, VerificationCounts,
};
pub use sink::{MeteringSink, UNKNOWN_TOOL};

/// Everything that can go wrong in this crate. Messages never carry record content.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MeteringError {
    #[error("metering log I/O failed: {0}")]
    Io(String),
    #[error("metering log line {line} is not a valid record: {msg}")]
    Parse { line: usize, msg: String },
    #[error("could not serialize the metering data: {0}")]
    Serialize(String),
    #[error("not a valid UTC day (expected YYYY-MM-DD): {0:?}")]
    InvalidDay(String),
    #[error("the member has not opted in to sharing benchmark aggregates")]
    NotOptedIn,
    #[error("the report has no turns, so there is nothing to share")]
    EmptyReport,
    #[error("not a usable contract address: {0:?}")]
    InvalidAddress(String),
}
