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
//! - D-27 measures (HUP-S7.5, US-7.3 AC1) on each record: time to first token and generation time
//!   from the model server's own timings, CPU/GPU/RAM peaks from a host-supplied
//!   [`ResourceSampler`], an energy figure labelled "estimate", and the model's self-review claim
//!   labelled "opinion". [`ChainReceipt`] / [`ChainSpendSummary`] carry SALT spent and gas from the
//!   receipts of Hermes's chain transactions (reported by citrate-core, which signs them).
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
//! The sidecar wires this into every session (`agent-sidecar/src/metering.rs`); citrate-core shows
//! the daily report in the Journal and signs any on-chain sharing.

use thiserror::Error;

mod benchmark;
mod chain_receipts;
mod clock;
mod day;
mod decisions;
mod escalations;
mod log;
mod measures;
mod record;
mod report;
mod sink;

pub use benchmark::{
    build_benchmark_payload, build_benchmark_payload_with, hermes_capsule_id, metric_name_hash,
    record_selector, BenchmarkCall, BenchmarkOptIn, BenchmarkPayload, BENCHMARK_RECORD_SIGNATURE,
    CITRATE_CHAIN_ID, HERMES_CAPSULE_LABEL, METRICS,
};
pub use chain_receipts::{
    format_salt, ChainPurpose, ChainReceipt, ChainReceiptLog, ChainSpendSummary,
    CHAIN_RECEIPT_SCHEMA,
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
pub use measures::{
    tokens_per_s_milli, EnergyEstimate, EnergyModel, Generation, ResourcePeaks, ResourceSample,
    ResourceSampler, SelfReview, SelfReviewClaim, TurnSampling, BPS_WHOLE, DEFAULT_ENERGY_MODEL,
    ENERGY_ESTIMATE_LABEL, SELF_REVIEW_OPINION,
};
pub use record::{
    ToolTally, TurnOutcome, TurnRecord, Verification, VerifierOutcome, RECORD_SCHEMA,
};
pub use report::{
    DailyReport, EnergyTotals, LatencyStats, OutcomeCounts, PassFail, ResourceTotals,
    SelfReviewCounts, SpeedTotals, TokenTotals, VerificationCounts, REPORT_SCHEMA,
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
    #[error("not a valid chain receipt: {0}")]
    InvalidReceipt(String),
}
