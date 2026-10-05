//! The per-turn metering record.

use crate::measures::{EnergyEstimate, Generation, ResourcePeaks, SelfReview};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Record schema version. Version 2 (HUP-S7.5, D-27) adds the optional measures (time to first
/// token, generation, resource peaks, energy estimate, self-review). A version 1 line still reads:
/// every added field defaults to unknown.
pub const RECORD_SCHEMA: u32 = 2;

/// How the loop ended a turn (the loop's own `done` label). `Answered` means the model produced a
/// final message, not that the task succeeded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnOutcome {
    Answered,
    Stopped,
    StepLimit,
    Failed,
    /// A `done` label this version does not know.
    Unknown,
}

impl TurnOutcome {
    pub(crate) fn from_label(label: &str) -> Self {
        match label {
            "answered" => TurnOutcome::Answered,
            "stopped" => TurnOutcome::Stopped,
            "step_limit" => TurnOutcome::StepLimit,
            "failed" => TurnOutcome::Failed,
            _ => TurnOutcome::Unknown,
        }
    }
}

/// Per-tool counts within a turn (or a day). `calls` counts every call the model proposed;
/// the status counts come from the loop's `tool_result` events.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolTally {
    pub calls: u32,
    pub ok: u32,
    pub denied: u32,
    pub error: u32,
    /// Calls that needed a member's explicit decision because the session was tainted.
    pub hic_required: u32,
}

impl ToolTally {
    pub(crate) fn add(&mut self, o: &ToolTally) {
        self.calls = self.calls.saturating_add(o.calls);
        self.ok = self.ok.saturating_add(o.ok);
        self.denied = self.denied.saturating_add(o.denied);
        self.error = self.error.saturating_add(o.error);
        self.hic_required = self.hic_required.saturating_add(o.hic_required);
    }
}

/// One verifier's verdict on the turn (a workflow step attempt). The verifier's failure detail is
/// deliberately not kept: it can quote the answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierOutcome {
    pub step: String,
    pub name: String,
    pub passed: bool,
}

/// Whether verifiers judged a turn, and how.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    /// At least one verifier ran and every one passed.
    Passed,
    /// At least one verifier failed.
    Failed,
    /// No verifier judged this turn. Not a success and not a failure.
    Unverified,
}

/// One loop turn, measured. Holds no conversation content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnRecord {
    pub schema: u32,
    pub session_id: String,
    /// 1-based turn number within the sink's session.
    pub turn: u32,
    pub model: String,
    /// Wall-clock start (first event of the turn), Unix ms UTC.
    pub started_unix_ms: u64,
    /// Monotonic time from the turn's first event to its `done` event.
    pub latency_ms: u64,
    /// Prompt tokens summed over the turn's model calls; `None` when the client reported none.
    pub tokens_in: Option<u64>,
    /// Completion tokens summed over the turn's model calls; `None` when unreported.
    pub tokens_out: Option<u64>,
    /// Model steps started in the turn.
    pub steps: u32,
    /// Tool calls by registered tool name (model-invented names are pooled under `(unknown tool)`).
    pub tool_calls: BTreeMap<String, ToolTally>,
    /// The session became tainted during this turn.
    pub tainted: bool,
    pub verifiers: Vec<VerifierOutcome>,
    pub outcome: TurnOutcome,
    /// D-27: the server's time to first token for the turn's first model call (llama-server
    /// `timings.prompt_ms`). `None` when that call did not report it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttft_ms: Option<u64>,
    /// D-27: completion tokens over the server's generation time, for tokens per second. `None`
    /// when no model call of the turn reported a generation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<Generation>,
    /// D-27: CPU, GPU and RAM load sampled while the turn ran. `None` when nothing sampled it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcePeaks>,
    /// D-27: an energy figure, labelled "estimate" (load times nominal watts, not measured).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub energy_estimate: Option<EnergyEstimate>,
    /// D-27: the model's PASS/FAIL claim about this attempt, labelled "opinion". Never a verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_review: Option<SelfReview>,
}

impl TurnRecord {
    /// An empty record (outcome `Unknown` until the turn's `done` event).
    pub fn new(session_id: &str, turn: u32, model: &str, started_unix_ms: u64) -> Self {
        TurnRecord {
            schema: RECORD_SCHEMA,
            session_id: session_id.to_string(),
            turn,
            model: model.to_string(),
            started_unix_ms,
            latency_ms: 0,
            tokens_in: None,
            tokens_out: None,
            steps: 0,
            tool_calls: BTreeMap::new(),
            tainted: false,
            verifiers: Vec::new(),
            outcome: TurnOutcome::Unknown,
            ttft_ms: None,
            generation: None,
            resources: None,
            energy_estimate: None,
            self_review: None,
        }
    }

    /// The verifiers' collective verdict on this turn.
    pub fn verification(&self) -> Verification {
        if self.verifiers.is_empty() {
            Verification::Unverified
        } else if self.verifiers.iter().all(|v| v.passed) {
            Verification::Passed
        } else {
            Verification::Failed
        }
    }

    /// Every tool call proposed in the turn.
    pub fn tool_call_total(&self) -> u32 {
        self.tool_calls
            .values()
            .fold(0u32, |a, t| a.saturating_add(t.calls))
    }
}
