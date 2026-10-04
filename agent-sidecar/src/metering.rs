//! HUP-S7.5 (runtime, sidecar wiring): every session meters itself.
//!
//! - Each session wraps its event sink in a [`MeteringSink`] (records derived from the loop's
//!   event stream, no conversation content) and its model client in a [`MeteredLlm`], so token
//!   usage the provider reports lands on the turn it belongs to. A provider that reports no usage
//!   leaves tokens unknown, never zero.
//! - Finished turns go to a [`MeteringStore`]: the local JSONL log under
//!   `CITRATE_HERMES_METERING_DIR` when citrate-core configures one, otherwise a bounded in-memory
//!   list that lasts as long as the sidecar process (the report says which).
//! - `GET /metering/daily?day=YYYY-MM-DD` serves the day's [`DailyReport`] plus the D-27 measures
//!   this build does not collect yet, named so a surface can show them as unknown.
//! - `POST /metering/benchmark` builds the opt-in BenchmarkRegistry calldata for a day. It builds
//!   bytes only: no key, no signing, no network (Rule 3). Submitting is citrate-core's ceremony.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use citrate_agent_loop::{
    AssistantTurn, CompletionRequest, Event, EventSink, LlmClient, LlmError, TokenUsage,
};
use citrate_agent_metering::{
    DailyReport, EscalationLog, EscalationReceipt, EscalationSummary, MeteringError, MeteringLog,
    MeteringSink, TurnRecord,
};
use serde::Serialize;

/// Directory for the metering log (set by citrate-core). Unset: records are kept in memory only.
pub const METERING_DIR_ENV: &str = "CITRATE_HERMES_METERING_DIR";
/// The log file inside that directory.
pub const METERING_LOG_FILE: &str = "metering.jsonl";
/// The escalation receipt log inside that directory (HUP-S1.5, US-1.5 AC3).
pub const ESCALATION_LOG_FILE: &str = "escalations.jsonl";
/// Records kept in memory when there is no log (oldest dropped first).
pub const MEMORY_CAP: usize = 10_000;

/// D-27 measures this build does not collect. A surface shows each as unknown.
pub const NOT_MEASURED: &[&str] = &[
    "time to first token",
    "tokens per second",
    "SALT spent",
    "gas",
    "CPU, GPU and RAM peak",
    "energy estimate",
    "self-review",
];

/// Where finished turn records and escalation receipts live.
pub struct MeteringStore {
    log: Option<MeteringLog>,
    memory: Mutex<VecDeque<TurnRecord>>,
    escalations: Option<EscalationLog>,
    escalation_memory: Mutex<VecDeque<EscalationReceipt>>,
}

impl MeteringStore {
    /// Records kept only for the life of this process.
    pub fn in_memory() -> Self {
        MeteringStore {
            log: None,
            memory: Mutex::new(VecDeque::new()),
            escalations: None,
            escalation_memory: Mutex::new(VecDeque::new()),
        }
    }

    /// Records appended to `<dir>/metering.jsonl` (created on first use).
    pub fn persistent(dir: &Path) -> Self {
        MeteringStore {
            log: Some(MeteringLog::new(dir.join(METERING_LOG_FILE))),
            memory: Mutex::new(VecDeque::new()),
            escalations: Some(EscalationLog::new(dir.join(ESCALATION_LOG_FILE))),
            escalation_memory: Mutex::new(VecDeque::new()),
        }
    }

    /// `"log"` when records are written to disk, `"memory"` otherwise.
    pub fn source(&self) -> &'static str {
        if self.log.is_some() {
            "log"
        } else {
            "memory"
        }
    }

    fn memory(&self) -> std::sync::MutexGuard<'_, VecDeque<TurnRecord>> {
        match self.memory.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    fn remember(&self, rec: TurnRecord) {
        let mut m = self.memory();
        m.push_back(rec);
        while m.len() > MEMORY_CAP {
            m.pop_front();
        }
    }

    /// Keep these records. A record the log cannot take is kept in memory instead (and the
    /// failure is logged to stderr without content), so a full disk loses durability, not data.
    pub fn append(&self, records: Vec<TurnRecord>) {
        for rec in records {
            match &self.log {
                Some(log) => {
                    if let Err(e) = log.append(&rec) {
                        eprintln!("citrate-agent-sidecar: metering log write failed: {e}");
                        self.remember(rec);
                    }
                }
                None => self.remember(rec),
            }
        }
    }

    /// Every record: the log's, then any held in memory.
    pub fn records(&self) -> Result<Vec<TurnRecord>, MeteringError> {
        let mut out = match &self.log {
            Some(log) => log.read_all()?,
            None => Vec::new(),
        };
        out.extend(self.memory().iter().cloned());
        Ok(out)
    }

    fn escalation_memory(&self) -> std::sync::MutexGuard<'_, VecDeque<EscalationReceipt>> {
        match self.escalation_memory.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Keep one escalation receipt. A receipt the log cannot take is kept in memory instead (the
    /// failure is logged to stderr without content).
    pub fn append_escalation(&self, rec: EscalationReceipt) {
        let keep = match &self.escalations {
            Some(log) => match log.append(&rec) {
                Ok(()) => None,
                Err(e) => {
                    eprintln!("citrate-agent-sidecar: escalation receipt write failed: {e}");
                    Some(rec)
                }
            },
            None => Some(rec),
        };
        if let Some(rec) = keep {
            let mut m = self.escalation_memory();
            m.push_back(rec);
            while m.len() > MEMORY_CAP {
                m.pop_front();
            }
        }
    }

    /// Every escalation receipt: the log's, then any held in memory.
    pub fn escalation_receipts(&self) -> Result<Vec<EscalationReceipt>, MeteringError> {
        let mut out = match &self.escalations {
            Some(log) => log.read_all()?,
            None => Vec::new(),
        };
        out.extend(self.escalation_memory().iter().cloned());
        Ok(out)
    }

    /// The daily report for `day` (`YYYY-MM-DD`, UTC), with the day's escalation receipts.
    pub fn daily(&self, day: &str) -> Result<DailyResponse, MeteringError> {
        let report = DailyReport::build(day, &self.records()?)?;
        let escalations = EscalationSummary::build(day, &self.escalation_receipts()?)?;
        Ok(DailyResponse {
            day: day.to_string(),
            source: self.source(),
            persisted: self.log.is_some(),
            markdown: format!("{}{}", report.to_markdown(), escalations.to_markdown()),
            report,
            escalations,
            not_measured: NOT_MEASURED.to_vec(),
        })
    }
}

/// `GET /metering/daily` body.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DailyResponse {
    pub day: String,
    /// `"log"` or `"memory"`.
    pub source: &'static str,
    /// Whether the records behind this report survive a sidecar restart.
    pub persisted: bool,
    pub report: DailyReport,
    /// The day's escalation receipts, summed (HUP-S1.5, US-1.5 AC3).
    pub escalations: EscalationSummary,
    pub markdown: String,
    /// D-27 measures not collected by this build (show as unknown).
    pub not_measured: Vec<&'static str>,
}

/// The store named by `CITRATE_HERMES_METERING_DIR` (an absolute path), else in memory.
pub fn metering_from_value(value: Option<&str>) -> MeteringStore {
    match value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
    {
        Some(dir) if dir.is_absolute() => MeteringStore::persistent(&dir),
        Some(_) => {
            eprintln!(
                "citrate-agent-sidecar: {METERING_DIR_ENV} must be an absolute path; metering stays in memory"
            );
            MeteringStore::in_memory()
        }
        None => MeteringStore::in_memory(),
    }
}

/// [`metering_from_value`] over the process environment.
pub fn metering_from_env() -> Arc<MeteringStore> {
    Arc::new(metering_from_value(
        std::env::var(METERING_DIR_ENV).ok().as_deref(),
    ))
}

/// A model client that reports the provider's token usage to the session's metering sink.
pub struct MeteredLlm {
    inner: Arc<dyn LlmClient>,
    sink: Arc<MeteringSink>,
}

impl MeteredLlm {
    pub fn new(inner: Arc<dyn LlmClient>, sink: Arc<MeteringSink>) -> Self {
        MeteredLlm { inner, sink }
    }
}

impl LlmClient for MeteredLlm {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        self.complete_with_usage(req).map(|(t, _)| t)
    }

    fn complete_with_usage(
        &self,
        req: &CompletionRequest,
    ) -> Result<(AssistantTurn, Option<TokenUsage>), LlmError> {
        let (turn, usage) = self.inner.complete_with_usage(req)?;
        if let Some(u) = usage {
            self.sink.record_usage(u.prompt_tokens, u.completion_tokens);
        }
        Ok((turn, usage))
    }
}

/// Fans each event out to observers (metering, trajectories) and then to the session's own log.
pub(crate) struct TeeSink<'a> {
    pub observers: Vec<&'a dyn EventSink>,
    pub last: &'a dyn EventSink,
}

impl EventSink for TeeSink<'_> {
    fn emit(&self, ev: Event) {
        for o in &self.observers {
            o.emit(ev.clone());
        }
        self.last.emit(ev);
    }
}
