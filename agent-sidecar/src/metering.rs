//! HUP-S7.5 (runtime, sidecar wiring): every session meters itself.
//!
//! - Each session wraps its event sink in a [`MeteringSink`] (records derived from the loop's
//!   event stream, no conversation content) and its model client in a [`MeteredLlm`], so token
//!   usage the provider reports lands on the turn it belongs to. A provider that reports no usage
//!   leaves tokens unknown, never zero.
//! - Finished turns go to a [`MeteringStore`]: the local JSONL log under
//!   `CITRATE_HERMES_METERING_DIR` when citrate-core configures one, otherwise a bounded in-memory
//!   list that lasts as long as the sidecar process (the report says which).
//! - `GET /metering/daily?day=YYYY-MM-DD` serves the day's [`DailyReport`] (with the D-27 measures:
//!   time to first token, tokens per second, CPU/GPU/RAM peaks, the energy estimate and the
//!   self-review opinions), the day's escalation receipts and its chain spend.
//! - D-27 resource peaks come from [`crate::resources::SystemSampler`], one sampling per turn.
//! - `POST /metering/chain-receipt` takes one mined Hermes transaction from citrate-core (which
//!   signed it): hash, purpose, status, gas used, gas price and value. Public facts only; it is how
//!   SALT spent and gas reach the report.
//! - `POST /metering/benchmark` builds the opt-in BenchmarkRegistry calldata for a day. It builds
//!   bytes only: no key, no signing, no network (Rule 3). Submitting is citrate-core's ceremony.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use citrate_agent_loop::{
    AssistantTurn, CompletionRequest, Event, EventSink, LlmClient, LlmError, TokenUsage,
};
use citrate_agent_metering::{
    ChainReceipt, ChainReceiptLog, ChainSpendSummary, DailyReport, EnergyModel, EscalationLog,
    EscalationReceipt, EscalationSummary, MeteringError, MeteringLog, MeteringSink,
    ResourceSampler, TurnRecord, DEFAULT_ENERGY_MODEL,
};
use serde::Serialize;

/// Directory for the metering log (set by citrate-core). Unset: records are kept in memory only.
pub const METERING_DIR_ENV: &str = "CITRATE_HERMES_METERING_DIR";
/// The log file inside that directory.
pub const METERING_LOG_FILE: &str = "metering.jsonl";
/// The escalation receipt log inside that directory (HUP-S1.5, US-1.5 AC3).
pub const ESCALATION_LOG_FILE: &str = "escalations.jsonl";
/// The chain receipt log inside that directory (HUP-S7.5, D-27: SALT spent and gas).
pub const CHAIN_LOG_FILE: &str = "chain_receipts.jsonl";
/// Records kept in memory when there is no log (oldest dropped first).
pub const MEMORY_CAP: usize = 10_000;

/// D-27 measures this build does not collect. Every D-27 measure is collected now (HUP-S7.5), so
/// the list is empty; the field stays for surfaces built against the earlier report. A measure no
/// turn reported on a given day is `null` in the report and shown as unknown.
pub const NOT_MEASURED: &[&str] = &[];

/// Where finished turn records and escalation receipts live.
pub struct MeteringStore {
    log: Option<MeteringLog>,
    memory: Mutex<VecDeque<TurnRecord>>,
    escalations: Option<EscalationLog>,
    escalation_memory: Mutex<VecDeque<EscalationReceipt>>,
    chain: Option<ChainReceiptLog>,
    chain_memory: Mutex<VecDeque<ChainReceipt>>,
    /// D-27: samples the machine during each turn (`None`: peaks and energy stay unknown).
    sampler: Option<Arc<dyn ResourceSampler>>,
    energy: EnergyModel,
}

impl MeteringStore {
    /// Records kept only for the life of this process.
    pub fn in_memory() -> Self {
        MeteringStore {
            log: None,
            memory: Mutex::new(VecDeque::new()),
            escalations: None,
            escalation_memory: Mutex::new(VecDeque::new()),
            chain: None,
            chain_memory: Mutex::new(VecDeque::new()),
            sampler: None,
            energy: DEFAULT_ENERGY_MODEL,
        }
    }

    /// Records appended to `<dir>/metering.jsonl` (created on first use).
    pub fn persistent(dir: &Path) -> Self {
        MeteringStore {
            log: Some(MeteringLog::new(dir.join(METERING_LOG_FILE))),
            memory: Mutex::new(VecDeque::new()),
            escalations: Some(EscalationLog::new(dir.join(ESCALATION_LOG_FILE))),
            escalation_memory: Mutex::new(VecDeque::new()),
            chain: Some(ChainReceiptLog::new(dir.join(CHAIN_LOG_FILE))),
            chain_memory: Mutex::new(VecDeque::new()),
            sampler: None,
            energy: DEFAULT_ENERGY_MODEL,
        }
    }

    /// D-27: sample the machine during each turn, and estimate energy with `energy` (builder).
    pub fn with_measures(
        mut self,
        sampler: Option<Arc<dyn ResourceSampler>>,
        energy: EnergyModel,
    ) -> Self {
        self.sampler = sampler;
        self.energy = energy;
        self
    }

    /// A session's metering sink, with this store's sampler and energy model attached.
    pub fn sink(
        &self,
        session_id: impl Into<String>,
        model: impl Into<String>,
        known_tools: impl IntoIterator<Item = String>,
        clock: Arc<dyn citrate_agent_metering::Clock>,
    ) -> MeteringSink {
        let sink =
            MeteringSink::new(session_id, model, known_tools, clock).with_energy_model(self.energy);
        match &self.sampler {
            Some(s) => sink.sampling_with(s.clone()),
            None => sink,
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

    fn chain_memory(&self) -> std::sync::MutexGuard<'_, VecDeque<ChainReceipt>> {
        match self.chain_memory.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Keep one chain receipt (D-27). A malformed receipt is refused; one the log cannot take is
    /// kept in memory instead (the failure is logged to stderr without content).
    pub fn append_chain_receipt(&self, rec: ChainReceipt) -> Result<(), MeteringError> {
        rec.validate()?;
        let keep = match &self.chain {
            Some(log) => match log.append(&rec) {
                Ok(()) => None,
                Err(e) => {
                    eprintln!("citrate-agent-sidecar: chain receipt write failed: {e}");
                    Some(rec)
                }
            },
            None => Some(rec),
        };
        if let Some(rec) = keep {
            let mut m = self.chain_memory();
            m.push_back(rec);
            while m.len() > MEMORY_CAP {
                m.pop_front();
            }
        }
        Ok(())
    }

    /// Every chain receipt: the log's, then any held in memory.
    pub fn chain_receipts(&self) -> Result<Vec<ChainReceipt>, MeteringError> {
        let mut out = match &self.chain {
            Some(log) => log.read_all()?,
            None => Vec::new(),
        };
        out.extend(self.chain_memory().iter().cloned());
        Ok(out)
    }

    /// The daily report for `day` (`YYYY-MM-DD`, UTC), with the day's escalation receipts and its
    /// chain spend.
    pub fn daily(&self, day: &str) -> Result<DailyResponse, MeteringError> {
        let report = DailyReport::build(day, &self.records()?)?;
        let escalations = EscalationSummary::build(day, &self.escalation_receipts()?)?;
        let chain = ChainSpendSummary::build(day, &self.chain_receipts()?)?;
        Ok(DailyResponse {
            day: day.to_string(),
            source: self.source(),
            persisted: self.log.is_some(),
            markdown: format!(
                "{}{}{}",
                report.to_markdown(),
                escalations.to_markdown(),
                chain.to_markdown()
            ),
            report,
            escalations,
            chain,
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
    /// D-27: the day's Hermes transactions on chain: gas used and SALT spent.
    pub chain: ChainSpendSummary,
    pub markdown: String,
    /// D-27 measures not collected by this build (empty now; kept for older surfaces).
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

/// [`metering_from_value`] over the process environment, with the D-27 machine sampler (unless
/// `CITRATE_HERMES_RESOURCE_SAMPLING` turns it off) and the energy model it names.
pub fn metering_from_env() -> Arc<MeteringStore> {
    Arc::new(
        metering_from_value(std::env::var(METERING_DIR_ENV).ok().as_deref()).with_measures(
            crate::resources::SystemSampler::from_env(),
            crate::resources::energy_model_from_value(
                std::env::var(crate::resources::ENERGY_WATTS_ENV)
                    .ok()
                    .as_deref(),
            ),
        ),
    )
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
        if let Some(u) = &usage {
            self.sink.record_model_call(u);
        }
        Ok((turn, usage))
    }

    /// HUP-S1.1 (g1-render): streamed answers are metered exactly like whole ones.
    fn complete_streaming(
        &self,
        req: &CompletionRequest,
        on_delta: &mut dyn FnMut(&str),
    ) -> Result<(AssistantTurn, Option<TokenUsage>), LlmError> {
        let (turn, usage) = self.inner.complete_streaming(req, on_delta)?;
        if let Some(u) = &usage {
            self.sink.record_model_call(u);
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
