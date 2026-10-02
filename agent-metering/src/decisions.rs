//! HUP-S5.3 AC3: the `decide()` slot's metering. One log of content-free decision records and
//! task outcomes, and a per-backend report: decisions, errors by kind, latency, mean confidence,
//! bytes sent off-machine, and task success rate (e.g. on the WebVoyager-style subset).

use crate::report::{nearest_rank, LatencyStats};
use crate::MeteringError;
use citrate_agent_loop::decide::{BackendKind, DecisionRecord};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// Decision report schema version.
pub const DECISION_REPORT_SCHEMA: u32 = 1;

fn slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// One task attempted with one backend. `suite` and `task_id` are fixture slugs, never content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskRecord {
    pub at_unix_ms: u64,
    pub backend: BackendKind,
    pub suite: String,
    pub task_id: String,
    pub success: bool,
}

impl TaskRecord {
    pub fn new(
        at_unix_ms: u64,
        backend: BackendKind,
        suite: &str,
        task_id: &str,
        success: bool,
    ) -> Result<Self, String> {
        if !slug(suite) || !slug(task_id) {
            return Err(
                "suite and task id must be 1-64 ASCII letters, digits, '-', '_' or '.'".into(),
            );
        }
        Ok(TaskRecord {
            at_unix_ms,
            backend,
            suite: suite.to_string(),
            task_id: task_id.to_string(),
            success,
        })
    }
}

/// One line of the decision log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum DecisionLine {
    Decision(DecisionRecord),
    Task(TaskRecord),
}

/// A local append-only JSONL file of [`DecisionLine`]s.
#[derive(Debug, Clone)]
pub struct DecisionLog {
    path: PathBuf,
}

impl DecisionLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        DecisionLog { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, line: &DecisionLine) -> Result<(), MeteringError> {
        let mut text =
            serde_json::to_string(line).map_err(|e| MeteringError::Serialize(e.to_string()))?;
        text.push('\n');
        if let Some(dir) = self.path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).map_err(|e| MeteringError::Io(e.to_string()))?;
            }
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| MeteringError::Io(e.to_string()))?;
        f.write_all(text.as_bytes())
            .map_err(|e| MeteringError::Io(e.to_string()))
    }

    /// Every line in order; a missing file is empty, a bad line is an error naming it (1-based).
    pub fn read_all(&self) -> Result<Vec<DecisionLine>, MeteringError> {
        let f = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(MeteringError::Io(e.to_string())),
        };
        let mut out = Vec::new();
        for (i, line) in BufReader::new(f).lines().enumerate() {
            let line = line.map_err(|e| MeteringError::Io(e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            out.push(
                serde_json::from_str(&line).map_err(|e| MeteringError::Parse {
                    line: i + 1,
                    msg: e.to_string(),
                })?,
            );
        }
        Ok(out)
    }
}

/// One backend's numbers.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BackendStats {
    pub decisions: u32,
    pub errors: u32,
    pub errors_by_kind: BTreeMap<String, u32>,
    /// Over successful decisions; `None` when there were none.
    pub latency_ms: Option<LatencyStats>,
    /// Mean confidence over decisions that reported one.
    pub mean_confidence: Option<f64>,
    /// Bytes sent off-machine (Jev request bodies).
    pub egress_bytes: u64,
    pub tasks_attempted: u32,
    pub tasks_succeeded: u32,
    /// succeeded / attempted in basis points; `None` when no task was attempted.
    pub task_success_bps: Option<u32>,
}

/// Per-backend decision metering.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionReport {
    pub schema: u32,
    /// Keyed by backend name (`local`, `jev`).
    pub backends: BTreeMap<String, BackendStats>,
}

impl DecisionReport {
    pub fn build(lines: &[DecisionLine]) -> Self {
        let mut stats: BTreeMap<String, BackendStats> = BTreeMap::new();
        let mut latencies: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        let mut confidences: BTreeMap<String, Vec<f64>> = BTreeMap::new();
        for line in lines {
            match line {
                DecisionLine::Decision(d) => {
                    let key = d.backend.as_str().to_string();
                    let s = stats.entry(key.clone()).or_default();
                    s.decisions = s.decisions.saturating_add(1);
                    if d.ok {
                        latencies.entry(key.clone()).or_default().push(d.latency_ms);
                        if let Some(c) = d.confidence.filter(|c| c.is_finite()) {
                            confidences.entry(key).or_default().push(c);
                        }
                        s.egress_bytes = s
                            .egress_bytes
                            .saturating_add(d.egress_bytes.unwrap_or(0) as u64);
                    } else {
                        s.errors = s.errors.saturating_add(1);
                        let kind = d.error.clone().unwrap_or_else(|| "unknown".into());
                        let e = s.errors_by_kind.entry(kind).or_insert(0);
                        *e = e.saturating_add(1);
                    }
                }
                DecisionLine::Task(t) => {
                    let s = stats.entry(t.backend.as_str().to_string()).or_default();
                    s.tasks_attempted = s.tasks_attempted.saturating_add(1);
                    if t.success {
                        s.tasks_succeeded = s.tasks_succeeded.saturating_add(1);
                    }
                }
            }
        }
        for (k, s) in stats.iter_mut() {
            if let Some(l) = latencies.get_mut(k) {
                l.sort_unstable();
                s.latency_ms = Some(LatencyStats {
                    p50: nearest_rank(l, 50),
                    p95: nearest_rank(l, 95),
                    max: l.last().copied().unwrap_or(0),
                });
            }
            if let Some(c) = confidences.get(k).filter(|c| !c.is_empty()) {
                s.mean_confidence = Some(c.iter().sum::<f64>() / c.len() as f64);
            }
            if s.tasks_attempted > 0 {
                let bps = u64::from(s.tasks_succeeded) * 10_000 / u64::from(s.tasks_attempted);
                s.task_success_bps = Some(u32::try_from(bps).unwrap_or(10_000));
            }
        }
        DecisionReport {
            schema: DECISION_REPORT_SCHEMA,
            backends: stats,
        }
    }

    /// A markdown table for the journal and the activity monitor.
    pub fn to_markdown(&self) -> String {
        if self.backends.is_empty() {
            return "No decisions recorded.\n".into();
        }
        let mut md = String::from(
            "| backend | decisions | errors | p50 ms | p95 ms | mean confidence | sent off-machine | tasks | task success |\n|---|---|---|---|---|---|---|---|---|\n",
        );
        for (k, s) in &self.backends {
            let (p50, p95) = s
                .latency_ms
                .as_ref()
                .map(|l| (l.p50.to_string(), l.p95.to_string()))
                .unwrap_or_else(|| ("-".into(), "-".into()));
            let conf = s
                .mean_confidence
                .map(|c| format!("{c:.2}"))
                .unwrap_or_else(|| "-".into());
            let rate = s
                .task_success_bps
                .map(|b| format!("{}.{:02}%", b / 100, b % 100))
                .unwrap_or_else(|| "-".into());
            md.push_str(&format!(
                "| {k} | {} | {} | {p50} | {p95} | {conf} | {} B | {} | {rate} |\n",
                s.decisions, s.errors, s.egress_bytes, s.tasks_attempted
            ));
        }
        md
    }
}
