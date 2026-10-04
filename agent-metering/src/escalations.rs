//! HUP-S1.5 / US-1.5 AC3: escalation records. One record per escalation the sidecar ran, to a
//! member endpoint or to a registry provider, so the spend and the payment receipt live in
//! metering next to the turn records.
//!
//! Like turn records, these hold **no conversation content**: no prompt, no answer, no endpoint
//! URL, no API key. A registry record keeps the payment facts (asset, payee, base units) and the
//! provider's receipt (settlement transaction, network, payer) exactly as the provider sent it;
//! citrate-core confirms settlement on chain separately and says so in its own ledger.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::day::utc_day_bounds_ms;
use crate::MeteringError;

/// Escalation record schema version.
pub const ESCALATION_RECORD_SCHEMA: u32 = 1;
/// Report schema version.
pub const ESCALATION_REPORT_SCHEMA: u32 = 1;

/// Where the escalation went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationRoute {
    /// A member-added OpenAI-compatible endpoint, priced from the member's price card.
    Endpoint,
    /// A provider listed by the on-chain InferenceRouter, paid with an x402 authorization.
    Registry,
}

/// The unit a charge is counted in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "unit", rename_all = "snake_case")]
pub enum ChargeUnit {
    /// Micro-units of the member's currency (the endpoint price card).
    MicroUsd,
    /// Base units of an on-chain asset.
    BaseUnits { asset: String, network: String },
}

/// The provider's x402 settlement receipt, as the provider claimed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptRecord {
    pub success: bool,
    pub transaction: Option<String>,
    pub network: Option<String>,
    pub payer: Option<String>,
}

/// How the escalation ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationOutcomeKind {
    Answered,
    /// Failed after the request may have reached the provider (it may have been billed).
    FailedMaybeSent,
    /// Failed before anything left the machine.
    FailedNotSent,
}

/// One escalation, measured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationRecord {
    pub schema: u32,
    pub escalation_id: String,
    pub route: EscalationRoute,
    /// The model name sent (endpoint) or the router's model hash (registry).
    pub model: String,
    pub started_unix_ms: u64,
    pub latency_ms: u64,
    pub tokens_in: Option<u64>,
    pub tokens_out: Option<u64>,
    /// The charge as a decimal string (micro-units or base units), `"0"` when nothing was charged.
    pub charged: String,
    pub unit: ChargeUnit,
    /// Registry: the payee the router named.
    pub payee: Option<String>,
    pub receipt: Option<ReceiptRecord>,
    pub outcome: EscalationOutcomeKind,
}

/// A local, append-only JSONL log of escalation records (`escalations.jsonl`).
#[derive(Debug, Clone)]
pub struct EscalationLog {
    path: PathBuf,
}

impl EscalationLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        EscalationLog { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record (creates the file and its parent directories on first use).
    pub fn append(&self, rec: &EscalationRecord) -> Result<(), MeteringError> {
        let mut line =
            serde_json::to_string(rec).map_err(|e| MeteringError::Serialize(e.to_string()))?;
        line.push('\n');
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
        f.write_all(line.as_bytes())
            .map_err(|e| MeteringError::Io(e.to_string()))
    }

    /// Every record in order. A missing file is an empty log; a bad line is an error naming it.
    pub fn read_all(&self) -> Result<Vec<EscalationRecord>, MeteringError> {
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
            let rec = serde_json::from_str(&line).map_err(|e| MeteringError::Parse {
                line: i + 1,
                msg: e.to_string(),
            })?;
            out.push(rec);
        }
        Ok(out)
    }
}

/// One UTC day of escalations: counts, spend per unit, and every registry receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EscalationReport {
    pub schema: u32,
    pub day: String,
    pub total: u32,
    pub answered: u32,
    pub failed_maybe_sent: u32,
    pub failed_not_sent: u32,
    pub endpoint: u32,
    pub registry: u32,
    /// Endpoint spend, micro-USD.
    pub micro_usd_charged: u64,
    /// Registry spend per `network/asset`, base units as decimal strings.
    pub base_units_charged: BTreeMap<String, String>,
    /// Registry records whose provider sent no successful receipt.
    pub registry_without_receipt: u32,
    /// `(escalation id, receipt)` for every registry escalation that has one, in record order.
    pub receipts: Vec<(String, ReceiptRecord)>,
}

impl EscalationReport {
    /// Aggregate the records that started on `day` (`YYYY-MM-DD`, UTC). Sums saturate rather than
    /// wrap.
    pub fn build(day: &str, records: &[EscalationRecord]) -> Result<Self, MeteringError> {
        let (start, end) = utc_day_bounds_ms(day)?;
        let mut r = EscalationReport {
            schema: ESCALATION_REPORT_SCHEMA,
            day: day.to_string(),
            total: 0,
            answered: 0,
            failed_maybe_sent: 0,
            failed_not_sent: 0,
            endpoint: 0,
            registry: 0,
            micro_usd_charged: 0,
            base_units_charged: BTreeMap::new(),
            registry_without_receipt: 0,
            receipts: Vec::new(),
        };
        let mut sums: BTreeMap<String, u128> = BTreeMap::new();
        for rec in records
            .iter()
            .filter(|x| x.started_unix_ms >= start && x.started_unix_ms < end)
        {
            r.total = r.total.saturating_add(1);
            match rec.outcome {
                EscalationOutcomeKind::Answered => r.answered = r.answered.saturating_add(1),
                EscalationOutcomeKind::FailedMaybeSent => {
                    r.failed_maybe_sent = r.failed_maybe_sent.saturating_add(1)
                }
                EscalationOutcomeKind::FailedNotSent => {
                    r.failed_not_sent = r.failed_not_sent.saturating_add(1)
                }
            }
            match rec.route {
                EscalationRoute::Endpoint => r.endpoint = r.endpoint.saturating_add(1),
                EscalationRoute::Registry => {
                    r.registry = r.registry.saturating_add(1);
                    match &rec.receipt {
                        Some(rc) if rc.success => {
                            r.receipts.push((rec.escalation_id.clone(), rc.clone()))
                        }
                        _ => r.registry_without_receipt = r.registry_without_receipt.saturating_add(1),
                    }
                }
            }
            match &rec.unit {
                ChargeUnit::MicroUsd => {
                    let c = rec.charged.parse::<u64>().unwrap_or(0);
                    r.micro_usd_charged = r.micro_usd_charged.saturating_add(c);
                }
                ChargeUnit::BaseUnits { asset, network } => {
                    let c = rec.charged.parse::<u128>().unwrap_or(0);
                    let k = format!("{network}/{asset}");
                    let e = sums.entry(k).or_insert(0);
                    *e = e.saturating_add(c);
                }
            }
        }
        r.base_units_charged = sums.into_iter().map(|(k, v)| (k, v.to_string())).collect();
        Ok(r)
    }
}
