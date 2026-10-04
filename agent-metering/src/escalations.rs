//! HUP-S1.5 / US-1.5 AC3: escalation receipts in metering.
//!
//! One [`EscalationReceipt`] per escalation that may have cost the member money: a settled request,
//! or one that failed after it may have reached the provider (core keeps that reservation charged,
//! so the receipt does too). A request refused before anything left the machine costs nothing and
//! leaves no receipt.
//!
//! Receipts hold **no content and no destination secrets**: no prompt, answer, endpoint URL or key.
//! They carry core's escalation id (so a receipt joins core's spend ledger), the model name, the
//! provider's reported tokens, and the charge in the member's price-card units (micro-USD for a
//! typical provider). Core's ledger stays the authority for the budget; this is the measurement.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::day::utc_day_bounds_ms;
use crate::log::{append_jsonl, read_jsonl};
use crate::MeteringError;

/// Receipt schema version (bumped on any incompatible change).
pub const ESCALATION_RECEIPT_SCHEMA: u32 = 1;

/// Where the escalation went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationRoute {
    /// A member-added OpenAI-compatible endpoint.
    MemberEndpoint,
    /// A registry model through the InferenceRouter.
    Registry,
}

/// How the escalation ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationSettlement {
    /// The provider answered; the charge is its reported usage (capped at the reservation), or the
    /// reservation when it reported none.
    Settled,
    /// The request may have reached the provider but no usable answer came back. The reservation
    /// stays charged (over-counting is the safe direction).
    FailedAfterSend,
}

/// One escalation, measured. Holds no conversation content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationReceipt {
    pub schema: u32,
    /// Core's id for the escalation (joins core's spend ledger).
    pub escalation_id: String,
    pub route: EscalationRoute,
    pub model: String,
    pub started_unix_ms: u64,
    pub latency_ms: u64,
    /// Prompt tokens the provider reported; `None` when it reported none.
    pub tokens_in: Option<u64>,
    /// Completion tokens the provider reported; `None` when it reported none.
    pub tokens_out: Option<u64>,
    /// What core reserved for the request (price-card micro-units).
    pub reserved_micros: u64,
    /// What the request is charged (price-card micro-units).
    pub charged_micros: u64,
    pub usage_reported: bool,
    /// The reported usage priced above the reservation (the charge was capped).
    pub exceeded_quote: bool,
    pub settlement: EscalationSettlement,
}

impl EscalationReceipt {
    /// A settled member-endpoint escalation.
    #[allow(clippy::too_many_arguments)]
    pub fn settled(
        escalation_id: &str,
        model: &str,
        started_unix_ms: u64,
        latency_ms: u64,
        usage: Option<(u64, u64)>,
        reserved_micros: u64,
        charged_micros: u64,
        exceeded_quote: bool,
    ) -> Self {
        EscalationReceipt {
            schema: ESCALATION_RECEIPT_SCHEMA,
            escalation_id: escalation_id.to_string(),
            route: EscalationRoute::MemberEndpoint,
            model: model.to_string(),
            started_unix_ms,
            latency_ms,
            tokens_in: usage.map(|u| u.0),
            tokens_out: usage.map(|u| u.1),
            reserved_micros,
            // Never more than the reservation, whatever the caller passed.
            charged_micros: charged_micros.min(reserved_micros),
            usage_reported: usage.is_some(),
            exceeded_quote,
            settlement: EscalationSettlement::Settled,
        }
    }

    /// A member-endpoint escalation that failed after it may have reached the provider: the full
    /// reservation is charged.
    pub fn failed_after_send(
        escalation_id: &str,
        model: &str,
        started_unix_ms: u64,
        latency_ms: u64,
        reserved_micros: u64,
    ) -> Self {
        EscalationReceipt {
            schema: ESCALATION_RECEIPT_SCHEMA,
            escalation_id: escalation_id.to_string(),
            route: EscalationRoute::MemberEndpoint,
            model: model.to_string(),
            started_unix_ms,
            latency_ms,
            tokens_in: None,
            tokens_out: None,
            reserved_micros,
            charged_micros: reserved_micros,
            usage_reported: false,
            exceeded_quote: false,
            settlement: EscalationSettlement::FailedAfterSend,
        }
    }
}

/// A local, append-only JSONL log of escalation receipts.
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

    pub fn append(&self, rec: &EscalationReceipt) -> Result<(), MeteringError> {
        append_jsonl(&self.path, rec)
    }

    pub fn read_all(&self) -> Result<Vec<EscalationReceipt>, MeteringError> {
        read_jsonl(&self.path)
    }
}

/// One UTC day of escalation receipts, summed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EscalationSummary {
    pub day: String,
    pub count: u32,
    pub settled: u32,
    pub failed_after_send: u32,
    /// Charged across the day (price-card micro-units, saturating).
    pub charged_micros: u64,
    /// Reserved across the day (price-card micro-units, saturating).
    pub reserved_micros: u64,
    /// Reported tokens, summed over the receipts that reported usage.
    pub tokens_in: u64,
    pub tokens_out: u64,
    /// Receipts with no reported usage (charged at the reservation).
    pub without_usage: u32,
    /// Receipts whose reported usage priced above the quote.
    pub exceeded_quote: u32,
}

impl EscalationSummary {
    /// Sum the receipts that started on `day` (`YYYY-MM-DD`, UTC).
    pub fn build(day: &str, receipts: &[EscalationReceipt]) -> Result<Self, MeteringError> {
        let (start, end) = utc_day_bounds_ms(day)?;
        let mut s = EscalationSummary {
            day: day.to_string(),
            ..Default::default()
        };
        for r in receipts
            .iter()
            .filter(|r| r.started_unix_ms >= start && r.started_unix_ms < end)
        {
            s.count = s.count.saturating_add(1);
            match r.settlement {
                EscalationSettlement::Settled => s.settled = s.settled.saturating_add(1),
                EscalationSettlement::FailedAfterSend => {
                    s.failed_after_send = s.failed_after_send.saturating_add(1)
                }
            }
            s.charged_micros = s.charged_micros.saturating_add(r.charged_micros);
            s.reserved_micros = s.reserved_micros.saturating_add(r.reserved_micros);
            if r.usage_reported {
                s.tokens_in = s.tokens_in.saturating_add(r.tokens_in.unwrap_or(0));
                s.tokens_out = s.tokens_out.saturating_add(r.tokens_out.unwrap_or(0));
            } else {
                s.without_usage = s.without_usage.saturating_add(1);
            }
            if r.exceeded_quote {
                s.exceeded_quote = s.exceeded_quote.saturating_add(1);
            }
        }
        Ok(s)
    }

    /// A markdown section for the daily report.
    pub fn to_markdown(&self) -> String {
        let usd = |m: u64| format!("${}.{:06}", m / 1_000_000, m % 1_000_000);
        let mut out = String::from("\n## Escalations\n\n");
        if self.count == 0 {
            out.push_str("No escalations.\n");
            return out;
        }
        out.push_str(&format!(
            "- Escalations: {} ({} settled, {} failed after sending)\n",
            self.count, self.settled, self.failed_after_send
        ));
        out.push_str(&format!(
            "- Charged: {} of {} reserved (price-card units; the provider's bill is authoritative)\n",
            usd(self.charged_micros),
            usd(self.reserved_micros)
        ));
        out.push_str(&format!(
            "- Reported tokens: {} in, {} out ({} without reported usage)\n",
            self.tokens_in, self.tokens_out, self.without_usage
        ));
        if self.exceeded_quote > 0 {
            out.push_str(&format!(
                "- Above the quote (charge capped): {}\n",
                self.exceeded_quote
            ));
        }
        out
    }
}
