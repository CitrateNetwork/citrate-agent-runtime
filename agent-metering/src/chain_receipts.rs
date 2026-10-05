//! HUP-S7.5 / US-7.3 AC1 (D-27): SALT spent and gas, from the receipts of Hermes's chain
//! transactions.
//!
//! Every Hermes transaction on 40204 is signed in citrate-core (its SignatureCeremony, or the
//! nightly anchor's own signer). Core reports each mined one here as a [`ChainReceipt`]: the
//! transaction hash, what it was for, its receipt status, the gas it used, the price paid per gas
//! and the SALT value it carried. The sidecar never signs and never reads a key; it only keeps
//! these public facts and sums them per day ([`ChainSpendSummary`]).
//!
//! SALT spent = gas fee (gas used x effective gas price) + the value sent by transactions that
//! succeeded (a reverted transaction moves no value but still pays gas). A refund the member later
//! claims is a separate transaction with its own receipt; refunds received are not subtracted.
//! Amounts are wei as decimal strings (they exceed what a JSON number holds exactly).

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::day::utc_day_bounds_ms;
use crate::log::{append_jsonl, read_jsonl};
use crate::MeteringError;

/// Receipt schema version.
pub const CHAIN_RECEIPT_SCHEMA: u32 = 1;

/// What a Hermes transaction was for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainPurpose {
    /// A registry escalation through the InferenceRouter (pays native SALT).
    RegistryEscalation,
    /// The nightly anchor of the day's decision records.
    Anchor,
    /// Opt-in BenchmarkRegistry sharing.
    Benchmark,
    /// Any other transaction Hermes proposed and the member approved.
    Agent,
}

/// One mined Hermes transaction. Public facts only: no key, no calldata, no content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainReceipt {
    pub schema: u32,
    /// `0x` + 64 hex.
    pub tx_hash: String,
    pub purpose: ChainPurpose,
    /// When core read the receipt, Unix ms UTC (the day it counts toward).
    pub mined_unix_ms: u64,
    /// The receipt status: 1 succeeded, 0 reverted.
    pub status: u8,
    pub gas_used: u64,
    /// Wei per gas actually paid, decimal.
    pub effective_gas_price_wei: String,
    /// SALT value the transaction carried, wei, decimal.
    pub value_wei: String,
}

fn wei(s: &str) -> Option<u128> {
    if s.is_empty() || s.len() > 39 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

impl ChainReceipt {
    /// Check the receipt's shape: a transaction hash, status 0 or 1, decimal wei amounts.
    pub fn validate(&self) -> Result<(), MeteringError> {
        let bad = |m: &str| Err(MeteringError::InvalidReceipt(m.to_string()));
        let hash_ok = self.tx_hash.len() == 66
            && self.tx_hash.starts_with("0x")
            && self.tx_hash[2..].bytes().all(|b| b.is_ascii_hexdigit());
        if !hash_ok {
            return bad("tx_hash must be 0x and 64 hex digits");
        }
        if self.status > 1 {
            return bad("status must be 0 or 1");
        }
        if wei(&self.effective_gas_price_wei).is_none() {
            return bad("effective_gas_price_wei must be a decimal amount");
        }
        if wei(&self.value_wei).is_none() {
            return bad("value_wei must be a decimal amount");
        }
        Ok(())
    }

    /// Gas used times the effective gas price.
    pub fn fee_wei(&self) -> u128 {
        u128::from(self.gas_used).saturating_mul(wei(&self.effective_gas_price_wei).unwrap_or(0))
    }

    /// The value that left the account: only a successful transaction moves value.
    pub fn value_spent_wei(&self) -> u128 {
        if self.status == 1 {
            wei(&self.value_wei).unwrap_or(0)
        } else {
            0
        }
    }
}

/// A local, append-only JSONL log of chain receipts.
#[derive(Debug, Clone)]
pub struct ChainReceiptLog {
    path: PathBuf,
}

impl ChainReceiptLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        ChainReceiptLog { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one receipt after checking its shape.
    pub fn append(&self, rec: &ChainReceipt) -> Result<(), MeteringError> {
        rec.validate()?;
        append_jsonl(&self.path, rec)
    }

    pub fn read_all(&self) -> Result<Vec<ChainReceipt>, MeteringError> {
        read_jsonl(&self.path)
    }
}

/// One UTC day of Hermes chain transactions, summed. Wei amounts are decimal strings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainSpendSummary {
    pub day: String,
    /// Distinct transactions (a hash reported twice counts once).
    pub transactions: u32,
    pub reverted: u32,
    pub gas_used: u64,
    pub fee_wei: String,
    /// Value sent by successful transactions.
    pub value_wei: String,
    /// Fee plus value: the SALT that left the member's accounts for Hermes.
    pub salt_spent_wei: String,
    /// Transactions per purpose (`registry_escalation`, `anchor`, `benchmark`, `agent`).
    pub by_purpose: std::collections::BTreeMap<String, u32>,
}

fn purpose_key(p: ChainPurpose) -> &'static str {
    match p {
        ChainPurpose::RegistryEscalation => "registry_escalation",
        ChainPurpose::Anchor => "anchor",
        ChainPurpose::Benchmark => "benchmark",
        ChainPurpose::Agent => "agent",
    }
}

/// `wei` as SALT with up to 18 decimals, trailing zeros trimmed (`1.5 SALT`).
pub fn format_salt(wei: u128) -> String {
    const UNIT: u128 = 1_000_000_000_000_000_000;
    let whole = wei / UNIT;
    let frac = wei % UNIT;
    if frac == 0 {
        return format!("{whole} SALT");
    }
    let f = format!("{frac:018}");
    format!("{whole}.{} SALT", f.trim_end_matches('0'))
}

impl ChainSpendSummary {
    /// Sum the distinct receipts read on `day` (`YYYY-MM-DD`, UTC). Malformed receipts are skipped
    /// (the log only takes valid ones).
    pub fn build(day: &str, receipts: &[ChainReceipt]) -> Result<Self, MeteringError> {
        let (start, end) = utc_day_bounds_ms(day)?;
        let mut seen = BTreeSet::new();
        let mut s = ChainSpendSummary {
            day: day.to_string(),
            ..Default::default()
        };
        let (mut fee, mut value) = (0u128, 0u128);
        for r in receipts
            .iter()
            .filter(|r| r.mined_unix_ms >= start && r.mined_unix_ms < end && r.validate().is_ok())
        {
            if !seen.insert(r.tx_hash.to_ascii_lowercase()) {
                continue;
            }
            s.transactions = s.transactions.saturating_add(1);
            if r.status == 0 {
                s.reverted = s.reverted.saturating_add(1);
            }
            s.gas_used = s.gas_used.saturating_add(r.gas_used);
            fee = fee.saturating_add(r.fee_wei());
            value = value.saturating_add(r.value_spent_wei());
            let e = s
                .by_purpose
                .entry(purpose_key(r.purpose).to_string())
                .or_default();
            *e = e.saturating_add(1);
        }
        s.fee_wei = fee.to_string();
        s.value_wei = value.to_string();
        s.salt_spent_wei = fee.saturating_add(value).to_string();
        Ok(s)
    }

    /// The SALT spent, in wei.
    pub fn salt_spent(&self) -> u128 {
        wei(&self.salt_spent_wei).unwrap_or(0)
    }

    /// A markdown section for the daily report.
    pub fn to_markdown(&self) -> String {
        let mut out = String::from("\n## On chain\n\n");
        if self.transactions == 0 {
            out.push_str("No Hermes transactions.\n");
            return out;
        }
        let w = |s: &str| format_salt(wei(s).unwrap_or(0));
        out.push_str(&format!(
            "- Transactions: {} ({} reverted)\n- Gas used: {}\n- SALT spent: {} (gas fees {}, value sent {})\n",
            self.transactions,
            self.reverted,
            self.gas_used,
            w(&self.salt_spent_wei),
            w(&self.fee_wei),
            w(&self.value_wei)
        ));
        out
    }
}
