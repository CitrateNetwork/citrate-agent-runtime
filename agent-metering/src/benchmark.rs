//! Opt-in BenchmarkRegistry payload builder (D-27: aggregates on-chain only if the member opts in).
//!
//! Shaped from citrate-chain `contracts/src/cit_agent/BenchmarkRegistry.sol`:
//!
//! ```solidity
//! function record(uint256 agent_id, bytes32 capsule_id, bytes32 metric_name, uint256 value) external;
//! ```
//!
//! Records are namespaced by `msg.sender`, so whichever account submits them owns the series.
//! The contract stamps `block.timestamp`; the day is implied by when the batch lands.
//!
//! This module builds unsigned calldata and stops there. It holds no key, signs nothing and
//! opens no connection (Rule 3). The member's own account submits through citrate-core's
//! SignatureCeremony (or the nightly anchor batch, D-23), which is separate work. As of this
//! crate, BenchmarkRegistry is not in the 40204 address book (D-24 deploys it in the next
//! redeploy), so the registry address is always supplied by the caller.

use crate::chain_receipts::ChainSpendSummary;
use crate::report::DailyReport;
use crate::MeteringError;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// The function the payload calls.
pub const BENCHMARK_RECORD_SIGNATURE: &str = "record(uint256,bytes32,bytes32,uint256)";

/// Citrate chain id.
pub const CITRATE_CHAIN_ID: u64 = 40_204;

/// Label hashed into the `capsule_id` slot for the Hermes agent loop (it is not a capsule; the
/// slot names the producer of the metric).
pub const HERMES_CAPSULE_LABEL: &str = "citrate.hermes.agent-loop.v1";

/// Every metric this builder can emit, in emission order. `metric_name = keccak256(name)`.
pub const METRICS: &[&str] = &[
    "hermes.daily.turns",
    "hermes.daily.verified_pass",
    "hermes.daily.verified_fail",
    "hermes.daily.unverified",
    "hermes.daily.verified_success_bps",
    "hermes.daily.answered",
    "hermes.daily.stopped",
    "hermes.daily.step_limit",
    "hermes.daily.failed",
    "hermes.daily.latency_p50_ms",
    "hermes.daily.latency_p95_ms",
    "hermes.daily.steps",
    "hermes.daily.tool_calls",
    "hermes.daily.tokens_in",
    "hermes.daily.tokens_out",
    // HUP-S7.5 (D-27). Each is omitted on a day nothing measured it.
    "hermes.daily.ttft_p50_ms",
    "hermes.daily.ttft_p95_ms",
    "hermes.daily.tokens_per_s_milli",
    "hermes.daily.cpu_peak_bps",
    "hermes.daily.gpu_peak_bps",
    "hermes.daily.ram_peak_mib",
    "hermes.daily.energy_estimate_uwh",
    "hermes.daily.self_review_opinion_pass",
    "hermes.daily.self_review_opinion_fail",
    "hermes.daily.gas_used",
    "hermes.daily.salt_spent_wei",
];

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

/// The 4-byte selector of [`BENCHMARK_RECORD_SIGNATURE`].
pub fn record_selector() -> [u8; 4] {
    let h = keccak(BENCHMARK_RECORD_SIGNATURE.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// `keccak256(HERMES_CAPSULE_LABEL)`.
pub fn hermes_capsule_id() -> [u8; 32] {
    keccak(HERMES_CAPSULE_LABEL.as_bytes())
}

/// `keccak256(metric)`.
pub fn metric_name_hash(metric: &str) -> [u8; 32] {
    keccak(metric.as_bytes())
}

/// A member's explicit opt-in to share daily aggregates. Constructing one is the opt-in: there
/// is no default, and [`build_benchmark_payload`] refuses without one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchmarkOptIn {
    agent_id: u128,
    registry: [u8; 20],
}

impl BenchmarkOptIn {
    /// `agent_id` is the member's AgentSBT id; `registry` the BenchmarkRegistry address
    /// (`0x` + 40 hex, not the zero address).
    pub fn new(agent_id: u128, registry: &str) -> Result<Self, MeteringError> {
        let bad = || MeteringError::InvalidAddress(registry.to_string());
        let hex_part = registry.strip_prefix("0x").ok_or_else(bad)?;
        if hex_part.len() != 40 {
            return Err(bad());
        }
        let bytes = hex::decode(hex_part).map_err(|_| bad())?;
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&bytes);
        if addr == [0u8; 20] {
            return Err(bad());
        }
        Ok(BenchmarkOptIn {
            agent_id,
            registry: addr,
        })
    }
    pub fn agent_id(&self) -> u128 {
        self.agent_id
    }
    pub fn registry_hex(&self) -> String {
        format!("0x{}", hex::encode(self.registry))
    }
}

/// One unsigned `record(...)` call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkCall {
    /// Human-readable metric (one of [`METRICS`]).
    pub metric: String,
    /// `0x` + keccak256(metric).
    pub metric_name: String,
    /// The uint256 value, decimal.
    pub value: String,
    /// `0x` + ABI-encoded calldata.
    pub data: String,
}

/// Unsigned calldata for one day's aggregates. Nothing here has been sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkPayload {
    pub chain_id: u64,
    /// The BenchmarkRegistry address.
    pub to: String,
    /// Native value attached to each call (always zero).
    pub value: String,
    pub function: String,
    pub agent_id: String,
    pub capsule_id: String,
    /// The UTC day the aggregates describe (informational; the contract stamps its own time).
    pub day: String,
    pub calls: Vec<BenchmarkCall>,
    /// Always false: this crate never submits.
    pub sent: bool,
    pub note: String,
}

fn word_u128(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

fn encode_record(agent_id: u128, capsule: &[u8; 32], metric: &[u8; 32], value: u128) -> String {
    let mut data = Vec::with_capacity(4 + 32 * 4);
    data.extend_from_slice(&record_selector());
    data.extend_from_slice(&word_u128(agent_id));
    data.extend_from_slice(capsule);
    data.extend_from_slice(metric);
    data.extend_from_slice(&word_u128(value));
    format!("0x{}", hex::encode(data))
}

/// Build the opt-in payload for one daily report: aggregate counts only, no names of tools,
/// models, sessions or verifiers. Metrics that are undefined for the day (no verified turns, no
/// reported tokens) are omitted rather than sent as zero.
pub fn build_benchmark_payload(
    report: &DailyReport,
    opt_in: Option<&BenchmarkOptIn>,
) -> Result<BenchmarkPayload, MeteringError> {
    build_benchmark_payload_with(report, None, opt_in)
}

/// [`build_benchmark_payload`] plus (D-27) the day's chain spend: gas used and SALT spent by
/// Hermes's own transactions. A day with no Hermes transaction omits both.
pub fn build_benchmark_payload_with(
    report: &DailyReport,
    chain: Option<&ChainSpendSummary>,
    opt_in: Option<&BenchmarkOptIn>,
) -> Result<BenchmarkPayload, MeteringError> {
    let opt = opt_in.ok_or(MeteringError::NotOptedIn)?;
    if report.turns == 0 {
        return Err(MeteringError::EmptyReport);
    }
    let tool_calls: u64 = report.tool_calls.values().map(|t| u64::from(t.calls)).sum();
    let tokens = report.tokens.turns_reporting > 0;
    let lat = report.latency_ms.as_ref();
    let values: Vec<(&str, Option<u128>)> = vec![
        ("hermes.daily.turns", Some(report.turns.into())),
        (
            "hermes.daily.verified_pass",
            Some(report.verification.passed.into()),
        ),
        (
            "hermes.daily.verified_fail",
            Some(report.verification.failed.into()),
        ),
        (
            "hermes.daily.unverified",
            Some(report.verification.unverified.into()),
        ),
        (
            "hermes.daily.verified_success_bps",
            report.verified_success_bps.map(u128::from),
        ),
        (
            "hermes.daily.answered",
            Some(report.outcomes.answered.into()),
        ),
        ("hermes.daily.stopped", Some(report.outcomes.stopped.into())),
        (
            "hermes.daily.step_limit",
            Some(report.outcomes.step_limit.into()),
        ),
        ("hermes.daily.failed", Some(report.outcomes.failed.into())),
        ("hermes.daily.latency_p50_ms", lat.map(|l| l.p50.into())),
        ("hermes.daily.latency_p95_ms", lat.map(|l| l.p95.into())),
        ("hermes.daily.steps", Some(report.steps_total.into())),
        ("hermes.daily.tool_calls", Some(tool_calls.into())),
        (
            "hermes.daily.tokens_in",
            tokens.then_some(report.tokens.tokens_in.into()),
        ),
        (
            "hermes.daily.tokens_out",
            tokens.then_some(report.tokens.tokens_out.into()),
        ),
        (
            "hermes.daily.ttft_p50_ms",
            report.ttft_ms.as_ref().map(|t| t.p50.into()),
        ),
        (
            "hermes.daily.ttft_p95_ms",
            report.ttft_ms.as_ref().map(|t| t.p95.into()),
        ),
        (
            "hermes.daily.tokens_per_s_milli",
            report.speed.as_ref().map(|s| s.tokens_per_s_milli.into()),
        ),
        (
            "hermes.daily.cpu_peak_bps",
            report.resources.as_ref().map(|r| r.cpu_peak_bps.into()),
        ),
        (
            "hermes.daily.gpu_peak_bps",
            report
                .resources
                .as_ref()
                .and_then(|r| r.gpu_peak_bps.map(u128::from)),
        ),
        (
            "hermes.daily.ram_peak_mib",
            report
                .resources
                .as_ref()
                .map(|r| u128::from(r.ram_used_peak_bytes / (1024 * 1024))),
        ),
        (
            "hermes.daily.energy_estimate_uwh",
            report
                .energy_estimate
                .as_ref()
                .map(|e| e.microwatt_hours.into()),
        ),
        (
            "hermes.daily.self_review_opinion_pass",
            (report.self_review.total() > 0).then_some(report.self_review.pass.into()),
        ),
        (
            "hermes.daily.self_review_opinion_fail",
            (report.self_review.total() > 0).then_some(report.self_review.fail.into()),
        ),
        (
            "hermes.daily.gas_used",
            chain
                .filter(|c| c.transactions > 0)
                .map(|c| c.gas_used.into()),
        ),
        (
            "hermes.daily.salt_spent_wei",
            chain
                .filter(|c| c.transactions > 0)
                .map(ChainSpendSummary::salt_spent),
        ),
    ];
    let capsule = hermes_capsule_id();
    let calls = values
        .into_iter()
        .filter_map(|(metric, v)| v.map(|v| (metric, v)))
        .map(|(metric, v)| {
            let name = metric_name_hash(metric);
            BenchmarkCall {
                metric: metric.to_string(),
                metric_name: format!("0x{}", hex::encode(name)),
                value: v.to_string(),
                data: encode_record(opt.agent_id, &capsule, &name, v),
            }
        })
        .collect();
    Ok(BenchmarkPayload {
        chain_id: CITRATE_CHAIN_ID,
        to: opt.registry_hex(),
        value: "0".to_string(),
        function: BENCHMARK_RECORD_SIGNATURE.to_string(),
        agent_id: opt.agent_id.to_string(),
        capsule_id: format!("0x{}", hex::encode(capsule)),
        day: report.day.clone(),
        calls,
        sent: false,
        note: "Unsigned calldata built from daily aggregates. Not sent. Submitting needs the \
               member's signature through the app's signature ceremony."
            .to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_metric_is_unique() {
        let mut v = METRICS.to_vec();
        v.sort_unstable();
        v.dedup();
        assert_eq!(v.len(), METRICS.len());
    }

    #[test]
    fn large_ids_and_values_are_big_endian_words() {
        let w = word_u128(u128::MAX);
        assert!(w[..16].iter().all(|b| *b == 0));
        assert!(w[16..].iter().all(|b| *b == 0xff));
        assert_eq!(word_u128(1)[31], 1);
    }
}
