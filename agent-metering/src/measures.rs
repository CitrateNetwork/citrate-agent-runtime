//! HUP-S7.5 / US-7.3 AC1 (D-27): the per-turn measures beyond counts and latency.
//!
//! - [`Generation`]: completion tokens over the model server's own generation time (llama-server
//!   `timings.predicted_ms`), for tokens per second.
//! - [`ResourcePeaks`]: CPU, GPU and RAM load sampled while the turn ran. The sampling itself is a
//!   [`ResourceSampler`] the host supplies (the sidecar samples the machine); this crate only
//!   reduces samples to peaks and means.
//! - [`EnergyEstimate`]: an **estimate**, always labelled as one: mean load times nominal watts
//!   ([`EnergyModel`]) times the turn's duration. Nothing on the machine measured power.
//! - [`SelfReview`]: the model's own PASS/FAIL claim about the attempt, labelled "opinion". Only the
//!   claim is kept, never the text, and it never decides anything.

use serde::{Deserialize, Serialize};

/// Basis points in one whole (100%).
pub const BPS_WHOLE: u32 = 10_000;

/// Completion tokens and the time the server spent writing them, summed over the turn's model
/// calls that reported a generation time. Calls without one are left out of both sums.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Generation {
    pub tokens: u64,
    pub ms: u64,
}

impl Generation {
    /// Tokens per second, times 1000 (so 29.97 tokens/s is 29_970). `None` when no time was
    /// reported.
    pub fn tokens_per_s_milli(&self) -> Option<u64> {
        tokens_per_s_milli(self.tokens, self.ms)
    }
}

/// `tokens / (ms / 1000)`, times 1000. `None` for zero time.
pub fn tokens_per_s_milli(tokens: u64, ms: u64) -> Option<u64> {
    if ms == 0 {
        return None;
    }
    let v = u128::from(tokens) * 1_000_000 / u128::from(ms);
    Some(u64::try_from(v).unwrap_or(u64::MAX))
}

/// One reading of the machine while a turn runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSample {
    /// Busy share of all CPU cores, basis points (0..=10_000).
    pub cpu_bps: u32,
    pub ram_used_bytes: u64,
    pub ram_total_bytes: u64,
    /// Busy share of the GPU, basis points, when the machine reports it; `None` otherwise.
    pub gpu_bps: Option<u32>,
}

/// Machine load over one turn: peaks and means of the samples taken while it ran. System-wide,
/// not just Hermes: the model server is a separate process and its load is the point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePeaks {
    pub samples: u32,
    pub cpu_peak_bps: u32,
    pub cpu_mean_bps: u32,
    pub ram_used_peak_bytes: u64,
    pub ram_total_bytes: u64,
    /// `None` when no sample had a GPU reading (unknown, never zero).
    pub gpu_peak_bps: Option<u32>,
    pub gpu_mean_bps: Option<u32>,
}

impl ResourcePeaks {
    /// Reduce samples to peaks and means. `None` for no samples. Readings above 100% are clamped.
    pub fn from_samples(samples: &[ResourceSample]) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        let n = u64::try_from(samples.len()).unwrap_or(u64::MAX);
        let cpu = |s: &ResourceSample| s.cpu_bps.min(BPS_WHOLE);
        let cpu_sum: u64 = samples.iter().map(|s| u64::from(cpu(s))).sum();
        let gpus: Vec<u32> = samples
            .iter()
            .filter_map(|s| s.gpu_bps.map(|g| g.min(BPS_WHOLE)))
            .collect();
        let gpu_mean = if gpus.is_empty() {
            None
        } else {
            let sum: u64 = gpus.iter().map(|g| u64::from(*g)).sum();
            let len = u64::try_from(gpus.len()).unwrap_or(u64::MAX);
            Some(u32::try_from(sum / len).unwrap_or(BPS_WHOLE))
        };
        Some(ResourcePeaks {
            samples: u32::try_from(samples.len()).unwrap_or(u32::MAX),
            cpu_peak_bps: samples.iter().map(cpu).max().unwrap_or(0),
            cpu_mean_bps: u32::try_from(cpu_sum / n).unwrap_or(BPS_WHOLE),
            ram_used_peak_bytes: samples.iter().map(|s| s.ram_used_bytes).max().unwrap_or(0),
            ram_total_bytes: samples.iter().map(|s| s.ram_total_bytes).max().unwrap_or(0),
            gpu_peak_bps: gpus.iter().copied().max(),
            gpu_mean_bps: gpu_mean,
        })
    }
}

/// Samples the machine while one turn runs. The host decides how (the sidecar reads the OS).
pub trait ResourceSampler: Send + Sync {
    /// Start sampling for a turn that just opened.
    fn begin(&self) -> Box<dyn TurnSampling>;
}

/// The sampling of one turn in progress.
pub trait TurnSampling: Send {
    /// Stop sampling and reduce what was read. `None` when nothing could be read.
    fn finish(self: Box<Self>) -> Option<ResourcePeaks>;
}

/// The label every energy figure carries.
pub const ENERGY_ESTIMATE_LABEL: &str = "estimate";

/// Nominal power used to turn load into an energy estimate. Placeholder values pending owner
/// sign-off; the sidecar lets the member override them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnergyModel {
    /// Watts drawn by the CPU at full load.
    pub cpu_watts: u32,
    /// Watts drawn by the GPU at full load.
    pub gpu_watts: u32,
}

/// The default [`EnergyModel`] (a laptop-class machine). Pending owner sign-off.
pub const DEFAULT_ENERGY_MODEL: EnergyModel = EnergyModel {
    cpu_watts: 30,
    gpu_watts: 30,
};

/// An energy figure for one turn. It is an estimate, labelled as one: nothing measured power.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnergyEstimate {
    /// Always [`ENERGY_ESTIMATE_LABEL`].
    pub label: String,
    pub microwatt_hours: u64,
    /// How it was computed.
    pub method: String,
    pub cpu_watts: u32,
    pub gpu_watts: u32,
    /// False when the GPU's load was unknown, so only the CPU's share is counted.
    pub gpu_included: bool,
}

impl EnergyModel {
    /// Mean load times nominal watts times the turn's duration.
    pub fn estimate(&self, peaks: &ResourcePeaks, duration_ms: u64) -> EnergyEstimate {
        let cpu_mw = u128::from(peaks.cpu_mean_bps) * u128::from(self.cpu_watts) * 1_000
            / u128::from(BPS_WHOLE);
        let gpu_mw = peaks.gpu_mean_bps.map_or(0, |g| {
            u128::from(g) * u128::from(self.gpu_watts) * 1_000 / u128::from(BPS_WHOLE)
        });
        // mW x ms = microjoules; one microwatt-hour is 3600 microjoules.
        let uwh = (cpu_mw + gpu_mw) * u128::from(duration_ms) / 3_600;
        EnergyEstimate {
            label: ENERGY_ESTIMATE_LABEL.to_string(),
            microwatt_hours: u64::try_from(uwh).unwrap_or(u64::MAX),
            method: format!(
                "estimate: mean CPU load x {} W{} x turn time; no power was measured",
                self.cpu_watts,
                if peaks.gpu_mean_bps.is_some() {
                    format!(" + mean GPU load x {} W", self.gpu_watts)
                } else {
                    " (GPU load unknown, not counted)".to_string()
                }
            ),
            cpu_watts: self.cpu_watts,
            gpu_watts: self.gpu_watts,
            gpu_included: peaks.gpu_mean_bps.is_some(),
        }
    }
}

/// The label every self-review carries (the agent loop's own label).
pub const SELF_REVIEW_OPINION: &str = citrate_agent_loop::SELF_REVIEW_LABEL;

/// What the model claimed about its own attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfReviewClaim {
    Pass,
    Fail,
    /// The opinion did not start with PASS or FAIL, or the review call failed.
    Unclear,
}

impl SelfReviewClaim {
    /// The claim from the opinion's first word (the reviewer is asked to start with PASS or FAIL).
    /// Leading markup (`**PASS**`, `- FAIL`, a quote) is skipped; a reply that starts with any
    /// other word is unclear.
    pub fn parse(text: &str) -> Self {
        let first: String = text
            .trim_start_matches(|c: char| !c.is_alphanumeric())
            .chars()
            .take_while(|c| c.is_ascii_alphabetic())
            .collect();
        match first.to_ascii_uppercase().as_str() {
            "PASS" => SelfReviewClaim::Pass,
            "FAIL" => SelfReviewClaim::Fail,
            _ => SelfReviewClaim::Unclear,
        }
    }
}

/// The model's self-review of a turn: its claim only, labelled as an opinion. Never a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfReview {
    /// Always [`SELF_REVIEW_OPINION`] ("opinion").
    pub label: String,
    pub claim: SelfReviewClaim,
}

impl SelfReview {
    pub fn from_text(text: &str) -> Self {
        SelfReview {
            label: SELF_REVIEW_OPINION.to_string(),
            claim: SelfReviewClaim::parse(text),
        }
    }
}
