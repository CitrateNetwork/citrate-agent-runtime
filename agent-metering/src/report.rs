//! The daily report: one UTC day of turn records, aggregated, as JSON and markdown.

use crate::day::utc_day_bounds_ms;
use crate::measures::{
    tokens_per_s_milli, SelfReviewClaim, ENERGY_ESTIMATE_LABEL, SELF_REVIEW_OPINION,
};
use crate::record::{ToolTally, TurnOutcome, TurnRecord, Verification};
use crate::MeteringError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Report schema version. Version 2 (HUP-S7.5, D-27) adds `ttft_ms`, `speed`, `resources`,
/// `energy_estimate` and `self_review`; each is absent from (and defaults when reading) a version 1
/// report.
pub const REPORT_SCHEMA: u32 = 2;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeCounts {
    pub answered: u32,
    pub stopped: u32,
    pub step_limit: u32,
    pub failed: u32,
    pub unknown: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCounts {
    pub passed: u32,
    pub failed: u32,
    pub unverified: u32,
}

/// Nearest-rank percentiles of turn latency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyStats {
    pub p50: u64,
    pub p95: u64,
    pub max: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenTotals {
    pub tokens_in: u64,
    pub tokens_out: u64,
    /// Turns whose model client reported usage. The totals cover only these.
    pub turns_reporting: u32,
}

/// D-27: tokens per second over the day, from the server's own generation time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeedTotals {
    /// Completion tokens covered by a reported generation time.
    pub tokens: u64,
    pub generation_ms: u64,
    /// tokens / seconds, times 1000.
    pub tokens_per_s_milli: u64,
    pub turns_reporting: u32,
}

/// D-27: the day's machine load peaks, over the turns that were sampled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceTotals {
    pub turns_sampled: u32,
    pub cpu_peak_bps: u32,
    pub ram_used_peak_bytes: u64,
    pub ram_total_bytes: u64,
    /// `None` when no sampled turn had a GPU reading.
    pub gpu_peak_bps: Option<u32>,
}

/// D-27: the day's energy figure. An estimate, labelled as one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnergyTotals {
    /// Always "estimate".
    pub label: String,
    pub microwatt_hours: u64,
    pub turns_estimated: u32,
    /// Turns whose estimate left the GPU out (its load was unknown).
    pub turns_without_gpu: u32,
}

/// D-27: the model's self-review claims, labelled "opinion", and how they compare with the
/// verifiers' verdicts on the same turns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfReviewCounts {
    /// Always "opinion".
    pub label: String,
    pub pass: u32,
    pub fail: u32,
    pub unclear: u32,
    /// The claim matched the verifiers' verdict (PASS on a passed turn, FAIL on a failed one).
    pub agreed_with_verifiers: u32,
    /// The claim contradicted the verifiers' verdict.
    pub disagreed_with_verifiers: u32,
}

impl Default for SelfReviewCounts {
    fn default() -> Self {
        SelfReviewCounts {
            label: SELF_REVIEW_OPINION.to_string(),
            pass: 0,
            fail: 0,
            unclear: 0,
            agreed_with_verifiers: 0,
            disagreed_with_verifiers: 0,
        }
    }
}

impl SelfReviewCounts {
    /// Opinions recorded.
    pub fn total(&self) -> u32 {
        self.pass
            .saturating_add(self.fail)
            .saturating_add(self.unclear)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassFail {
    pub passed: u32,
    pub failed: u32,
}

/// One UTC day of Hermes turns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DailyReport {
    pub schema: u32,
    /// `YYYY-MM-DD`, UTC.
    pub day: String,
    pub turns: u32,
    pub sessions: u32,
    pub outcomes: OutcomeCounts,
    pub verification: VerificationCounts,
    /// passed / (passed + failed) in basis points; `None` when no turn was verified either way.
    pub verified_success_bps: Option<u32>,
    /// `None` when there were no turns.
    pub latency_ms: Option<LatencyStats>,
    pub tokens: TokenTotals,
    pub steps_total: u64,
    pub tool_calls: BTreeMap<String, ToolTally>,
    /// Keyed `"<step> / <verifier>"`.
    pub verifiers: BTreeMap<String, PassFail>,
    /// Turns per model.
    pub models: BTreeMap<String, u32>,
    pub tainted_turns: u32,
    /// D-27: the server's time to first token over the turns that reported it.
    #[serde(default)]
    pub ttft_ms: Option<LatencyStats>,
    /// D-27: generation speed; `None` when no turn reported a generation time.
    #[serde(default)]
    pub speed: Option<SpeedTotals>,
    /// D-27: machine load peaks; `None` when no turn was sampled.
    #[serde(default)]
    pub resources: Option<ResourceTotals>,
    /// D-27: the energy estimate; `None` when no turn has one.
    #[serde(default)]
    pub energy_estimate: Option<EnergyTotals>,
    /// D-27: self-review opinions.
    #[serde(default)]
    pub self_review: SelfReviewCounts,
}

pub(crate) fn nearest_rank(sorted: &[u64], pct: u64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let n = sorted.len() as u64;
    let rank = (pct * n).div_ceil(100).clamp(1, n);
    sorted[(rank - 1) as usize]
}

fn inc(x: &mut u32) {
    *x = x.saturating_add(1);
}

impl DailyReport {
    /// Aggregate the records whose start falls inside `day` (UTC). Records from other days are
    /// ignored, so a whole log can be passed in.
    pub fn build(day: &str, records: &[TurnRecord]) -> Result<Self, MeteringError> {
        let (start, end) = utc_day_bounds_ms(day)?;
        let mut r = DailyReport {
            schema: REPORT_SCHEMA,
            day: day.to_string(),
            turns: 0,
            sessions: 0,
            outcomes: OutcomeCounts::default(),
            verification: VerificationCounts::default(),
            verified_success_bps: None,
            latency_ms: None,
            tokens: TokenTotals::default(),
            steps_total: 0,
            tool_calls: BTreeMap::new(),
            verifiers: BTreeMap::new(),
            models: BTreeMap::new(),
            tainted_turns: 0,
            ttft_ms: None,
            speed: None,
            resources: None,
            energy_estimate: None,
            self_review: SelfReviewCounts::default(),
        };
        let mut sessions = BTreeSet::new();
        let mut latencies = Vec::new();
        let mut ttfts = Vec::new();
        for rec in records
            .iter()
            .filter(|x| x.started_unix_ms >= start && x.started_unix_ms < end)
        {
            inc(&mut r.turns);
            sessions.insert(rec.session_id.as_str());
            match rec.outcome {
                TurnOutcome::Answered => inc(&mut r.outcomes.answered),
                TurnOutcome::Stopped => inc(&mut r.outcomes.stopped),
                TurnOutcome::StepLimit => inc(&mut r.outcomes.step_limit),
                TurnOutcome::Failed => inc(&mut r.outcomes.failed),
                TurnOutcome::Unknown => inc(&mut r.outcomes.unknown),
            }
            match rec.verification() {
                Verification::Passed => inc(&mut r.verification.passed),
                Verification::Failed => inc(&mut r.verification.failed),
                Verification::Unverified => inc(&mut r.verification.unverified),
            }
            latencies.push(rec.latency_ms);
            if rec.tokens_in.is_some() || rec.tokens_out.is_some() {
                inc(&mut r.tokens.turns_reporting);
                r.tokens.tokens_in = r
                    .tokens
                    .tokens_in
                    .saturating_add(rec.tokens_in.unwrap_or(0));
                r.tokens.tokens_out = r
                    .tokens
                    .tokens_out
                    .saturating_add(rec.tokens_out.unwrap_or(0));
            }
            r.steps_total = r.steps_total.saturating_add(u64::from(rec.steps));
            for (name, t) in &rec.tool_calls {
                r.tool_calls.entry(name.clone()).or_default().add(t);
            }
            for v in &rec.verifiers {
                let e = r
                    .verifiers
                    .entry(format!("{} / {}", v.step, v.name))
                    .or_default();
                if v.passed {
                    inc(&mut e.passed);
                } else {
                    inc(&mut e.failed);
                }
            }
            inc(r.models.entry(rec.model.clone()).or_default());
            if rec.tainted {
                inc(&mut r.tainted_turns);
            }
            if let Some(t) = rec.ttft_ms {
                ttfts.push(t);
            }
            if let Some(g) = rec.generation {
                let s = r.speed.get_or_insert(SpeedTotals {
                    tokens: 0,
                    generation_ms: 0,
                    tokens_per_s_milli: 0,
                    turns_reporting: 0,
                });
                s.tokens = s.tokens.saturating_add(g.tokens);
                s.generation_ms = s.generation_ms.saturating_add(g.ms);
                inc(&mut s.turns_reporting);
            }
            if let Some(p) = rec.resources {
                let t = r.resources.get_or_insert(ResourceTotals {
                    turns_sampled: 0,
                    cpu_peak_bps: 0,
                    ram_used_peak_bytes: 0,
                    ram_total_bytes: 0,
                    gpu_peak_bps: None,
                });
                inc(&mut t.turns_sampled);
                t.cpu_peak_bps = t.cpu_peak_bps.max(p.cpu_peak_bps);
                t.ram_used_peak_bytes = t.ram_used_peak_bytes.max(p.ram_used_peak_bytes);
                t.ram_total_bytes = t.ram_total_bytes.max(p.ram_total_bytes);
                t.gpu_peak_bps = match (t.gpu_peak_bps, p.gpu_peak_bps) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                };
            }
            if let Some(e) = &rec.energy_estimate {
                let t = r.energy_estimate.get_or_insert(EnergyTotals {
                    label: ENERGY_ESTIMATE_LABEL.to_string(),
                    microwatt_hours: 0,
                    turns_estimated: 0,
                    turns_without_gpu: 0,
                });
                t.microwatt_hours = t.microwatt_hours.saturating_add(e.microwatt_hours);
                inc(&mut t.turns_estimated);
                if !e.gpu_included {
                    inc(&mut t.turns_without_gpu);
                }
            }
            if let Some(sr) = &rec.self_review {
                let c = &mut r.self_review;
                match sr.claim {
                    SelfReviewClaim::Pass => inc(&mut c.pass),
                    SelfReviewClaim::Fail => inc(&mut c.fail),
                    SelfReviewClaim::Unclear => inc(&mut c.unclear),
                }
                match (sr.claim, rec.verification()) {
                    (SelfReviewClaim::Pass, Verification::Passed)
                    | (SelfReviewClaim::Fail, Verification::Failed) => {
                        inc(&mut c.agreed_with_verifiers)
                    }
                    (SelfReviewClaim::Pass, Verification::Failed)
                    | (SelfReviewClaim::Fail, Verification::Passed) => {
                        inc(&mut c.disagreed_with_verifiers)
                    }
                    _ => {}
                }
            }
        }
        if let Some(s) = r.speed.as_mut() {
            s.tokens_per_s_milli = tokens_per_s_milli(s.tokens, s.generation_ms).unwrap_or(0);
        }
        if !ttfts.is_empty() {
            ttfts.sort_unstable();
            r.ttft_ms = Some(LatencyStats {
                p50: nearest_rank(&ttfts, 50),
                p95: nearest_rank(&ttfts, 95),
                max: ttfts.last().copied().unwrap_or(0),
            });
        }
        r.sessions = u32::try_from(sessions.len()).unwrap_or(u32::MAX);
        let judged = u64::from(r.verification.passed) + u64::from(r.verification.failed);
        r.verified_success_bps = (u64::from(r.verification.passed) * 10_000)
            .checked_div(judged)
            .map(|bps| u32::try_from(bps).unwrap_or(10_000));
        if !latencies.is_empty() {
            latencies.sort_unstable();
            r.latency_ms = Some(LatencyStats {
                p50: nearest_rank(&latencies, 50),
                p95: nearest_rank(&latencies, 95),
                max: latencies.last().copied().unwrap_or(0),
            });
        }
        Ok(r)
    }

    /// The D-27 rows of the markdown table. A measure no turn reported is written as unknown.
    fn d27_markdown_rows(&self) -> String {
        let mut s = String::new();
        match &self.ttft_ms {
            Some(t) => s.push_str(&format!(
                "| Time to first token p50 / p95 | {} ms / {} ms |\n",
                t.p50, t.p95
            )),
            None => s.push_str(
                "| Time to first token | unknown (the model server did not report it) |\n",
            ),
        }
        match &self.speed {
            Some(sp) => s.push_str(&format!(
                "| Tokens per second | {}.{} (over {} turns) |\n",
                sp.tokens_per_s_milli / 1000,
                (sp.tokens_per_s_milli % 1000) / 100,
                sp.turns_reporting
            )),
            None => s.push_str("| Tokens per second | unknown (no generation time reported) |\n"),
        }
        match &self.resources {
            Some(rt) => {
                let gpu = rt.gpu_peak_bps.map_or("unknown".to_string(), |g| {
                    format!("{}.{:02}%", g / 100, g % 100)
                });
                s.push_str(&format!(
                    "| Peak CPU / GPU / RAM (whole machine) | {}.{:02}% / {} / {} MiB of {} MiB |\n",
                    rt.cpu_peak_bps / 100,
                    rt.cpu_peak_bps % 100,
                    gpu,
                    rt.ram_used_peak_bytes / (1024 * 1024),
                    rt.ram_total_bytes / (1024 * 1024)
                ));
            }
            None => s.push_str("| Peak CPU / GPU / RAM | unknown (not sampled) |\n"),
        }
        match &self.energy_estimate {
            Some(e) => s.push_str(&format!(
                "| Energy (estimate, not measured) | {}.{:03} mWh |\n",
                e.microwatt_hours / 1000,
                e.microwatt_hours % 1000
            )),
            None => s.push_str("| Energy (estimate) | unknown (not sampled) |\n"),
        }
        let sr = &self.self_review;
        if sr.total() > 0 {
            s.push_str(&format!(
                "| Self-review (opinion, not a verdict) PASS / FAIL / unclear | {} / {} / {} (agreed with verifiers {}, disagreed {}) |\n",
                sr.pass, sr.fail, sr.unclear, sr.agreed_with_verifiers, sr.disagreed_with_verifiers
            ));
        } else {
            s.push_str("| Self-review (opinion) | none recorded |\n");
        }
        s
    }

    /// Pretty JSON.
    pub fn to_json(&self) -> Result<String, MeteringError> {
        serde_json::to_string_pretty(self).map_err(|e| MeteringError::Serialize(e.to_string()))
    }

    /// A member-facing markdown summary (for the daily journal).
    pub fn to_markdown(&self) -> String {
        let mut s = format!("# Hermes daily report: {}\n\n", self.day);
        if self.turns == 0 {
            s.push_str("No turns were recorded on this day (UTC).\n");
            return s;
        }
        s.push_str(
            "Only verifier verdicts count as success. A turn where Hermes answered is not a \
             success by itself, and a turn no verifier judged is listed as unverified.\n\n",
        );
        s.push_str("| Measure | Value |\n|---|---|\n");
        s.push_str(&format!("| Turns | {} |\n", self.turns));
        s.push_str(&format!("| Sessions | {} |\n", self.sessions));
        s.push_str(&format!(
            "| Verified passed / failed / unverified | {} / {} / {} |\n",
            self.verification.passed, self.verification.failed, self.verification.unverified
        ));
        let rate = match self.verified_success_bps {
            Some(bps) => format!("{}.{:02}%", bps / 100, bps % 100),
            None => "n/a (no verified turns)".to_string(),
        };
        s.push_str(&format!("| Verified success rate | {rate} |\n"));
        s.push_str(&format!(
            "| Answered / stopped / step limit / failed | {} / {} / {} / {} |\n",
            self.outcomes.answered,
            self.outcomes.stopped,
            self.outcomes.step_limit,
            self.outcomes.failed
        ));
        if let Some(l) = &self.latency_ms {
            s.push_str(&format!(
                "| Latency p50 / p95 / max | {} ms / {} ms / {} ms |\n",
                l.p50, l.p95, l.max
            ));
        }
        s.push_str(&format!("| Model steps | {} |\n", self.steps_total));
        s.push_str(&format!(
            "| Tokens in / out | {} / {} (tokens reported for {} of {} turns) |\n",
            self.tokens.tokens_in, self.tokens.tokens_out, self.tokens.turns_reporting, self.turns
        ));
        s.push_str(&format!(
            "| Turns that read untrusted content | {} |\n",
            self.tainted_turns
        ));
        s.push_str(&self.d27_markdown_rows());
        if !self.tool_calls.is_empty() {
            s.push_str("\n## Tool calls\n\n| Tool | Calls | Ok | Declined | Errors | Needed explicit approval |\n|---|---|---|---|---|---|\n");
            for (name, t) in &self.tool_calls {
                s.push_str(&format!(
                    "| `{name}` | {} | {} | {} | {} | {} |\n",
                    t.calls, t.ok, t.denied, t.error, t.hic_required
                ));
            }
        }
        if !self.verifiers.is_empty() {
            s.push_str("\n## Verifiers\n\n| Step / verifier | Passed | Failed |\n|---|---|---|\n");
            for (name, pf) in &self.verifiers {
                s.push_str(&format!("| {name} | {} | {} |\n", pf.passed, pf.failed));
            }
        }
        if !self.models.is_empty() {
            s.push_str("\n## Models\n\n| Model | Turns |\n|---|---|\n");
            for (m, n) in &self.models {
                s.push_str(&format!("| `{m}` | {n} |\n"));
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::nearest_rank;

    #[test]
    fn nearest_rank_edges() {
        assert_eq!(nearest_rank(&[], 50), 0);
        assert_eq!(nearest_rank(&[7], 50), 7);
        assert_eq!(nearest_rank(&[7], 95), 7);
        assert_eq!(nearest_rank(&[1, 2], 50), 1);
        assert_eq!(nearest_rank(&[1, 2], 95), 2);
        let v: Vec<u64> = (1..=100).collect();
        assert_eq!(nearest_rank(&v, 50), 50);
        assert_eq!(nearest_rank(&v, 95), 95);
    }
}
