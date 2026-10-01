//! The daily report: one UTC day of turn records, aggregated, as JSON and markdown.

use crate::day::utc_day_bounds_ms;
use crate::record::{ToolTally, TurnOutcome, TurnRecord, Verification};
use crate::MeteringError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Report schema version.
pub const REPORT_SCHEMA: u32 = 1;

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
}

fn nearest_rank(sorted: &[u64], pct: u64) -> u64 {
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
        };
        let mut sessions = BTreeSet::new();
        let mut latencies = Vec::new();
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
