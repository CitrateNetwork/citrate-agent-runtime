//! BFR-INT-poam-B / WP-2 — threshold evaluation helpers.
//!
//! Two concerns the jobs all share:
//!
//! 1. **Hysteresis** — don't fire on oscillation around a
//!    threshold. Once Fired, stay Fired until the metric drops
//!    well below the threshold (configurable margin).
//!
//! 2. **Backoff** — don't re-fire the same tripwire while a
//!    previous firing is still active on chain (state ∈
//!    {Fired, Acknowledged}). The contract enforces this via
//!    `AlreadyFired` on identical firing_ids, but we should also
//!    check before paying for the failed TX.

use std::time::{Duration, Instant};

/// What a job returns after one tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobOutcome {
    /// Metric below threshold (or above threshold but already
    /// firing — backoff suppressed re-fire).
    NoBreach,
    /// Threshold breached + a chain TX was broadcast. Carries the
    /// tx hash for the operator's audit trail.
    Fired(String),
    /// Job ran but couldn't complete (network down, RPC error,
    /// etc). The reason is logged + the next tick retries.
    Failed(String),
    /// AR-B-010: the backing metric is ABSENT from the source. A
    /// detection control whose metric is missing is *disabled*, not
    /// "no breach" — mapping absence to `NoBreach` silently suppresses
    /// firing (delete/rename the metric and the control goes dark).
    /// This fail-safe outcome surfaces the gap so the operator sees a
    /// blind spot instead of a false all-clear.
    MetricUnavailable(String),
}

/// Threshold evaluator with hysteresis + per-tripwire backoff.
///
/// Lifecycle:
/// - Start in `Below`.
/// - When metric > `high_threshold`: transition to `Above` + return
///   true (caller fires the tripwire).
/// - While `Above`: only re-transition to `Below` when metric drops
///   under `low_threshold` (low < high, so there's a dead-band).
/// - Caller is responsible for the backoff window via `mark_fired`
///   + `is_in_backoff`.
pub struct HysteresisGate {
    high_threshold: f64,
    low_threshold: f64,
    state: GateState,
    last_fired_at: Option<Instant>,
    backoff: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateState {
    Below,
    Above,
}

impl HysteresisGate {
    /// Create a new gate. `low_threshold` must be ≤ `high_threshold`
    /// (asserted in debug; clamped to `high` in release).
    /// `backoff` is the minimum duration between consecutive Fired
    /// outcomes regardless of metric value.
    pub fn new(high_threshold: f64, low_threshold: f64, backoff: Duration) -> Self {
        debug_assert!(low_threshold <= high_threshold);
        let low = low_threshold.min(high_threshold);
        Self {
            high_threshold,
            low_threshold: low,
            state: GateState::Below,
            last_fired_at: None,
            backoff,
        }
    }

    /// Evaluate a metric value. Returns true iff the caller SHOULD
    /// fire the tripwire (state crossed Below → Above + not in
    /// backoff). Internal state advances.
    pub fn evaluate(&mut self, metric_value: f64) -> bool {
        match self.state {
            GateState::Below => {
                if metric_value > self.high_threshold {
                    self.state = GateState::Above;
                    if self.is_in_backoff() {
                        return false;
                    }
                    self.last_fired_at = Some(Instant::now());
                    true
                } else {
                    false
                }
            }
            GateState::Above => {
                if metric_value < self.low_threshold {
                    self.state = GateState::Below;
                }
                // No re-fire while still above the low watermark.
                false
            }
        }
    }

    /// True if the last fire happened within the backoff window.
    pub fn is_in_backoff(&self) -> bool {
        match self.last_fired_at {
            Some(t) => t.elapsed() < self.backoff,
            None => false,
        }
    }

    /// For tests + manual control: clear the last-fired marker.
    #[cfg(test)]
    pub fn reset_backoff(&mut self) {
        self.last_fired_at = None;
    }

    /// Currently above the high threshold (used by tests/debug).
    #[cfg(test)]
    pub fn is_above(&self) -> bool {
        self.state == GateState::Above
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_then_above_fires_once() {
        let mut g = HysteresisGate::new(100.0, 80.0, Duration::from_secs(0));
        assert!(!g.evaluate(50.0));   // below
        assert!(!g.evaluate(99.0));   // still below
        assert!(g.evaluate(150.0));   // crosses → fire
        assert!(!g.evaluate(150.0));  // still above, don't re-fire
        assert!(!g.evaluate(90.0));   // in dead-band, still above
        assert!(!g.evaluate(79.0));   // crosses low_threshold → below
        assert!(g.is_above() == false);
    }

    #[test]
    fn re_arming_requires_dead_band_clear() {
        let mut g = HysteresisGate::new(100.0, 80.0, Duration::from_secs(0));
        assert!(g.evaluate(150.0));   // fire
        assert!(!g.evaluate(75.0));   // re-arm (below dead-band)
        assert!(g.evaluate(150.0));   // can fire again
    }

    #[test]
    fn oscillation_in_dead_band_does_not_fire() {
        let mut g = HysteresisGate::new(100.0, 80.0, Duration::from_secs(0));
        assert!(g.evaluate(150.0));   // fire
        for _ in 0..100 {
            // Bounce between 85 and 95 — both in dead-band — no fire.
            assert!(!g.evaluate(85.0));
            assert!(!g.evaluate(95.0));
        }
    }

    #[test]
    fn backoff_suppresses_re_fire_after_re_arm() {
        let mut g = HysteresisGate::new(
            100.0,
            80.0,
            Duration::from_secs(3600), // 1h backoff
        );
        assert!(g.evaluate(150.0));   // fire (state Below → Above)
        assert!(!g.evaluate(50.0));   // re-arm (state Above → Below, no fire)
        // Attempt to re-fire: state Below → Above, but is_in_backoff()
        // returns true (within 1h of last fire), so evaluate() returns
        // false. Note the state DOES advance — the backoff suppresses
        // the boolean but not the gate transition.
        assert!(!g.evaluate(150.0));
        // We're now in state Above (transitioned silently). Re-arm.
        assert!(!g.evaluate(50.0));
        // After reset, last_fired_at is None → not in backoff.
        g.reset_backoff();
        assert!(g.evaluate(150.0)); // fires this time
    }

    #[test]
    fn no_breach_outcome_default() {
        let outcome = JobOutcome::NoBreach;
        assert_eq!(outcome, JobOutcome::NoBreach);
    }

    #[test]
    fn fired_outcome_carries_tx_hash() {
        let outcome = JobOutcome::Fired("0xabc123".to_string());
        match outcome {
            JobOutcome::Fired(tx) => assert_eq!(tx, "0xabc123"),
            _ => panic!("expected Fired"),
        }
    }

    #[test]
    fn failed_outcome_carries_reason() {
        let outcome = JobOutcome::Failed("rpc timeout".to_string());
        match outcome {
            JobOutcome::Failed(reason) => assert!(reason.contains("timeout")),
            _ => panic!("expected Failed"),
        }
    }
}
