//! Budget tracking — token/cost limits for agent sessions.

use crate::error::AgentError;
use std::sync::atomic::{AtomicU64, Ordering};

/// Budget configuration for an agent session.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BudgetConfig {
    /// Maximum tokens (input + output) per session
    pub max_tokens: u64,
    /// Maximum cost in microdollars per session (1_000_000 = $1.00)
    pub max_cost_micros: u64,
    /// Maximum tool executions per session
    pub max_tool_calls: u64,
    /// Maximum wall-clock time in seconds
    pub max_time_seconds: u64,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            max_tokens: 100_000,
            max_cost_micros: 1_000_000, // $1.00
            max_tool_calls: 50,
            max_time_seconds: 3600, // 1 hour
        }
    }
}

/// Budget tracker — tracks usage against limits.
pub struct BudgetTracker {
    config: BudgetConfig,
    tokens_used: AtomicU64,
    cost_micros: AtomicU64,
    tool_calls: AtomicU64,
    start_time: std::time::Instant,
}

impl BudgetTracker {
    pub fn new(config: BudgetConfig) -> Self {
        Self {
            config,
            tokens_used: AtomicU64::new(0),
            cost_micros: AtomicU64::new(0),
            tool_calls: AtomicU64::new(0),
            start_time: std::time::Instant::now(),
        }
    }

    /// Record token usage. Returns error if budget exceeded.
    ///
    /// AR-B-029: `count` typically comes from a model provider's usage field.
    /// The old `fetch_add(count) + count` panicked in debug and WRAPPED the
    /// running total in release on overflow — resetting the counter and
    /// re-opening an exhausted budget. Saturate the computed total and clamp the
    /// stored counter so a huge `count` can never wrap it back to a small value.
    pub fn record_tokens(&self, count: u64) -> Result<(), AgentError> {
        let new_total = Self::commit_saturating(&self.tokens_used, count);
        if new_total > self.config.max_tokens {
            Err(AgentError::BudgetExceeded(format!(
                "Token limit: {}/{}",
                new_total, self.config.max_tokens
            )))
        } else {
            Ok(())
        }
    }

    /// Record a tool call. Returns error if budget exceeded.
    pub fn record_tool_call(&self) -> Result<(), AgentError> {
        let new_total = Self::commit_saturating(&self.tool_calls, 1);
        if new_total > self.config.max_tool_calls {
            Err(AgentError::BudgetExceeded(format!(
                "Tool call limit: {}/{}",
                new_total, self.config.max_tool_calls
            )))
        } else {
            Ok(())
        }
    }

    /// Record cost. Returns error if budget exceeded.
    pub fn record_cost(&self, micros: u64) -> Result<(), AgentError> {
        let new_total = Self::commit_saturating(&self.cost_micros, micros);
        if new_total > self.config.max_cost_micros {
            Err(AgentError::BudgetExceeded(format!(
                "Cost limit: ${:.2}/${:.2}",
                new_total as f64 / 1_000_000.0,
                self.config.max_cost_micros as f64 / 1_000_000.0
            )))
        } else {
            Ok(())
        }
    }

    /// AR-B-029: add `count` to a monotonic saturating counter and return the
    /// (saturating) new total. If the underlying `fetch_add` wrapped, clamp the
    /// stored value to `u64::MAX` so the budget stays exhausted rather than
    /// re-opening at a small wrapped value.
    fn commit_saturating(counter: &AtomicU64, count: u64) -> u64 {
        let prev = counter.fetch_add(count, Ordering::SeqCst);
        match prev.checked_add(count) {
            Some(total) => total,
            None => {
                // The atomic just wrapped — pin it at the ceiling.
                counter.store(u64::MAX, Ordering::SeqCst);
                u64::MAX
            }
        }
    }

    /// Check if time limit exceeded.
    pub fn check_time(&self) -> Result<(), AgentError> {
        let elapsed = self.start_time.elapsed().as_secs();
        if elapsed > self.config.max_time_seconds {
            Err(AgentError::BudgetExceeded(format!(
                "Time limit: {}s/{}s",
                elapsed, self.config.max_time_seconds
            )))
        } else {
            Ok(())
        }
    }

    /// Get current usage snapshot.
    pub fn usage(&self) -> BudgetUsage {
        BudgetUsage {
            tokens_used: self.tokens_used.load(Ordering::SeqCst),
            tokens_limit: self.config.max_tokens,
            cost_micros: self.cost_micros.load(Ordering::SeqCst),
            cost_limit_micros: self.config.max_cost_micros,
            tool_calls: self.tool_calls.load(Ordering::SeqCst),
            tool_calls_limit: self.config.max_tool_calls,
            elapsed_seconds: self.start_time.elapsed().as_secs(),
            time_limit_seconds: self.config.max_time_seconds,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BudgetUsage {
    pub tokens_used: u64,
    pub tokens_limit: u64,
    pub cost_micros: u64,
    pub cost_limit_micros: u64,
    pub tool_calls: u64,
    pub tool_calls_limit: u64,
    pub elapsed_seconds: u64,
    pub time_limit_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_budget() {
        let tracker = BudgetTracker::new(BudgetConfig {
            max_tokens: 100,
            ..Default::default()
        });
        assert!(tracker.record_tokens(50).is_ok());
        assert!(tracker.record_tokens(50).is_ok());
        assert!(tracker.record_tokens(1).is_err());
    }

    #[test]
    fn record_tokens_saturates_and_stays_exhausted_on_overflow() {
        // AR-B-029: a provider-supplied u64::MAX must not wrap the counter back
        // to a small value and re-open an exhausted budget.
        let tracker = BudgetTracker::new(BudgetConfig {
            max_tokens: 100,
            ..Default::default()
        });
        assert!(tracker.record_tokens(80).is_ok());
        // A hostile/huge usage report must be refused, not wrap.
        assert!(
            tracker.record_tokens(u64::MAX).is_err(),
            "overflowing count must be refused"
        );
        // And the budget must remain exhausted afterwards (no wrap re-open).
        assert!(
            tracker.record_tokens(1).is_err(),
            "budget must stay exhausted after a saturating overflow"
        );
    }

    #[test]
    fn test_tool_call_budget() {
        let tracker = BudgetTracker::new(BudgetConfig {
            max_tool_calls: 2,
            ..Default::default()
        });
        assert!(tracker.record_tool_call().is_ok());
        assert!(tracker.record_tool_call().is_ok());
        assert!(tracker.record_tool_call().is_err());
    }

    #[test]
    fn test_cost_budget() {
        let tracker = BudgetTracker::new(BudgetConfig {
            max_cost_micros: 100,
            ..Default::default()
        });
        assert!(tracker.record_cost(60).is_ok());
        assert!(tracker.record_cost(60).is_err());
    }

    #[test]
    fn test_usage_snapshot() {
        let tracker = BudgetTracker::new(BudgetConfig::default());
        tracker.record_tokens(42).expect("within budget");
        tracker.record_tool_call().expect("within budget");
        let usage = tracker.usage();
        assert_eq!(usage.tokens_used, 42);
        assert_eq!(usage.tool_calls, 1);
    }
}
