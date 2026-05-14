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
    pub fn record_tokens(&self, count: u64) -> Result<(), AgentError> {
        let new_total = self.tokens_used.fetch_add(count, Ordering::SeqCst) + count;
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
        let new_total = self.tool_calls.fetch_add(1, Ordering::SeqCst) + 1;
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
        let new_total = self.cost_micros.fetch_add(micros, Ordering::SeqCst) + micros;
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
