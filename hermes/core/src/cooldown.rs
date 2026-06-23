//! Per-user refusal cooldown (T12). A non-owner who addresses the bot gets the refusal
//! at most once per window; repeats are silently dropped. Without this, anyone could
//! @mention the bot in a loop and turn it into a channel-flooding amplifier.
//!
//! Time is **injected** (a monotonic millisecond clock) rather than read internally, so
//! the policy is deterministic and unit-testable — the daemon passes
//! `Instant`-derived millis; tests pass explicit values.

use crate::event::UserId;
use std::collections::HashMap;

/// Tracks the last time each user was sent a refusal and enforces a minimum gap.
#[derive(Debug, Clone)]
pub struct RefusalCooldown {
    window_ms: u64,
    last: HashMap<UserId, u64>,
}

impl RefusalCooldown {
    /// A cooldown with the given window in milliseconds (e.g. 10 minutes = 600_000).
    pub fn new(window_ms: u64) -> Self {
        Self { window_ms, last: HashMap::new() }
    }

    /// Whether a refusal should be sent to `user` at `now_ms`. Returns `true` and
    /// records the send if the window has elapsed (or this is the first time); returns
    /// `false` (drop) if still within the window of the last refusal.
    pub fn should_refuse(&mut self, user: UserId, now_ms: u64) -> bool {
        match self.last.get(&user) {
            Some(&t) if now_ms.saturating_sub(t) < self.window_ms => false,
            _ => {
                self.last.insert(user, now_ms);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: UserId = 111;
    const B: UserId = 222;

    #[test]
    fn first_refusal_is_sent_then_suppressed_within_window() {
        let mut cd = RefusalCooldown::new(10_000);
        assert!(cd.should_refuse(A, 0), "first refusal goes through");
        assert!(!cd.should_refuse(A, 1_000), "within window: dropped");
        assert!(!cd.should_refuse(A, 9_999), "still within window: dropped");
    }

    #[test]
    fn refusal_resumes_after_the_window() {
        let mut cd = RefusalCooldown::new(10_000);
        assert!(cd.should_refuse(A, 0));
        assert!(cd.should_refuse(A, 10_000), "window elapsed: allowed again");
        assert!(!cd.should_refuse(A, 10_001), "and re-armed");
    }

    #[test]
    fn cooldown_is_per_user() {
        // One spammer's cooldown never suppresses a different user's first refusal.
        let mut cd = RefusalCooldown::new(10_000);
        assert!(cd.should_refuse(A, 0));
        assert!(cd.should_refuse(B, 1_000), "B is independent of A");
    }
}
