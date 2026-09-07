//! Per-user refusal cooldown (T12). A non-owner who addresses the bot gets the refusal
//! at most once per window; repeats are silently dropped. Without this, anyone could
//! @mention the bot in a loop and turn it into a channel-flooding amplifier.
//!
//! Time is **injected** (a monotonic millisecond clock) rather than read internally, so
//! the policy is deterministic and unit-testable — the daemon passes
//! `Instant`-derived millis; tests pass explicit values.

use crate::event::UserId;
use std::collections::HashMap;

/// AR-B-033: hard cap on distinct tracked users. An entry is only useful for
/// `window_ms`, so an unauthenticated flood of distinct ids cannot grow the map
/// without bound — expired entries are pruned first, and if the map is still at
/// the cap the coldest entries are dropped (dropping a cold entry at worst lets
/// one extra refusal through later, never a security loss).
const MAX_TRACKED_USERS: usize = 100_000;

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
                // AR-B-033: bound memory before inserting a new tracked user.
                if !self.last.contains_key(&user) {
                    self.evict(now_ms);
                }
                self.last.insert(user, now_ms);
                true
            }
        }
    }

    /// AR-B-033: drop entries whose window has already elapsed (they can never
    /// suppress again), then, if still at the cap, drop the coldest entries.
    fn evict(&mut self, now_ms: u64) {
        if self.last.len() < MAX_TRACKED_USERS {
            return;
        }
        let window = self.window_ms;
        self.last
            .retain(|_, &mut t| now_ms.saturating_sub(t) < window);
        if self.last.len() >= MAX_TRACKED_USERS {
            // Everything is still live (a burst within one window). Drop the
            // oldest quarter to make room; the worst case is a slightly early
            // re-refusal for those users.
            let mut times: Vec<u64> = self.last.values().copied().collect();
            times.sort_unstable();
            let cutoff = times[times.len() / 4];
            self.last.retain(|_, &mut t| t > cutoff);
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
    fn map_is_bounded_under_a_distinct_id_flood() {
        // AR-B-033: an unauthenticated flood of distinct ids must not grow the
        // map without bound.
        let mut cd = RefusalCooldown::new(10_000);
        // Fill past the cap with already-expired entries (t = 0, now far later).
        for id in 0..(MAX_TRACKED_USERS as u64 + 50) {
            cd.should_refuse(id, 0);
        }
        // A later insert triggers eviction of the expired entries.
        cd.should_refuse(u64::MAX, 1_000_000);
        assert!(
            cd.last.len() <= MAX_TRACKED_USERS,
            "cooldown map must stay bounded; got {}",
            cd.last.len()
        );
    }

    #[test]
    fn cooldown_is_per_user() {
        // One spammer's cooldown never suppresses a different user's first refusal.
        let mut cd = RefusalCooldown::new(10_000);
        assert!(cd.should_refuse(A, 0));
        assert!(cd.should_refuse(B, 1_000), "B is independent of A");
    }
}
