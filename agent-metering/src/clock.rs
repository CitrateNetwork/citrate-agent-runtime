//! Time sources. Latency uses a monotonic clock; the record's start time uses wall-clock UTC.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// A clock the sink reads. Injected so latency is testable without sleeping.
pub trait Clock: Send + Sync {
    /// Wall-clock milliseconds since the Unix epoch (UTC).
    fn unix_ms(&self) -> u64;
    /// Monotonic milliseconds from an arbitrary origin. Never goes backwards.
    fn monotonic_ms(&self) -> u64;
}

/// The real clock: `SystemTime` for the start stamp, `Instant` for latency.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        SystemClock {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        SystemClock::new()
    }
}

impl Clock for SystemClock {
    fn unix_ms(&self) -> u64 {
        // A clock set before 1970 reads as the epoch rather than panicking.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
    fn monotonic_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_clock_is_after_2026_and_monotonic() {
        let c = SystemClock::new();
        assert!(c.unix_ms() > 1_767_225_600_000);
        let a = c.monotonic_ms();
        let b = c.monotonic_ms();
        assert!(b >= a);
    }
}
