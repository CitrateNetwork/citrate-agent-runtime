//! Emergency stop — kill switch for all agent operations.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Emergency stop flag — shared across all agents.
/// When triggered, all tool executions immediately return AgentError::EmergencyStop.
#[derive(Clone)]
pub struct EmergencyStop {
    stopped: Arc<AtomicBool>,
}

impl Default for EmergencyStop {
    fn default() -> Self {
        Self::new()
    }
}

impl EmergencyStop {
    pub fn new() -> Self {
        Self {
            stopped: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Trigger emergency stop — all agents halt.
    pub fn trigger(&self) {
        tracing::warn!("EMERGENCY STOP triggered — all agent operations halted");
        self.stopped.store(true, Ordering::SeqCst);
    }

    /// Reset emergency stop — resume operations.
    pub fn reset(&self) {
        tracing::info!("Emergency stop reset — agents can resume");
        self.stopped.store(false, Ordering::SeqCst);
    }

    /// Check if emergency stop is active.
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Check and return error if stopped.
    pub fn check(&self) -> Result<(), crate::error::AgentError> {
        if self.is_stopped() {
            Err(crate::error::AgentError::EmergencyStop)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let estop = EmergencyStop::new();
        assert!(!estop.is_stopped());
        assert!(estop.check().is_ok());
    }

    #[test]
    fn test_trigger() {
        let estop = EmergencyStop::new();
        estop.trigger();
        assert!(estop.is_stopped());
        assert!(estop.check().is_err());
    }

    #[test]
    fn test_reset() {
        let estop = EmergencyStop::new();
        estop.trigger();
        estop.reset();
        assert!(!estop.is_stopped());
        assert!(estop.check().is_ok());
    }

    #[test]
    fn test_clone_shares_state() {
        let estop1 = EmergencyStop::new();
        let estop2 = estop1.clone();
        estop1.trigger();
        assert!(estop2.is_stopped());
    }
}
