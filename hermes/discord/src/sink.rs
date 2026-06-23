//! Live trail sinks for the daemon. `TracingTrail` records every decision to structured
//! logs (journald under the systemd unit) — an append-only operator-visible record. The
//! on-chain decision-anchoring sink (the runtime's `RecorderClient`) is added in S2,
//! where the approval queue produces actual Approved/Rejected decisions to anchor.

use hermes_core::trail::{Trail, TrailEntry};

/// A trail sink that emits each entry as a structured log event. Security signals
/// (non-owner command attempts) are logged at WARN so they stand out; everything else
/// at INFO.
pub struct TracingTrail;

impl Trail for TracingTrail {
    fn record(&self, e: TrailEntry) {
        if e.is_security_signal() {
            tracing::warn!(
                at_ms = e.at_ms,
                principal = ?e.principal,
                actor = ?e.actor,
                channel = e.channel,
                outcome = ?e.outcome,
                "trail: security signal"
            );
        } else {
            tracing::info!(
                at_ms = e.at_ms,
                principal = ?e.principal,
                actor = ?e.actor,
                channel = e.channel,
                outcome = ?e.outcome,
                "trail"
            );
        }
    }
}
