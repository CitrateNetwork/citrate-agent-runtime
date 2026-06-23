//! Live trail sinks for the daemon. `TracingTrail` records every guard decision to
//! structured logs (journald under the systemd unit) — an append-only operator-visible
//! record. `TracingDecisionSink` does the same for **approval-queue decisions** (the
//! owner's approve/deny), which are the records worth anchoring on-chain; the optional
//! on-chain sink (the runtime's `RecorderClient`) lives in `hermes-anchor` and is wired
//! only when the owner supplies a registry address + signer (WP-S2.2b).

use hermes_core::decision::{ApprovalDecision, DecisionSink};
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

/// A decision sink that emits each owner approve/deny to structured logs (journald) — the
/// always-on, append-only decision record. The on-chain anchor (`hermes-anchor`) is an
/// additional sink layered on top when configured; this one is never optional, so there is
/// always a local audit record of every decision even with no chain wired (WP-S2.2b).
pub struct TracingDecisionSink;

impl DecisionSink for TracingDecisionSink {
    fn record(&self, d: ApprovalDecision) {
        tracing::info!(
            at_ms = d.at_ms,
            action_id = d.action_id,
            effect_kind = d.effect_kind,
            status = d.status_str(),
            triggered_by = ?d.provenance.triggered_by_message,
            "decision: {}",
            d.effect_describe
        );
    }
}

/// Fan a decision out to several sinks (e.g. the always-on tracing sink **plus** the
/// optional on-chain anchor). Keeps the handler agnostic to how many sinks are wired.
pub struct FanoutDecisionSink {
    sinks: Vec<std::sync::Arc<dyn DecisionSink>>,
}

impl FanoutDecisionSink {
    /// Build a fan-out over the given sinks.
    pub fn new(sinks: Vec<std::sync::Arc<dyn DecisionSink>>) -> Self {
        Self { sinks }
    }
}

impl DecisionSink for FanoutDecisionSink {
    fn record(&self, d: ApprovalDecision) {
        for s in &self.sinks {
            s.record(d.clone());
        }
    }
}
