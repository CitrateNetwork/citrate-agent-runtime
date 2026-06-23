//! The audit trail seam (WP-S1.4). Every authorization decision and action is recorded
//! here. The trait is intentionally minimal — `record` only, no mutate or delete — so an
//! implementation cannot rewrite history: the **append-only** guarantee is structural,
//! not a convention.
//!
//! `hermes-core` stays dependency-free (ADR-H11: no supply-chain surface on the
//! boundary), so concrete sinks live in the adapter: a structured-logging sink is live
//! today (`hermes-discord::TracingTrail` → journald, an append-only record); on-chain
//! anchoring of *decisions* via the runtime's `RecorderClient` lands in S2, where the
//! approval queue produces actual Approved/Rejected decisions worth anchoring (anchoring
//! every message on-chain is neither desirable nor what the decision registry is for).

use crate::action::Action;
use crate::event::{AuthorKind, ChannelId, MessageId, UserId};
use crate::principal::Principal;

/// What the guard decided about an event — the recorded outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A command was accepted from the owner, bound to this message id (ADR-H9).
    Command { message_id: MessageId },
    /// A non-owner was refused on the command plane.
    Refused,
    /// Seen and routed to the moderation plane as data (no action in S1).
    Moderated,
    /// Dropped — self-event, or a refusal suppressed by the cooldown.
    Ignored,
    /// An interaction was allowed (owner).
    InteractionAllowed,
    /// An interaction was denied (non-owner) — channel visibility is not authority.
    InteractionDenied,
}

impl Outcome {
    /// Map a message [`Action`] to its recorded outcome.
    pub fn from_action(a: &Action) -> Outcome {
        match a {
            Action::Refuse => Outcome::Refused,
            Action::Command { message_id } => Outcome::Command { message_id: *message_id },
            Action::Moderate => Outcome::Moderated,
            Action::Ignore => Outcome::Ignored,
        }
    }
}

/// One append-only trail entry: when, who, where, and what was decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailEntry {
    /// Monotonic-clock milliseconds at the decision.
    pub at_ms: u64,
    /// The principal the guard authorized the actor as.
    pub principal: Principal,
    /// The acting user id, when there is one (`None` for webhook/system/integration).
    pub actor: Option<UserId>,
    /// The channel the event arrived on.
    pub channel: ChannelId,
    /// The decision.
    pub outcome: Outcome,
}

impl TrailEntry {
    /// Build an entry for a message decision.
    pub fn for_message(
        at_ms: u64,
        principal: Principal,
        author: AuthorKind,
        channel: ChannelId,
        action: &Action,
    ) -> Self {
        let actor = match author {
            AuthorKind::User(id) => Some(id),
            _ => None,
        };
        Self { at_ms, principal, actor, channel, outcome: Outcome::from_action(action) }
    }

    /// Whether this entry is a **security signal** — a non-owner attempting command-plane
    /// action (a refusal or a denied interaction). These are what an operator most wants
    /// surfaced.
    pub fn is_security_signal(&self) -> bool {
        matches!(self.outcome, Outcome::Refused | Outcome::InteractionDenied)
    }
}

/// An append-only audit sink. `record` is the only operation; there is no way to mutate
/// or delete a recorded entry through this trait.
pub trait Trail: Send + Sync {
    /// Append one entry. Must not block for long — sinks that anchor remotely should
    /// batch/offload, not stall the event path.
    fn record(&self, entry: TrailEntry);
}

/// A no-op trail (for tests that do not assert on the trail).
pub struct NullTrail;

impl Trail for NullTrail {
    fn record(&self, _entry: TrailEntry) {}
}

/// An in-memory trail for tests: collects entries so assertions can inspect them.
#[derive(Default)]
pub struct InMemoryTrail {
    entries: std::sync::Mutex<Vec<TrailEntry>>,
}

impl InMemoryTrail {
    /// A new, empty in-memory trail.
    pub fn new() -> Self {
        Self::default()
    }
    /// A snapshot of recorded entries.
    pub fn entries(&self) -> Vec<TrailEntry> {
        self.entries.lock().unwrap().clone()
    }
    /// How many entries have been recorded.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
    /// Whether nothing has been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.entries.lock().unwrap().is_empty()
    }
}

impl Trail for InMemoryTrail {
    fn record(&self, entry: TrailEntry) {
        self.entries.lock().unwrap().push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_maps_from_action() {
        assert_eq!(Outcome::from_action(&Action::Refuse), Outcome::Refused);
        assert_eq!(
            Outcome::from_action(&Action::Command { message_id: 5 }),
            Outcome::Command { message_id: 5 }
        );
        assert_eq!(Outcome::from_action(&Action::Moderate), Outcome::Moderated);
        assert_eq!(Outcome::from_action(&Action::Ignore), Outcome::Ignored);
    }

    #[test]
    fn refusals_and_denied_interactions_are_security_signals() {
        let sig = TrailEntry {
            at_ms: 1,
            principal: Principal::Other,
            actor: Some(222),
            channel: 7,
            outcome: Outcome::Refused,
        };
        assert!(sig.is_security_signal());

        let ok = TrailEntry {
            at_ms: 1,
            principal: Principal::Owner,
            actor: Some(1),
            channel: 7,
            outcome: Outcome::Command { message_id: 9 },
        };
        assert!(!ok.is_security_signal());
    }

    #[test]
    fn webhook_author_records_no_actor_id() {
        let e = TrailEntry::for_message(
            10,
            Principal::Other,
            AuthorKind::Webhook,
            7,
            &Action::Refuse,
        );
        assert_eq!(e.actor, None);
        assert!(e.is_security_signal());
    }

    #[test]
    fn in_memory_trail_is_append_only_record() {
        let t = InMemoryTrail::new();
        assert!(t.is_empty());
        t.record(TrailEntry::for_message(
            1,
            Principal::Owner,
            AuthorKind::User(1),
            7,
            &Action::Command { message_id: 9 },
        ));
        t.record(TrailEntry::for_message(
            2,
            Principal::Other,
            AuthorKind::User(2),
            7,
            &Action::Refuse,
        ));
        let entries = t.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].outcome, Outcome::Command { message_id: 9 });
        assert_eq!(entries[1].outcome, Outcome::Refused);
        // exactly one is a security signal (the non-owner refusal)
        assert_eq!(entries.iter().filter(|e| e.is_security_signal()).count(), 1);
    }
}
