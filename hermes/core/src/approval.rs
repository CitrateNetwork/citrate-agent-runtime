//! The approval queue (WP-S2.2): how Hermes proposes an outward-facing action and the
//! owner approves or denies it with one click before it executes.
//!
//! Two security properties live here, both tested:
//!
//! - **Concrete effect, not a label** (T11/H-A12): a [`PendingAction`] carries the exact
//!   effect ([`ActionEffect::describe`]) so the owner approves *what will happen*, not a
//!   summary an injection could have shaped.
//! - **No double-execute**: [`ApprovalQueue::resolve`] removes the action atomically and
//!   returns it at most once. A second click (or a replayed interaction) resolves to
//!   `None`, so an action can never run twice.
//!
//! Authorization of the click is *not* here — that is the ingress guard
//! ([`crate::guard::route_interaction`], owner-only, T15). This module assumes the
//! resolve call only happens for an authorized owner interaction.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::event::{ChannelId, MessageId};

/// A queue-assigned id for a pending action (monotonic within a run).
pub type ActionId = u64;

/// The concrete effect a pending action will have if approved. Each variant is something
/// outward-facing or hard-to-reverse, which is *why* it needs approval (guardrails 02).
/// S2.2 ships the one Guided-Builder effect; S3/S4 add moderation and server-structure
/// effects behind the same queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionEffect {
    /// Post a message to a channel.
    PostMessage {
        /// The exact target channel.
        channel: ChannelId,
        /// The exact content that will be posted.
        content: String,
    },
}

impl ActionEffect {
    /// A short machine label (for logs/trail).
    pub fn kind(&self) -> &'static str {
        match self {
            ActionEffect::PostMessage { .. } => "post-message",
        }
    }

    /// The **full, concrete** human description the owner approves against (H-A12): the
    /// exact target and the exact content, never a vague summary.
    pub fn describe(&self) -> String {
        match self {
            ActionEffect::PostMessage { channel, content } => {
                let quoted = if content.is_empty() {
                    "> (empty)".to_string()
                } else {
                    content.lines().map(|l| format!("> {l}")).collect::<Vec<_>>().join("\n")
                };
                format!("**Post a message** to <#{channel}>:\n{quoted}")
            }
        }
    }
}

/// Where a proposed action came from (T11): the owner message and channel that triggered
/// it, so the queue entry shows authentic provenance.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Provenance {
    /// The owner message that led to this proposal.
    pub triggered_by_message: Option<MessageId>,
    /// The channel that message was in.
    pub triggered_in_channel: Option<ChannelId>,
}

/// A proposed action awaiting the owner's decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAction {
    /// The queue id.
    pub id: ActionId,
    /// What will happen if approved.
    pub effect: ActionEffect,
    /// What triggered it.
    pub provenance: Provenance,
    /// When it was proposed (monotonic ms).
    pub created_at_ms: u64,
}

/// The owner's decision on a pending action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Approve,
    Deny,
}

/// The in-memory approval queue. Durable persistence (so pending actions survive a
/// restart) is WP-S2.3; the API is the same.
#[derive(Default)]
pub struct ApprovalQueue {
    inner: Mutex<QueueInner>,
}

#[derive(Default)]
struct QueueInner {
    next_id: ActionId,
    pending: HashMap<ActionId, PendingAction>,
}

impl ApprovalQueue {
    /// A new, empty queue (ids start at 1).
    pub fn new() -> Self {
        Self::default()
    }

    /// Propose an action; returns the stored [`PendingAction`] (with its assigned id).
    pub fn propose(
        &self,
        effect: ActionEffect,
        provenance: Provenance,
        now_ms: u64,
    ) -> PendingAction {
        let mut g = self.inner.lock().unwrap();
        g.next_id += 1;
        let id = g.next_id;
        let action = PendingAction { id, effect, provenance, created_at_ms: now_ms };
        g.pending.insert(id, action.clone());
        action
    }

    /// Look at a pending action without resolving it.
    pub fn get(&self, id: ActionId) -> Option<PendingAction> {
        self.inner.lock().unwrap().pending.get(&id).cloned()
    }

    /// Resolve an action: atomically remove it and return it. Returns `None` if it was
    /// already resolved (or never existed) — this is the no-double-execute guarantee.
    /// The `decision` is returned to the caller's flow; the queue only owns removal.
    pub fn resolve(&self, id: ActionId, _decision: Decision) -> Option<PendingAction> {
        self.inner.lock().unwrap().pending.remove(&id)
    }

    /// How many actions are awaiting a decision.
    pub fn pending_count(&self) -> usize {
        self.inner.lock().unwrap().pending.len()
    }
}

/// Encode a button's `custom_id` for a decision on an action: `"approve:<id>"` /
/// `"deny:<id>"`.
pub fn custom_id(decision: Decision, id: ActionId) -> String {
    let verb = match decision {
        Decision::Approve => "approve",
        Decision::Deny => "deny",
    };
    format!("{verb}:{id}")
}

/// Parse a button `custom_id` back into a `(Decision, ActionId)`. Returns `None` for any
/// id that is not one of ours (so a stray component interaction is ignored, not acted on).
pub fn parse_custom_id(s: &str) -> Option<(Decision, ActionId)> {
    let (verb, id) = s.split_once(':')?;
    let id = id.parse::<ActionId>().ok()?;
    let decision = match verb {
        "approve" => Decision::Approve,
        "deny" => Decision::Deny,
        _ => return None,
    };
    Some((decision, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post(channel: ChannelId, content: &str) -> ActionEffect {
        ActionEffect::PostMessage { channel, content: content.into() }
    }

    #[test]
    fn propose_assigns_monotonic_ids_and_stores() {
        let q = ApprovalQueue::new();
        let a = q.propose(post(10, "hi"), Provenance::default(), 0);
        let b = q.propose(post(10, "yo"), Provenance::default(), 1);
        assert_eq!(a.id, 1);
        assert_eq!(b.id, 2);
        assert_eq!(q.pending_count(), 2);
        assert_eq!(q.get(1).unwrap().effect, post(10, "hi"));
    }

    #[test]
    fn resolve_returns_once_then_none_no_double_execute() {
        let q = ApprovalQueue::new();
        let a = q.propose(post(10, "hi"), Provenance::default(), 0);
        // First resolve hands back the action to execute.
        assert_eq!(q.resolve(a.id, Decision::Approve), Some(a.clone()));
        // A second click (or a replayed interaction) gets nothing — cannot run twice.
        assert_eq!(q.resolve(a.id, Decision::Approve), None);
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn deny_also_removes_without_returning_for_execution_path() {
        // resolve() removes regardless; the caller only *executes* on Approve.
        let q = ApprovalQueue::new();
        let a = q.propose(post(10, "hi"), Provenance::default(), 0);
        assert!(q.resolve(a.id, Decision::Deny).is_some());
        assert!(q.get(a.id).is_none());
    }

    #[test]
    fn resolving_unknown_id_is_none() {
        let q = ApprovalQueue::new();
        assert_eq!(q.resolve(999, Decision::Approve), None);
    }

    #[test]
    fn describe_shows_the_concrete_effect() {
        let d = post(12345, "Welcome!\nRules in #info").describe();
        assert!(d.contains("<#12345>"));
        assert!(d.contains("> Welcome!"));
        assert!(d.contains("> Rules in #info"));
    }

    #[test]
    fn custom_id_round_trips_and_rejects_garbage() {
        assert_eq!(custom_id(Decision::Approve, 7), "approve:7");
        assert_eq!(custom_id(Decision::Deny, 7), "deny:7");
        assert_eq!(parse_custom_id("approve:7"), Some((Decision::Approve, 7)));
        assert_eq!(parse_custom_id("deny:42"), Some((Decision::Deny, 42)));
        assert_eq!(parse_custom_id("nonsense"), None);
        assert_eq!(parse_custom_id("approve:notanid"), None);
        assert_eq!(parse_custom_id("delete:7"), None); // not one of ours
    }
}
