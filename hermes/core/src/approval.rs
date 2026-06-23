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

/// The agentile-pack capsule actions Hermes can take on its own work (S2.2b): opening and
/// closing a sprint, writing a journal entry, and anchoring a work note. They are recorded
/// to the agentile worklog on approval, and — because every approval emits an
/// [`crate::decision::ApprovalDecision`] — a work-anchor is anchored on-chain for free when
/// the anchor sink is configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentileAction {
    /// Open a sprint.
    SprintOpen,
    /// Close a sprint.
    SprintClose,
    /// Write a journal entry.
    JournalWrite,
    /// Anchor a work note.
    WorkAnchor,
}

impl AgentileAction {
    /// The stable machine label (used as the effect kind in logs/trail/decisions).
    pub fn as_kind(self) -> &'static str {
        match self {
            AgentileAction::SprintOpen => "sprint-open",
            AgentileAction::SprintClose => "sprint-close",
            AgentileAction::JournalWrite => "journal-write",
            AgentileAction::WorkAnchor => "work-anchor",
        }
    }

    /// Parse from the tool-supplied action string. `None` for anything unrecognized, so an
    /// unknown action is refused rather than guessed.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "sprint-open" => Some(AgentileAction::SprintOpen),
            "sprint-close" => Some(AgentileAction::SprintClose),
            "journal-write" => Some(AgentileAction::JournalWrite),
            "work-anchor" => Some(AgentileAction::WorkAnchor),
            _ => None,
        }
    }

    /// A human verb for the description.
    fn verb(self) -> &'static str {
        match self {
            AgentileAction::SprintOpen => "Open sprint",
            AgentileAction::SprintClose => "Close sprint",
            AgentileAction::JournalWrite => "Write journal entry",
            AgentileAction::WorkAnchor => "Anchor work note",
        }
    }
}

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
    /// Summarize a channel's recent activity and post the digest to a target (S2.4). The
    /// target is allowlisted by the adapter (T13); the source content is summarized as
    /// untrusted data (T22). The summary is produced at execute time, so the approval is for
    /// the *act* (summarize source → post to target), with the exact source + target shown.
    Digest {
        /// The channel whose recent activity will be summarized.
        source_channel: ChannelId,
        /// The allowlisted channel the digest will be posted to.
        target_channel: ChannelId,
    },
    /// An agentile-pack action on Hermes's own work (S2.2b): sprint open/close, journal
    /// write, or work anchor. Executed by appending a structured block to the agentile
    /// worklog; approval emits a decision record (so a work-anchor anchors on-chain).
    Agentile {
        /// Which agentile action.
        action: AgentileAction,
        /// A short title / sprint name / journal title.
        title: String,
        /// Optional body (journal text, work note); may be empty for sprint open/close.
        body: String,
    },
}

impl ActionEffect {
    /// A short machine label (for logs/trail).
    pub fn kind(&self) -> &'static str {
        match self {
            ActionEffect::PostMessage { .. } => "post-message",
            ActionEffect::Digest { .. } => "digest",
            ActionEffect::Agentile { action, .. } => action.as_kind(),
        }
    }

    /// The **full, concrete** human description the owner approves against (H-A12): the
    /// exact target and the exact content/effect, never a vague summary.
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
            ActionEffect::Digest { source_channel, target_channel } => {
                format!(
                    "**Summarize** <#{source_channel}> and **post the digest** to <#{target_channel}>"
                )
            }
            ActionEffect::Agentile { action, title, body } => {
                let mut out = format!("**{}** `{title}`", action.verb());
                if !body.is_empty() {
                    let quoted =
                        body.lines().map(|l| format!("> {l}")).collect::<Vec<_>>().join("\n");
                    out.push_str(&format!(":\n{quoted}"));
                }
                out
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

    /// Snapshot the queue for durable persistence (WP-S2.3): the pending actions and the
    /// `next_id` high-water mark. Restoring `next_id` is what stops a post-restart proposal
    /// from reusing an id that a still-displayed button refers to.
    pub fn snapshot(&self) -> (Vec<PendingAction>, ActionId) {
        let g = self.inner.lock().unwrap();
        (g.pending.values().cloned().collect(), g.next_id)
    }

    /// Restore a persisted snapshot into an empty queue (WP-S2.3). `next_id` is advanced to
    /// at least the max restored id, so a new proposal never collides with a restored one.
    /// Restored actions are inert until the owner approves — and approval re-runs the guard
    /// on the interacting user (T15) — so a tampered snapshot still cannot self-execute.
    pub fn restore(&self, pending: Vec<PendingAction>, next_id: ActionId) {
        let mut g = self.inner.lock().unwrap();
        let max_id = pending.iter().map(|a| a.id).max().unwrap_or(0);
        g.next_id = next_id.max(max_id);
        for a in pending {
            g.pending.insert(a.id, a);
        }
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
    fn agentile_action_parse_roundtrips_and_rejects_unknown() {
        for k in ["sprint-open", "sprint-close", "journal-write", "work-anchor"] {
            assert_eq!(AgentileAction::parse(k).unwrap().as_kind(), k);
        }
        assert_eq!(AgentileAction::parse("delete-everything"), None);
    }

    #[test]
    fn agentile_effect_describes_action_title_and_body() {
        let e = ActionEffect::Agentile {
            action: AgentileAction::JournalWrite,
            title: "S2 close-out".into(),
            body: "Shipped the research room.\nLesson: seam + adapter.".into(),
        };
        assert_eq!(e.kind(), "journal-write");
        let d = e.describe();
        assert!(d.contains("Write journal entry"));
        assert!(d.contains("`S2 close-out`"));
        assert!(d.contains("> Shipped the research room."));
        // Empty body → no quoted block.
        let open = ActionEffect::Agentile {
            action: AgentileAction::SprintOpen,
            title: "HERMES-L-S3".into(),
            body: String::new(),
        };
        assert_eq!(open.kind(), "sprint-open");
        assert!(!open.describe().contains('>'));
    }

    #[test]
    fn digest_effect_describes_source_and_target() {
        let e = ActionEffect::Digest { source_channel: 111, target_channel: 222 };
        assert_eq!(e.kind(), "digest");
        let d = e.describe();
        assert!(d.contains("<#111>"));
        assert!(d.contains("<#222>"));
    }

    #[test]
    fn snapshot_restore_preserves_pending_and_advances_next_id() {
        let q = ApprovalQueue::new();
        q.propose(post(9, "a"), Provenance::default(), 0);
        q.propose(post(9, "b"), Provenance::default(), 1);
        let (pending, next_id) = q.snapshot();
        assert_eq!(pending.len(), 2);
        assert_eq!(next_id, 2);

        let q2 = ApprovalQueue::new();
        q2.restore(pending, next_id);
        assert_eq!(q2.pending_count(), 2);
        // A new proposal gets id 3 — no collision with the restored 1/2.
        assert_eq!(q2.propose(post(9, "c"), Provenance::default(), 2).id, 3);
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
