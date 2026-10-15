//! HGW-1 — the member's decisions on the sidecar's own actions after taint, per session.
//!
//! Owner decision 2026-10-15 (HGW (2)): once a session has read untrusted content (a command's
//! output, a web page, an MCP result), an effectful sidecar-hosted call (`fs_*`, `file_write`,
//! `sheet_write`, the toolchain tools, `project_create`, capsules) is not refused for the rest of
//! the conversation. It waits here as an approval card that citrate-core shows to the member
//! (`GET /sessions/:id/actions/pending`, decided with `POST /sessions/:id/actions/decide`):
//!
//! - the card shows the tool, the exact arguments that will be used (`subject`, canonical JSON),
//!   a one-line summary, why it is gated (`hicReason`) and every source that tainted the session
//!   (`taintSources`);
//! - a decision must carry the `subject` that was shown; anything else is refused and changes
//!   nothing;
//! - an allow releases **that one call**, with those arguments. The session stays tainted, so
//!   the next effectful call asks again (no approval is ever global);
//! - a decline, a session stop, or no decision within [`ACTION_APPROVAL_TIMEOUT`] declines it.
//!
//! The queue exists only for a session opened with `hicAware: true` (core's promise that a
//! `hic: "required"` card always reaches a person, with no automatic path). Without it the
//! sidecar declines tainted effectful calls with [`citrate_agent_loop::cannot_ask_reason`].
//! `shell_run`, the browser and MCP keep their own cards (`/shell`, `/browser/actions`, `/mcp`),
//! which carry the same taint reason. Nothing here signs or holds a key (Rule 3).

use citrate_agent_loop::{StopFlag, ToolCall};
use serde::Serialize;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// How long a card waits for the member before it is declined.
pub const ACTION_APPROVAL_TIMEOUT: Duration = Duration::from_secs(300);
/// At most this many cards wait at once per session.
pub const MAX_WAITING: usize = 8;
/// Longest summary line on a card.
pub const SUMMARY_MAX_CHARS: usize = 240;

/// What the approval card shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionPending {
    /// The approval id (`act-<n>`), which the decision names.
    pub id: String,
    /// The loop's tool call id.
    pub call_id: String,
    pub tool: String,
    /// Always `required`.
    pub hic: String,
    /// The exact arguments that will be used (canonical JSON); a decision must carry it back.
    pub subject: String,
    /// One line for a person: the tool and its main argument.
    pub summary: String,
    /// Why the member is asked (the loop's `hic_reason`).
    pub hic_reason: String,
    /// Every tool that brought untrusted content into the session since it was last clean.
    pub taint_sources: Vec<String>,
    /// Seconds left before it is declined for want of a decision.
    pub expires_in_secs: u64,
}

impl ActionPending {
    /// The card for `call` (its `id` is assigned when it is queued).
    pub fn for_call(call: &ToolCall, reason: &str, taint_sources: Vec<String>) -> Self {
        let subject = canonical_arguments(&call.arguments);
        ActionPending {
            id: String::new(),
            call_id: call.id.clone(),
            tool: call.name.clone(),
            hic: "required".into(),
            summary: summary_line(&call.name, &subject),
            subject,
            hic_reason: reason.to_string(),
            taint_sources,
            expires_in_secs: 0,
        }
    }
}

/// The arguments as canonical JSON (sorted keys, no whitespace); the raw text when it is not
/// JSON (the call is then refused by its tool after release, never run differently).
pub fn canonical_arguments(raw: &str) -> String {
    let raw = if raw.trim().is_empty() { "{}" } else { raw };
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(v) => sorted(v).to_string(),
        Err(_) => raw.to_string(),
    }
}

/// Keys sorted at every level (whatever serde_json's map order is in this build).
fn sorted(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => {
            let mut entries: Vec<(String, serde_json::Value)> = m.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            serde_json::Value::Object(entries.into_iter().map(|(k, v)| (k, sorted(v))).collect())
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(sorted).collect())
        }
        other => other,
    }
}

/// `tool path` (or the first string argument), clipped to [`SUMMARY_MAX_CHARS`].
fn summary_line(tool: &str, subject: &str) -> String {
    let main = serde_json::from_str::<serde_json::Value>(subject)
        .ok()
        .and_then(|v| {
            let o = v.as_object()?.clone();
            ["path", "from", "project", "name", "cwd"]
                .iter()
                .find_map(|k| o.get(*k).and_then(|x| x.as_str()).map(str::to_string))
                .or_else(|| o.values().find_map(|x| x.as_str().map(str::to_string)))
        })
        .unwrap_or_default();
    let line = if main.is_empty() {
        tool.to_string()
    } else {
        format!("{tool} {main}")
    };
    if line.chars().count() > SUMMARY_MAX_CHARS {
        let mut s: String = line.chars().take(SUMMARY_MAX_CHARS).collect();
        s.push_str("...");
        s
    } else {
        line
    }
}

struct Waiting {
    view: ActionPending,
    deadline: Instant,
    answer: Option<bool>,
}

#[derive(Default)]
struct Inner {
    next: u64,
    waiting: Vec<Waiting>,
}

/// One session's action cards.
pub struct ActionApprovals {
    inner: Mutex<Inner>,
    cv: Condvar,
    timeout: Duration,
}

impl Default for ActionApprovals {
    fn default() -> Self {
        Self::new(ACTION_APPROVAL_TIMEOUT)
    }
}

impl ActionApprovals {
    pub fn new(timeout: Duration) -> Self {
        ActionApprovals {
            inner: Mutex::new(Inner::default()),
            cv: Condvar::new(),
            timeout,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The cards waiting now, oldest first.
    pub fn pending(&self) -> Vec<ActionPending> {
        let now = Instant::now();
        self.lock()
            .waiting
            .iter()
            .filter(|w| w.answer.is_none())
            .map(|w| {
                let mut v = w.view.clone();
                v.expires_in_secs = w.deadline.saturating_duration_since(now).as_secs();
                v
            })
            .collect()
    }

    /// The card with this id, if it is still waiting (for the decision record).
    pub fn waiting(&self, id: &str) -> Option<ActionPending> {
        self.lock()
            .waiting
            .iter()
            .find(|w| w.view.id == id && w.answer.is_none())
            .map(|w| w.view.clone())
    }

    /// The member's decision on card `id`. It must carry the subject that was shown; otherwise
    /// (or when nothing with that id is waiting) it is refused and changes nothing.
    pub fn decide(&self, id: &str, allow: bool, subject: &str) -> Result<(), String> {
        let mut g = self.lock();
        let w = g
            .waiting
            .iter_mut()
            .find(|w| w.view.id == id && w.answer.is_none())
            .ok_or_else(|| "that action is no longer waiting for a decision".to_string())?;
        if w.view.subject != subject {
            return Err(
                "the decision does not match the action that is waiting; nothing was decided"
                    .to_string(),
            );
        }
        w.answer = Some(allow);
        drop(g);
        self.cv.notify_all();
        Ok(())
    }

    /// Park `view` until the member decides, it expires, or the session stops. `Ok(())` only for
    /// an explicit allow.
    pub fn request(&self, mut view: ActionPending, stop: &StopFlag) -> Result<(), String> {
        let deadline = Instant::now() + self.timeout;
        let mut g = self.lock();
        if g.waiting.iter().filter(|w| w.answer.is_none()).count() >= MAX_WAITING {
            return Err("too many actions are already waiting for the member".to_string());
        }
        g.next += 1;
        let id = format!("act-{}", g.next);
        view.id = id.clone();
        view.expires_in_secs = self.timeout.as_secs();
        g.waiting.push(Waiting {
            view,
            deadline,
            answer: None,
        });
        let outcome = loop {
            let answer = g
                .waiting
                .iter()
                .find(|w| w.view.id == id)
                .and_then(|w| w.answer);
            if let Some(a) = answer {
                break if a {
                    Ok(())
                } else {
                    Err("the member declined this action".to_string())
                };
            }
            if stop.is_stopped() {
                break Err("the session was stopped before the member decided".to_string());
            }
            let now = Instant::now();
            if now >= deadline {
                break Err(format!(
                    "no decision within {}s, so the action was declined",
                    self.timeout.as_secs()
                ));
            }
            let wait = (deadline - now).min(Duration::from_millis(100));
            g = match self.cv.wait_timeout(g, wait) {
                Ok((guard, _)) => guard,
                Err(p) => p.into_inner().0,
            };
        };
        g.waiting.retain(|w| w.view.id != id);
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn call() -> ToolCall {
        ToolCall {
            id: "c1".into(),
            name: "fs_write".into(),
            arguments: r#"{ "path": "/p/a.txt", "content": "x" }"#.into(),
        }
    }

    fn wait_for_card(a: &ActionApprovals) -> ActionPending {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(p) = a.pending().into_iter().next() {
                return p;
            }
            assert!(Instant::now() < deadline, "no card appeared");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn the_card_shows_canonical_arguments_a_summary_and_the_reason() {
        let v = ActionPending::for_call(&call(), "because", vec!["shell_run".into()]);
        assert_eq!(v.subject, r#"{"content":"x","path":"/p/a.txt"}"#);
        assert_eq!(v.summary, "fs_write /p/a.txt");
        assert_eq!(v.hic, "required");
        assert_eq!(v.hic_reason, "because");
        let j = serde_json::to_value(&v).expect("json");
        for k in ["callId", "hicReason", "taintSources", "expiresInSecs"] {
            assert!(j.get(k).is_some(), "camelCase field {k} missing: {j}");
        }
        let long = ToolCall {
            arguments: serde_json::json!({ "path": "x".repeat(500) }).to_string(),
            ..call()
        };
        let v = ActionPending::for_call(&long, "r", vec![]);
        assert!(v.summary.chars().count() <= SUMMARY_MAX_CHARS + 3);
    }

    #[test]
    fn an_allow_needs_the_subject_that_was_shown() {
        let a = Arc::new(ActionApprovals::default());
        let a2 = a.clone();
        let t = std::thread::spawn(move || {
            a2.request(
                ActionPending::for_call(&call(), "r", vec![]),
                &StopFlag::default(),
            )
        });
        let card = wait_for_card(&a);
        assert!(card.id.starts_with("act-"));
        assert!(a.decide(&card.id, true, "{}").is_err());
        assert!(a.decide("act-999", true, &card.subject).is_err());
        assert_eq!(a.waiting(&card.id).map(|c| c.call_id), Some("c1".into()));
        assert!(a.decide(&card.id, true, &card.subject).is_ok());
        assert_eq!(t.join().expect("join"), Ok(()));
        assert!(a.pending().is_empty());
    }

    #[test]
    fn a_decline_a_stop_and_a_timeout_all_decline() {
        let a = Arc::new(ActionApprovals::default());
        let a2 = a.clone();
        let t = std::thread::spawn(move || {
            a2.request(
                ActionPending::for_call(&call(), "r", vec![]),
                &StopFlag::default(),
            )
        });
        let card = wait_for_card(&a);
        a.decide(&card.id, false, &card.subject).expect("decide");
        assert!(t.join().expect("join").is_err());

        let stop = StopFlag::default();
        let s2 = stop.clone();
        let a3 = a.clone();
        let t = std::thread::spawn(move || {
            a3.request(ActionPending::for_call(&call(), "r", vec![]), &s2)
        });
        wait_for_card(&a);
        stop.stop();
        assert!(t.join().expect("join").is_err());

        let quick = ActionApprovals::new(Duration::from_millis(150));
        assert!(quick
            .request(
                ActionPending::for_call(&call(), "r", vec![]),
                &StopFlag::default()
            )
            .is_err());
    }
}
