//! HUP-S4.1 (US-4.1 AC2): the member's decisions on MCP calls, per session.
//!
//! Two things wait here for the member, each shown on an in-app approval card in citrate-core
//! (`GET /sessions/:id/mcp/pending`, decided with `POST /sessions/:id/mcp/decide`):
//!
//! - **An effectful MCP call after taint** (`kind: "tool_call"`). Once a session has read
//!   untrusted content, a call to an MCP tool that is not annotated read-only needs the member's
//!   explicit decision (HUP-S2.7). The card shows the server, the tool, the exact arguments that
//!   will be sent and the server's hints; only an explicit allow sends it, with those arguments.
//!   Untainted calls and read-only calls never come here.
//! - **A URL-mode elicitation** (`kind: "open_url"`, MCP 2026-07-28). A server asks the member to
//!   open a page (a sign-in, a payment). The card shows the full URL and its host with any
//!   warnings; the sidecar never opens it. On an allow, core opens it in the system browser.
//!
//! A decision must carry the subject that was shown (the arguments, or the URL); otherwise it is
//! refused and changes nothing. No decision within [`MCP_APPROVAL_TIMEOUT`], or a session stop,
//! declines. There is no automatic path. Nothing here signs or holds a key (Rule 3).

use citrate_agent_loop::StopFlag;
use citrate_agent_mcp_host::{CallApproval, ElicitAction, McpApprover, UrlElicitation};
use serde::Serialize;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// How long a card waits for the member before it is declined.
pub const MCP_APPROVAL_TIMEOUT: Duration = Duration::from_secs(300);
/// At most this many cards wait at once per session.
pub const MAX_WAITING: usize = 8;

/// What the approval card shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpPending {
    /// The approval id (`mcp-<n>`), which the decision names.
    pub id: String,
    /// `tool_call` or `open_url`.
    pub kind: String,
    /// The loop's tool call id.
    pub call_id: String,
    pub server: String,
    /// The server's own tool name.
    pub remote_tool: String,
    /// The exposed name (`mcp__<server>__<tool>`).
    pub tool: String,
    /// Always `required`.
    pub hic: String,
    /// What a decision must carry back: the exact arguments (tool_call) or URL (open_url).
    pub subject: String,
    /// tool_call: the arguments exactly as they will be sent (canonical JSON).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
    /// tool_call: the server's hints (never trusted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hints: Option<Hints>,
    /// Why the member is asked (tool_call) or the server's message (open_url, untrusted text).
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_host: Option<String>,
    pub warnings: Vec<String>,
    /// Seconds left before it is declined for want of a decision.
    pub expires_in_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Hints {
    pub read_only: bool,
    pub destructive: bool,
    pub idempotent: bool,
    pub open_world: bool,
}

struct Waiting {
    view: McpPending,
    deadline: Instant,
    answer: Option<bool>,
}

#[derive(Default)]
struct Inner {
    next: u64,
    waiting: Vec<Waiting>,
}

/// One session's MCP cards.
pub struct McpApprovals {
    inner: Mutex<Inner>,
    cv: Condvar,
    timeout: Duration,
}

impl Default for McpApprovals {
    fn default() -> Self {
        Self::new(MCP_APPROVAL_TIMEOUT)
    }
}

impl McpApprovals {
    pub fn new(timeout: Duration) -> Self {
        McpApprovals {
            inner: Mutex::new(Inner::default()),
            cv: Condvar::new(),
            timeout,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The cards waiting now, oldest first.
    pub fn pending(&self) -> Vec<McpPending> {
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
    pub fn waiting(&self, id: &str) -> Option<McpPending> {
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
            .ok_or_else(|| "that request is no longer waiting for a decision".to_string())?;
        if w.view.subject != subject {
            return Err(
                "the decision does not match what is waiting; nothing was decided".to_string(),
            );
        }
        w.answer = Some(allow);
        drop(g);
        self.cv.notify_all();
        Ok(())
    }

    /// Park `view` until the member decides, it expires, or the session stops. `Ok(())` only for
    /// an explicit allow.
    fn request(&self, mut view: McpPending, stop: &StopFlag) -> Result<(), String> {
        let deadline = Instant::now() + self.timeout;
        let mut g = self.lock();
        if g.waiting.iter().filter(|w| w.answer.is_none()).count() >= MAX_WAITING {
            return Err("too many requests are already waiting for the member".to_string());
        }
        g.next += 1;
        let id = format!("mcp-{}", g.next);
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
                    Err("the member declined this request".to_string())
                };
            }
            if stop.is_stopped() {
                break Err("the session was stopped before the member decided".to_string());
            }
            let now = Instant::now();
            if now >= deadline {
                break Err(format!(
                    "no decision within {}s, so it was declined",
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

impl McpApprover for McpApprovals {
    fn approve_call(&self, req: &CallApproval, stop: &StopFlag) -> Result<(), String> {
        let view = McpPending {
            id: String::new(),
            kind: "tool_call".into(),
            call_id: req.call_id.clone(),
            server: req.server.clone(),
            remote_tool: req.remote_tool.clone(),
            tool: req.tool.clone(),
            hic: "required".into(),
            subject: req.arguments.clone(),
            arguments: Some(req.arguments.clone()),
            hints: Some(Hints {
                read_only: req.read_only,
                destructive: req.destructive,
                idempotent: req.idempotent,
                open_world: req.open_world,
            }),
            reason: req.reason.clone(),
            url: None,
            url_host: None,
            warnings: Vec::new(),
            expires_in_secs: 0,
        };
        self.request(view, stop)
    }

    fn open_url(&self, call_id: &str, req: &UrlElicitation, stop: &StopFlag) -> ElicitAction {
        let view = McpPending {
            id: String::new(),
            kind: "open_url".into(),
            call_id: call_id.to_string(),
            server: req.server.clone(),
            remote_tool: req.tool.clone(),
            tool: format!("mcp__{}__{}", req.server, req.tool),
            hic: "required".into(),
            subject: req.url.clone(),
            arguments: None,
            hints: None,
            reason: req.message.clone(),
            url: Some(req.url.clone()),
            url_host: Some(req.host.clone()),
            warnings: req.warnings.clone(),
            expires_in_secs: 0,
        };
        match self.request(view, stop) {
            Ok(()) => ElicitAction::Accept,
            Err(_) if stop.is_stopped() => ElicitAction::Cancel,
            Err(_) => ElicitAction::Decline,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn call_req() -> CallApproval {
        CallApproval {
            call_id: "c1".into(),
            tool: "mcp__web__write_note".into(),
            server: "web".into(),
            remote_tool: "write_note".into(),
            arguments: r#"{"text":"hi"}"#.into(),
            read_only: false,
            destructive: true,
            idempotent: false,
            open_world: true,
            reason: "tainted".into(),
        }
    }

    fn wait_for_card(a: &McpApprovals) -> McpPending {
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
    fn an_allow_needs_the_subject_that_was_shown() {
        let a = Arc::new(McpApprovals::default());
        let a2 = a.clone();
        let t = std::thread::spawn(move || a2.approve_call(&call_req(), &StopFlag::default()));
        let card = wait_for_card(&a);
        assert_eq!(card.kind, "tool_call");
        assert_eq!(card.arguments.as_deref(), Some(r#"{"text":"hi"}"#));
        assert!(card.hints.is_some_and(|h| h.destructive));
        assert!(a.decide(&card.id, true, r#"{"text":"other"}"#).is_err());
        assert!(a.decide("mcp-999", true, &card.subject).is_err());
        assert!(a.decide(&card.id, true, &card.subject).is_ok());
        assert_eq!(t.join().expect("join"), Ok(()));
        assert!(a.pending().is_empty());
    }

    #[test]
    fn a_decline_a_stop_and_a_timeout_all_decline() {
        let a = Arc::new(McpApprovals::default());
        let a2 = a.clone();
        let t = std::thread::spawn(move || a2.approve_call(&call_req(), &StopFlag::default()));
        let card = wait_for_card(&a);
        a.decide(&card.id, false, &card.subject).expect("decide");
        assert!(t.join().expect("join").is_err());

        let stop = StopFlag::default();
        let s2 = stop.clone();
        let a3 = a.clone();
        let t = std::thread::spawn(move || a3.approve_call(&call_req(), &s2));
        wait_for_card(&a);
        stop.stop();
        assert!(t.join().expect("join").is_err());

        let quick = McpApprovals::new(Duration::from_millis(150));
        assert!(quick
            .approve_call(&call_req(), &StopFlag::default())
            .is_err());
    }

    #[test]
    fn a_url_card_shows_the_url_and_maps_the_answer() {
        let a = Arc::new(McpApprovals::default());
        let req = UrlElicitation {
            server: "web".into(),
            tool: "connect".into(),
            message: "Connect".into(),
            url: "https://auth.example.com/c?s=1".into(),
            host: "auth.example.com".into(),
            warnings: vec![],
        };
        for (allow, want) in [(true, ElicitAction::Accept), (false, ElicitAction::Decline)] {
            let a2 = a.clone();
            let r2 = req.clone();
            let t = std::thread::spawn(move || a2.open_url("c9", &r2, &StopFlag::default()));
            let card = wait_for_card(&a);
            assert_eq!(card.kind, "open_url");
            assert_eq!(card.subject, req.url);
            assert_eq!(card.url_host.as_deref(), Some("auth.example.com"));
            a.decide(&card.id, allow, &card.subject).expect("decide");
            assert_eq!(t.join().expect("join"), want);
        }
    }
}
