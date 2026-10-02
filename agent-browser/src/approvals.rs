//! HUP-S5.1: member decisions on browser actions after taint.
//!
//! Once a session has read a web page (untrusted content), every effectful browser action
//! (opening an address, clicking, typing) needs the member's explicit decision (HUP-S2.7,
//! TLA+ `TaintDowngrade`). This is where such an action waits: one at a time, until the member
//! allows or denies it, the deadline passes (denied), the browser is stopped (denied), or the
//! session is stopped (denied). Nothing here can allow an action on its own.

use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

/// The action the member is being asked about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingAction {
    pub id: String,
    pub tool: String,
    pub summary: String,
    pub reason: String,
}

/// How a wait ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    Denied(String),
}

#[derive(Debug, Default)]
struct Inner {
    next: u64,
    pending: Option<PendingAction>,
    answer: Option<(String, bool)>,
    /// Bumped by [`ActionApprovals::deny_all`]; a waiter that sees it change gives up.
    epoch: u64,
}

/// The single-slot decision queue.
#[derive(Debug, Default)]
pub struct ActionApprovals {
    inner: Mutex<Inner>,
    cv: Condvar,
}

impl ActionApprovals {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// The action waiting for the member, if any.
    pub fn pending(&self) -> Option<PendingAction> {
        self.lock().pending.clone()
    }

    /// Ask the member and wait. `stopped` is polled so a stop ends the wait promptly.
    pub fn request(
        &self,
        tool: &str,
        summary: &str,
        reason: &str,
        deadline: Duration,
        stopped: &dyn Fn() -> bool,
    ) -> Decision {
        let mut g = self.lock();
        if g.pending.is_some() {
            return Decision::Denied(
                "another browser action is already waiting for the member".to_string(),
            );
        }
        g.next += 1;
        let id = format!("b{}", g.next);
        g.pending = Some(PendingAction {
            id: id.clone(),
            tool: tool.to_string(),
            summary: summary.to_string(),
            reason: reason.to_string(),
        });
        g.answer = None;
        let epoch = g.epoch;
        drop(g);
        self.cv.notify_all();

        let end = Instant::now() + deadline;
        let mut g = self.lock();
        let outcome = loop {
            if g.epoch != epoch {
                break Decision::Denied("the browser was stopped".to_string());
            }
            if let Some((aid, allow)) = g.answer.clone() {
                if aid == id {
                    break if allow {
                        Decision::Allowed
                    } else {
                        Decision::Denied("the member declined this browser action".to_string())
                    };
                }
            }
            if stopped() {
                break Decision::Denied("the session was stopped".to_string());
            }
            let now = Instant::now();
            if now >= end {
                break Decision::Denied(format!(
                    "no decision within {}s, so nothing was done",
                    deadline.as_secs()
                ));
            }
            let wait = (end - now).min(Duration::from_millis(100));
            g = match self.cv.wait_timeout(g, wait) {
                Ok((g, _)) => g,
                Err(p) => p.into_inner().0,
            };
        };
        if g.pending.as_ref().map(|p| p.id.as_str()) == Some(id.as_str()) {
            g.pending = None;
        }
        g.answer = None;
        drop(g);
        self.cv.notify_all();
        outcome
    }

    /// The member's decision on the pending action `id`.
    pub fn decide(&self, id: &str, allow: bool) -> Result<(), String> {
        let mut g = self.lock();
        match &g.pending {
            Some(p) if p.id == id => {
                g.answer = Some((id.to_string(), allow));
                drop(g);
                self.cv.notify_all();
                Ok(())
            }
            _ => Err("that browser action is no longer waiting".to_string()),
        }
    }

    /// Deny whatever is waiting (the browser stopped).
    pub fn deny_all(&self) {
        let mut g = self.lock();
        g.epoch += 1;
        g.pending = None;
        drop(g);
        self.cv.notify_all();
    }
}
