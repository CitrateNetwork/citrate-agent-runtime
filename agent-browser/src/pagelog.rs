//! HUP-S5.1 (architecture 02 §5, `console` and `network`): what the page logged and which
//! requests it made, kept for two read-only tools.
//!
//! The worker listens to Chrome's own events on the tab it drives (`Runtime.consoleAPICalled`,
//! `Runtime.exceptionThrown`, `Log.entryAdded`, `Network.requestWillBeSent`,
//! `Network.responseReceived`, `Network.loadingFailed`) and keeps the latest [`MAX_ENTRIES`] of
//! each kind. What is kept is deliberately small:
//!
//! - console: the level, the message text (cut to [`MAX_TEXT_CHARS`]), where it came from, and the
//!   page it was logged on;
//! - network: the method, the address **without its query string, fragment or user info** (they
//!   often carry tokens), the resource type, the status or the failure, and the page.
//!
//! Never request or response bodies, never headers, never cookies. Everything here came from the
//! page, so the tools fence it as untrusted data. In attach mode the worker shows only entries of
//! origins the member consented to ([`crate::service`]).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use serde::Serialize;
use serde_json::Value;

use crate::snapshot::clean;

/// Entries kept per kind (the oldest go first).
pub const MAX_ENTRIES: usize = 200;
/// Longest console message kept.
pub const MAX_TEXT_CHARS: usize = 300;
/// Longest address kept.
pub const MAX_URL_CHARS: usize = 300;

/// How serious a console entry is, lowest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConsoleLevel {
    Debug,
    Info,
    Warning,
    Error,
}

impl ConsoleLevel {
    /// Chrome's console API types and log levels, folded into four.
    pub fn from_chrome(s: &str) -> ConsoleLevel {
        match s {
            "error" | "assert" => ConsoleLevel::Error,
            "warning" | "warn" => ConsoleLevel::Warning,
            "debug" | "verbose" | "trace" => ConsoleLevel::Debug,
            _ => ConsoleLevel::Info,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ConsoleLevel::Debug => "debug",
            ConsoleLevel::Info => "info",
            ConsoleLevel::Warning => "warning",
            ConsoleLevel::Error => "error",
        }
    }
}

/// One console message, exception or browser log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConsoleEntry {
    pub seq: u64,
    pub level: ConsoleLevel,
    /// `console`, `exception`, or Chrome's log source (`network`, `security`, ...).
    pub source: String,
    pub text: String,
    /// The page it was logged on (as the worker tracked it).
    pub page: String,
}

/// One request the page made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkEntry {
    pub seq: u64,
    #[serde(skip)]
    pub request_id: String,
    pub method: String,
    /// The address without query string, fragment or user info ([`redact_url`]).
    pub url: String,
    pub resource_type: String,
    pub status: Option<u16>,
    pub mime_type: Option<String>,
    /// Why it failed (`net::ERR_...`, `blocked: ...`, `canceled`), when it did.
    pub failed: Option<String>,
    pub page: String,
}

/// An address cut down to what is safe to show: `scheme://host[:port]/path`. User info, query
/// string and fragment are dropped; `data:` and `blob:` addresses are shown by scheme only.
pub fn redact_url(raw: &str) -> String {
    let lower = raw.trim_start().to_ascii_lowercase();
    for scheme in ["data:", "blob:", "javascript:"] {
        if lower.starts_with(scheme) {
            return format!("{scheme}(omitted)");
        }
    }
    match url::Url::parse(raw.trim()) {
        Ok(u) => {
            let host = u.host_str().unwrap_or_default();
            let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
            let shown = if host.is_empty() {
                format!("{}:{}", u.scheme(), u.path())
            } else {
                format!("{}://{host}{port}{}", u.scheme(), u.path())
            };
            clean(&shown, MAX_URL_CHARS)
        }
        Err(_) => "(not an address)".to_string(),
    }
}

/// The text of one `Runtime.RemoteObject` console argument.
fn arg_text(a: &Value) -> String {
    if let Some(s) = a["value"].as_str() {
        return s.to_string();
    }
    if !a["value"].is_null() && !a["value"].is_object() && !a["value"].is_array() {
        return a["value"].to_string();
    }
    if let Some(s) = a["unserializableValue"].as_str() {
        return s.to_string();
    }
    if let Some(s) = a["description"].as_str() {
        return s.to_string();
    }
    a["type"].as_str().unwrap_or_default().to_string()
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// The console and network logs of the tab the worker drives.
#[derive(Default)]
pub struct PageLog {
    seq: AtomicU64,
    console: Mutex<VecDeque<ConsoleEntry>>,
    network: Mutex<VecDeque<NetworkEntry>>,
}

impl PageLog {
    fn next(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn push_console(&self, level: ConsoleLevel, source: &str, text: &str, page: &str) {
        let e = ConsoleEntry {
            seq: self.next(),
            level,
            source: clean(source, 40),
            text: clean(text, MAX_TEXT_CHARS),
            page: redact_url(page),
        };
        let mut c = lock(&self.console);
        if c.len() >= MAX_ENTRIES {
            c.pop_front();
        }
        c.push_back(e);
    }

    /// Fold one CDP event in. Returns true when the event was one of ours.
    pub fn on_event(&self, method: &str, params: &Value, page: &str) -> bool {
        match method {
            "Runtime.consoleAPICalled" => {
                let level = ConsoleLevel::from_chrome(params["type"].as_str().unwrap_or("log"));
                let text = params["args"]
                    .as_array()
                    .map(|a| a.iter().map(arg_text).collect::<Vec<_>>().join(" "))
                    .unwrap_or_default();
                self.push_console(level, "console", &text, page);
                true
            }
            "Runtime.exceptionThrown" => {
                let d = &params["exceptionDetails"];
                let text = d["exception"]["description"]
                    .as_str()
                    .or_else(|| d["text"].as_str())
                    .unwrap_or("an uncaught exception");
                self.push_console(ConsoleLevel::Error, "exception", text, page);
                true
            }
            "Log.entryAdded" => {
                let e = &params["entry"];
                let level = ConsoleLevel::from_chrome(e["level"].as_str().unwrap_or("info"));
                let mut text = e["text"].as_str().unwrap_or_default().to_string();
                if let Some(u) = e["url"].as_str().filter(|u| !u.is_empty()) {
                    text.push_str(&format!(" ({})", redact_url(u)));
                }
                self.push_console(level, e["source"].as_str().unwrap_or("other"), &text, page);
                true
            }
            "Network.requestWillBeSent" => {
                let id = params["requestId"].as_str().unwrap_or_default().to_string();
                let req = &params["request"];
                let e = NetworkEntry {
                    seq: self.next(),
                    request_id: id,
                    method: clean(req["method"].as_str().unwrap_or("GET"), 12),
                    url: redact_url(req["url"].as_str().unwrap_or_default()),
                    resource_type: clean(params["type"].as_str().unwrap_or("Other"), 24),
                    status: None,
                    mime_type: None,
                    failed: None,
                    page: redact_url(page),
                };
                let mut n = lock(&self.network);
                if n.len() >= MAX_ENTRIES {
                    n.pop_front();
                }
                n.push_back(e);
                true
            }
            "Network.responseReceived" => {
                let id = params["requestId"].as_str().unwrap_or_default();
                let resp = &params["response"];
                let mut n = lock(&self.network);
                if let Some(e) = n.iter_mut().rev().find(|e| e.request_id == id) {
                    e.status = resp["status"]
                        .as_u64()
                        .or_else(|| resp["status"].as_f64().map(|f| f as u64))
                        .and_then(|s| u16::try_from(s).ok());
                    e.mime_type = resp["mimeType"].as_str().map(|m| clean(m, 60));
                }
                true
            }
            "Network.loadingFailed" => {
                let id = params["requestId"].as_str().unwrap_or_default();
                let why = if params["canceled"].as_bool() == Some(true) {
                    "canceled".to_string()
                } else if let Some(b) = params["blockedReason"].as_str() {
                    format!("blocked: {}", clean(b, 60))
                } else {
                    clean(params["errorText"].as_str().unwrap_or("failed"), 80)
                };
                let mut n = lock(&self.network);
                if let Some(e) = n.iter_mut().rev().find(|e| e.request_id == id) {
                    e.failed = Some(why);
                }
                true
            }
            _ => false,
        }
    }

    /// The latest `limit` console entries at `min` level or above, oldest first, that `keep`
    /// accepts (attach mode passes its consent check).
    pub fn console(
        &self,
        min: ConsoleLevel,
        limit: usize,
        keep: &dyn Fn(&str) -> bool,
    ) -> Vec<ConsoleEntry> {
        let c = lock(&self.console);
        let mut out: Vec<ConsoleEntry> = c
            .iter()
            .rev()
            .filter(|e| e.level >= min && keep(&e.page))
            .take(limit)
            .cloned()
            .collect();
        out.reverse();
        out
    }

    /// The latest `limit` requests (only failed ones, or HTTP 4xx/5xx, with `problems_only`),
    /// oldest first, that `keep` accepts.
    pub fn network(
        &self,
        problems_only: bool,
        limit: usize,
        keep: &dyn Fn(&str) -> bool,
    ) -> Vec<NetworkEntry> {
        let n = lock(&self.network);
        let mut out: Vec<NetworkEntry> = n
            .iter()
            .rev()
            .filter(|e| {
                (!problems_only || e.failed.is_some() || e.status.is_some_and(|s| s >= 400))
                    && keep(&e.page)
            })
            .take(limit)
            .cloned()
            .collect();
        out.reverse();
        out
    }

    /// Forget everything (the browser was torn down).
    pub fn clear(&self) {
        lock(&self.console).clear();
        lock(&self.network).clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn all(_: &str) -> bool {
        true
    }

    #[test]
    fn addresses_lose_query_fragment_and_user_info() {
        assert_eq!(
            redact_url("https://user:pw@api.example.com:8443/v1/items?token=abc#frag"),
            "https://api.example.com:8443/v1/items"
        );
        assert_eq!(
            redact_url("http://127.0.0.1:4000/x?q=1"),
            "http://127.0.0.1:4000/x"
        );
        assert_eq!(redact_url("data:text/html,<b>hi</b>"), "data:(omitted)");
        assert_eq!(redact_url("blob:https://a.example/123"), "blob:(omitted)");
        assert_eq!(redact_url("not a url"), "(not an address)");
        assert_eq!(redact_url("about:blank"), "about:blank");
    }

    #[test]
    fn console_calls_exceptions_and_log_entries_are_kept_with_their_level() {
        let log = PageLog::default();
        // Shapes as Chrome sends them (Runtime.consoleAPICalled / exceptionThrown, Log.entryAdded).
        assert!(log.on_event(
            "Runtime.consoleAPICalled",
            &json!({"type": "log", "args": [{"type": "string", "value": "hello"}, {"type": "number", "value": 42}]}),
            "http://127.0.0.1:1/a?secret=1",
        ));
        log.on_event(
            "Runtime.consoleAPICalled",
            &json!({"type": "warning", "args": [{"type": "object", "description": "Object"}]}),
            "http://127.0.0.1:1/a",
        );
        log.on_event(
            "Runtime.exceptionThrown",
            &json!({"exceptionDetails": {"text": "Uncaught", "exception": {"description": "TypeError: x is undefined\n    at a.js:1"}}}),
            "http://127.0.0.1:1/a",
        );
        log.on_event(
            "Log.entryAdded",
            &json!({"entry": {"source": "network", "level": "error", "text": "Failed to load resource", "url": "http://127.0.0.1:1/missing.js?v=2"}}),
            "http://127.0.0.1:1/a",
        );
        assert!(!log.on_event("Page.frameNavigated", &json!({}), "x"));
        let every = log.console(ConsoleLevel::Debug, 10, &all);
        assert_eq!(every.len(), 4);
        assert_eq!(every[0].text, "hello 42");
        assert_eq!(
            every[0].page, "http://127.0.0.1:1/a",
            "page shown without its query"
        );
        assert_eq!(every[1].level, ConsoleLevel::Warning);
        assert_eq!(every[2].source, "exception");
        assert!(every[2].text.starts_with("TypeError: x is undefined"));
        assert!(
            !every[2].text.contains('\n'),
            "control characters are stripped"
        );
        assert_eq!(
            every[3].text,
            "Failed to load resource (http://127.0.0.1:1/missing.js)"
        );
        let errors = log.console(ConsoleLevel::Error, 10, &all);
        assert_eq!(errors.len(), 2);
        let last = log.console(ConsoleLevel::Debug, 1, &all);
        assert_eq!(last[0].seq, every[3].seq, "limit keeps the newest");
    }

    #[test]
    fn requests_get_their_status_or_failure_and_never_their_query() {
        let log = PageLog::default();
        let page = "http://127.0.0.1:1/shop";
        log.on_event(
            "Network.requestWillBeSent",
            &json!({"requestId": "1", "type": "Document", "request": {"method": "GET", "url": "http://127.0.0.1:1/shop?session=abc"}}),
            page,
        );
        log.on_event(
            "Network.requestWillBeSent",
            &json!({"requestId": "2", "type": "Fetch", "request": {"method": "POST", "url": "https://api.example/cart?key=k"}}),
            page,
        );
        log.on_event(
            "Network.requestWillBeSent",
            &json!({"requestId": "3", "type": "Script", "request": {"method": "GET", "url": "http://127.0.0.1:1/gone.js"}}),
            page,
        );
        log.on_event(
            "Network.responseReceived",
            &json!({"requestId": "1", "response": {"status": 200, "mimeType": "text/html"}}),
            page,
        );
        log.on_event(
            "Network.responseReceived",
            &json!({"requestId": "3", "response": {"status": 404.0, "mimeType": "text/html"}}),
            page,
        );
        log.on_event(
            "Network.loadingFailed",
            &json!({"requestId": "2", "errorText": "net::ERR_CONNECTION_REFUSED", "canceled": false}),
            page,
        );
        let all_reqs = log.network(false, 10, &all);
        assert_eq!(all_reqs.len(), 3);
        assert_eq!(all_reqs[0].url, "http://127.0.0.1:1/shop");
        assert_eq!(all_reqs[0].status, Some(200));
        assert_eq!(all_reqs[1].method, "POST");
        assert_eq!(all_reqs[1].url, "https://api.example/cart");
        assert_eq!(
            all_reqs[1].failed.as_deref(),
            Some("net::ERR_CONNECTION_REFUSED")
        );
        let problems = log.network(true, 10, &all);
        assert_eq!(
            problems
                .iter()
                .map(|e| e.request_id.as_str())
                .collect::<Vec<_>>(),
            vec!["2", "3"]
        );
        let shown = serde_json::to_string(&all_reqs).unwrap_or_default();
        assert!(!shown.contains("session=") && !shown.contains("key=k"));
        assert!(!shown.contains("request_id"), "internal ids are not shown");
    }

    #[test]
    fn the_logs_are_bounded_and_filtered_by_the_callers_check() {
        let log = PageLog::default();
        for i in 0..(MAX_ENTRIES + 25) {
            let page = if i % 2 == 0 {
                "https://ok.example/"
            } else {
                "https://other.example/"
            };
            log.on_event(
                "Runtime.consoleAPICalled",
                &json!({"type": "log", "args": [{"type": "string", "value": format!("m{i}")}]}),
                page,
            );
        }
        assert_eq!(
            log.console(ConsoleLevel::Debug, usize::MAX, &all).len(),
            MAX_ENTRIES
        );
        let only_ok = log.console(ConsoleLevel::Debug, usize::MAX, &|p: &str| {
            p.starts_with("https://ok.example")
        });
        assert!(only_ok
            .iter()
            .all(|e| e.page.starts_with("https://ok.example")));
        assert_eq!(only_ok.len(), MAX_ENTRIES / 2);
        log.clear();
        assert!(log.console(ConsoleLevel::Debug, 10, &all).is_empty());
        assert!(log.network(false, 10, &all).is_empty());
    }

    #[test]
    fn a_long_message_is_cut() {
        let log = PageLog::default();
        log.on_event(
            "Runtime.consoleAPICalled",
            &json!({"type": "error", "args": [{"type": "string", "value": "x".repeat(5000)}]}),
            "https://a.example/",
        );
        let e = log.console(ConsoleLevel::Error, 1, &all);
        assert!(e[0].text.chars().count() <= MAX_TEXT_CHARS);
    }
}
