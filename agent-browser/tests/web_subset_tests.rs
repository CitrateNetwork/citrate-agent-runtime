//! HUP-S5.3 in the browser: the multi-step web subset (`agent-loop/evals/web-subset-v2.json`), the
//! move runner over live snapshots, and the read-only console and network tools (02 §5).
//!
//! The subset checks run anywhere. The live tests drive a real headless Chromium on pages served
//! from 127.0.0.1 and skip, saying so, when none is installed. The scripted picker below plays a
//! known-good sequence of moves for each task: it proves that every task can be finished with
//! the moves the runner offers and that each end-state check is right, without a model. The scored
//! runs with a real model are in `agent-sidecar/tests/browse_live.rs`.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use citrate_agent_browser::pick::{run_task, Move, Picker, WebSubset};
use citrate_agent_browser::tools::{self, BrowserToolHost};
use citrate_agent_browser::BrowserService;
use citrate_agent_loop::decide::{
    BackendKind, DecideError, DecideRequest, Decision, DecisionPurpose, ProbSource,
};
use citrate_agent_loop::{StopFlag, ToolCall, ToolHost, ToolOutcome};

const SUBSET: &str = include_str!("../../agent-loop/evals/web-subset-v2.json");

fn subset() -> WebSubset {
    match WebSubset::parse(SUBSET) {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    }
}

/// Serve the subset's pages (and `extra`) on 127.0.0.1; returns the base URL.
fn serve_pages(extra: Vec<(String, String)>) -> String {
    let s = subset();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let s = s.clone();
            let extra = extra.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(&stream);
                let mut first = String::new();
                if reader.read_line(&mut first).is_err() {
                    return;
                }
                loop {
                    let mut l = String::new();
                    match reader.read_line(&mut l) {
                        Ok(0) | Err(_) => break,
                        Ok(_) if l == "\r\n" || l == "\n" => break,
                        Ok(_) => {}
                    }
                }
                let path = first.split_whitespace().nth(1).unwrap_or("/").to_string();
                let bare = path.split('?').next().unwrap_or("/").to_string();
                let found = s.page(&path).map(str::to_string).or_else(|| {
                    extra
                        .iter()
                        .find(|(p, _)| *p == bare)
                        .map(|(_, b)| b.clone())
                });
                let (status, body) = match found {
                    Some(b) => ("200 OK", b),
                    None => (
                        "404 Not Found",
                        "<html><title>Not found</title>nope</html>".to_string(),
                    ),
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let mut out = &stream;
                let _ = out.write_all(resp.as_bytes());
            });
        }
    });
    format!("http://{addr}")
}

/// One scripted step: an option whose label contains `needle` under `op` (`click`, `type`,
/// `enter`), or `done`. For `type`, `value` is the value that goes in.
struct Script {
    steps: Vec<(&'static str, &'static str, Option<&'static str>)>,
    at: Mutex<usize>,
    pending_value: Mutex<Option<&'static str>>,
}

impl Script {
    fn new(steps: Vec<(&'static str, &'static str, Option<&'static str>)>) -> Self {
        Script {
            steps,
            at: Mutex::new(0),
            pending_value: Mutex::new(None),
        }
    }
}

fn decision(req: &DecideRequest, choice: String) -> Decision {
    Decision {
        choice,
        probs: Vec::new(),
        confidence: None,
        probs_source: ProbSource::None,
        backend: BackendKind::Local,
        purpose: req.purpose,
        n_options: req.options.len(),
        latency_ms: 0,
        egress: None,
    }
}

impl Picker for Script {
    fn decide(&self, req: &DecideRequest) -> Result<Decision, DecideError> {
        if req.purpose == DecisionPurpose::Choose {
            let want = self
                .pending_value
                .lock()
                .map_err(|_| DecideError::Backend("lock".into()))?
                .take()
                .ok_or_else(|| DecideError::BadAnswer("no value scripted".into()))?;
            let o = req
                .options
                .iter()
                .find(|o| o.label == format!("\"{want}\""))
                .ok_or_else(|| DecideError::BadAnswer(format!("value {want} not offered")))?;
            return Ok(decision(req, o.id.clone()));
        }
        let mut at = self
            .at
            .lock()
            .map_err(|_| DecideError::Backend("lock".into()))?;
        let (op, needle, value) = self
            .steps
            .get(*at)
            .copied()
            .ok_or_else(|| DecideError::BadAnswer("script ran out".into()))?;
        *at += 1;
        if op == "done" {
            return Ok(decision(req, "done".into()));
        }
        let o = req
            .options
            .iter()
            .find(|o| o.id.starts_with(&format!("{op}:")) && o.label.contains(needle))
            .ok_or_else(|| {
                DecideError::BadAnswer(format!(
                    "no {op} option containing {needle:?} in {:?}",
                    req.options.iter().map(|o| &o.label).collect::<Vec<_>>()
                ))
            })?;
        if let Some(v) = value {
            if let Ok(mut p) = self.pending_value.lock() {
                *p = Some(v);
            }
        }
        Ok(decision(req, o.id.clone()))
    }
}

fn scripts() -> Vec<(&'static str, Script)> {
    vec![
        (
            "search-open-result",
            Script::new(vec![
                ("type", "searchbox \"Search\"", None),
                ("enter", "searchbox \"Search\"", None),
                ("click", "Citrate BlockDAG overview", None),
                ("done", "", None),
            ]),
        ),
        (
            "shop-size-cart",
            Script::new(vec![
                ("click", "link \"Trail Runner 4\"", None),
                ("click", "radio \"Size 10\"", None),
                ("click", "button \"Add to cart\"", None),
                ("done", "", None),
            ]),
        ),
        (
            "login-email",
            Script::new(vec![
                ("type", "textbox \"Email\"", None),
                ("click", "button \"Continue\"", None),
                ("done", "", None),
            ]),
        ),
        (
            "cookies-then-article",
            Script::new(vec![
                ("click", "button \"Reject all\"", None),
                ("click", "link \"Rust 2.0 ships\"", None),
                ("done", "", None),
            ]),
        ),
        (
            "pagination-page-3",
            Script::new(vec![
                ("click", "link \"Next page\"", None),
                ("click", "link \"Next page\"", None),
                ("done", "", None),
            ]),
        ),
        (
            "filter-stock-price",
            Script::new(vec![
                ("click", "checkbox \"In stock only\"", None),
                ("click", "checkbox \"Under $50\"", None),
                ("click", "button \"Apply filters\"", None),
                ("done", "", None),
            ]),
        ),
        (
            "contact-form",
            Script::new(vec![
                ("type", "textbox \"Your name\"", Some("Ada")),
                ("type", "textbox \"Your email\"", Some("ada@example.org")),
                ("type", "textbox \"Message\"", Some("Hello from Hermes")),
                ("click", "button \"Send\"", None),
                ("done", "", None),
            ]),
        ),
        (
            "settings-email-alerts",
            Script::new(vec![
                ("click", "tab \"Notifications\"", None),
                ("click", "checkbox \"Email alerts\"", None),
                ("click", "button \"Save notifications\"", None),
                ("done", "", None),
            ]),
        ),
        (
            "docs-deploy-guide",
            Script::new(vec![
                ("click", "link \"Guides\"", None),
                ("click", "link \"Deploy a contract\"", None),
                ("done", "", None),
            ]),
        ),
        (
            "package-changelog-2",
            Script::new(vec![
                ("click", "link \"v2.0 (latest)\"", None),
                ("click", "link \"Changelog\"", None),
                ("done", "", None),
            ]),
        ),
    ]
}

#[test]
fn the_subset_has_ten_to_twelve_well_formed_multi_step_tasks() {
    let s = subset();
    assert_eq!(s.suite, "web-subset-v2");
    assert!((8..=12).contains(&s.tasks.len()), "{}", s.tasks.len());
    let mut ids = std::collections::HashSet::new();
    for t in &s.tasks {
        assert!(ids.insert(t.id.clone()), "duplicate {}", t.id);
        assert!(
            t.id.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "task ids are slugs (metering): {}",
            t.id
        );
        assert!(s.page(&t.start).is_some(), "{}: no start page", t.id);
        assert!(
            t.success.url_contains.is_some() || t.success.text_contains.is_some(),
            "{}: no end-state check",
            t.id
        );
        for v in &t.values {
            assert!(
                t.goal.contains(v.as_str()),
                "{}: value {v} is not in the goal",
                t.id
            );
        }
    }
    // Every scripted task exists and every task has a script (the live test plays them all).
    let scripted: Vec<&str> = scripts().iter().map(|(id, _)| *id).collect();
    for t in &s.tasks {
        assert!(scripted.contains(&t.id.as_str()), "{} has no script", t.id);
    }
    assert_eq!(scripted.len(), s.tasks.len());
}

#[test]
fn the_page_lookup_ignores_query_strings() {
    let s = subset();
    assert!(s.page("/list?page=3").is_some());
    assert!(s.page("/news/rust?cookies=rejected").is_some());
    assert!(s.page("/nope").is_none());
}

#[test]
fn every_task_can_be_finished_with_the_offered_moves_live() {
    let Some(exe) = common::chromium() else {
        return;
    };
    let base = serve_pages(Vec::new());
    let s = subset();
    for (id, script) in scripts() {
        let task = s
            .tasks
            .iter()
            .find(|t| t.id == id)
            .unwrap_or_else(|| panic!("no task {id}"));
        let svc = BrowserService::new(common::config(exe.clone()));
        let run = run_task(&svc, &script, &base, task, true);
        assert!(
            run.success,
            "{id}: the scripted moves did not finish the task: {run:#?}"
        );
        assert!(
            run.declared_done && run.reached && run.error.is_none(),
            "{id}"
        );
        assert_eq!(
            run.snapshots.len(),
            run.steps.len(),
            "one live snapshot per step"
        );
        assert!(
            run.steps[..run.steps.len() - 1]
                .iter()
                .all(|s| s.page_changed),
            "{id}: every scripted move changes the page: {:#?}",
            run.steps
        );
        assert!(run.steps.iter().all(|s| s.error.is_none()), "{id}");
    }
}

#[test]
fn stopping_early_or_on_the_wrong_page_is_not_a_success_live() {
    let Some(exe) = common::chromium() else {
        return;
    };
    let base = serve_pages(Vec::new());
    let s = subset();
    let task = s
        .tasks
        .iter()
        .find(|t| t.id == "cookies-then-article")
        .expect("task");
    // Skipping the cookie choice opens the article, but the check needs the rejection.
    let wrong = Script::new(vec![
        ("click", "link \"Rust 2.0 ships\"", None),
        ("done", "", None),
    ]);
    let svc = BrowserService::new(common::config(exe.clone()));
    let run = run_task(&svc, &wrong, &base, task, false);
    assert!(
        run.declared_done && !run.success && !run.reached,
        "{run:#?}"
    );
    // A control whose last two clicks changed nothing is no longer offered for clicking.
    let settings = s
        .tasks
        .iter()
        .find(|t| t.id == "settings-email-alerts")
        .expect("task");
    let stuck = Script::new(vec![
        ("click", "tab \"Profile\"", None),
        ("click", "tab \"Profile\"", None),
        ("click", "tab \"Profile\"", None),
    ]);
    let svc = BrowserService::new(common::config(exe));
    let run = run_task(&svc, &stuck, &base, settings, false);
    assert!(!run.success);
    assert_eq!(run.steps.len(), 2, "{run:#?}");
    assert!(run.steps.iter().all(|s| !s.page_changed), "{run:#?}");
    assert_eq!(
        run.error.as_deref(),
        Some("decide failed at step 3: bad_answer"),
        "the third click was not offered"
    );
}

const LOGS: &str = r#"<!doctype html><html><head><title>Logs</title></head><body><h1>Logs</h1>
<script>
console.log('ready', 3);
console.warn('slow image');
console.error('cart failed');
fetch('/api/cart?token=abc123').catch(function(){});
setTimeout(function(){ throw new Error('boom'); }, 0);
</script></body></html>"#;

fn call(name: &str, args: &str) -> ToolCall {
    ToolCall {
        id: "c1".into(),
        name: name.into(),
        arguments: args.into(),
    }
}

fn text(o: ToolOutcome) -> String {
    match o {
        ToolOutcome::Untrusted(s) => s,
        other => panic!("expected untrusted output, got {other:?}"),
    }
}

#[test]
fn console_and_network_tools_read_what_the_page_did_live() {
    let Some(exe) = common::chromium() else {
        return;
    };
    let base = serve_pages(vec![("/logs".to_string(), LOGS.to_string())]);
    let svc = Arc::new(BrowserService::new(common::config(exe)));
    let host = BrowserToolHost::new(svc.clone(), StopFlag::default());
    // Before any page is open the read-only tools launch nothing.
    match host.execute(&call(tools::CONSOLE, "{}")) {
        ToolOutcome::Error(e) => assert!(e.contains("no page open"), "{e}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(svc.status().mode, "off");
    let _ = text(host.execute(&call(
        tools::NAVIGATE,
        &format!(r#"{{"url": "{base}/logs"}}"#),
    )));
    std::thread::sleep(std::time::Duration::from_millis(600));
    let all = text(host.execute(&call(tools::CONSOLE, "{}")));
    assert!(all.contains("untrusted data"), "{all}");
    for want in [
        "info (console",
        "ready 3",
        "slow image",
        "cart failed",
        "boom",
    ] {
        assert!(all.contains(want), "{want} missing: {all}");
    }
    let errors = text(host.execute(&call(tools::CONSOLE, r#"{"level": "error"}"#)));
    assert!(
        errors.contains("cart failed") && !errors.contains("slow image"),
        "{errors}"
    );
    let net = text(host.execute(&call(tools::NETWORK, "{}")));
    assert!(net.contains("/logs (Document) -> 200"), "{net}");
    assert!(net.contains("/api/cart (Fetch) -> 404"), "{net}");
    assert!(
        !net.contains("token"),
        "query strings are never shown: {net}"
    );
    let problems = text(host.execute(&call(tools::NETWORK, r#"{"problems_only": true}"#)));
    assert!(
        problems.contains("/api/cart") && !problems.contains("/logs (Document)"),
        "{problems}"
    );
    match host.execute(&call(tools::NETWORK, r#"{"limit": 0}"#)) {
        ToolOutcome::Error(e) => assert!(e.contains("limit"), "{e}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn browser_pick_suggests_a_move_and_does_nothing_live() {
    let Some(exe) = common::chromium() else {
        return;
    };
    let base = serve_pages(Vec::new());
    let svc = Arc::new(BrowserService::new(common::config(exe)));
    let host = BrowserToolHost::new(svc.clone(), StopFlag::default());
    match host.execute(&call(tools::PICK, r#"{"goal": "Open the guides"}"#)) {
        ToolOutcome::Error(e) => assert!(e.contains("not configured"), "{e}"),
        other => panic!("{other:?}"),
    }
    let host = host.with_picker(Arc::new(Script::new(vec![(
        "click",
        "link \"Guides\"",
        None,
    )])));
    let _ = text(host.execute(&call(
        tools::NAVIGATE,
        &format!(r#"{{"url": "{base}/docs"}}"#),
    )));
    let out = text(host.execute(&call(tools::PICK, r#"{"goal": "Open the guides"}"#)));
    assert!(
        out.contains("Suggested next move: Click link \"Guides\""),
        "{out}"
    );
    assert!(out.contains("nothing was done"), "{out}");
    assert!(out.contains("browser_act with ref"), "{out}");
    assert!(svc.status().url.ends_with("/docs"), "the page did not move");
    let parsed = Move::parse("click:e2");
    assert_eq!(parsed, Some(Move::Click("e2".into())));
}
