//! HUP-S5.3 AC1/AC3, live: the managed browser finishes the multi-step web subset
//! (`agent-loop/evals/web-subset-v2.json`) with the `decide()` slot picking every move over real
//! snapshot refs, through the sidecar's metered decide service on a real llama-server. Each task's
//! result is recorded through `POST /decide/outcomes` and the per-backend report is read back from
//! `GET /decide/stats`.
//!
//! Ignored by default (it needs a Chromium and a running model). Run it with:
//!
//! ```text
//! CITRATE_DECIDE_LIVE_URL=http://127.0.0.1:18091/v1 CITRATE_DECIDE_LIVE_MODEL=gemma-4-e4b \
//!   CITRATE_BROWSER_CHROMIUM=<chrome for testing executable> \
//!   CITRATE_BROWSE_LIVE_OUT=/tmp/web-subset-v2-run.json \
//!   cargo test -p agent-sidecar --test browse_live -- --ignored --nocapture
//! ```
//!
//! The success rate is the measurement: the test fails only when the run itself could not happen
//! (no browser, a decide transport error on every task, or a route refusing an outcome).

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;

use agent_sidecar::decide::{DecideService, SessionPicker};
use agent_sidecar::sessions::{LlmEndpoint, SessionManager};
use agent_sidecar::{app, AppState, MAX_CONCURRENT_SKILLS};
use axum::body::Body;
use axum::http::Request;
use citrate_agent_browser::chromium::{discover, system_candidates, MANAGED_CHROMIUM_ENV};
use citrate_agent_browser::pick::{run_task, TaskRun, WebSubset};
use citrate_agent_browser::{BrowserConfig, BrowserService};
use citrate_agent_core::hitl::ApprovalQueue;
use citrate_agent_legacy::estop::EmergencyStop;
use tower::ServiceExt;

const SUBSET: &str = include_str!("../../agent-loop/evals/web-subset-v2.json");
const BEARER: &str = "browse-live-bearer-0123456789abcdef";

fn serve(s: WebSubset) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let s = s.clone();
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
                let (status, body) = match s.page(&path) {
                    Some(b) => ("200 OK", b.to_string()),
                    None => (
                        "404 Not Found",
                        "<html><title>Not found</title>nope</html>".into(),
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

#[test]
#[ignore = "needs a Chromium and a running llama-server (CITRATE_DECIDE_LIVE_URL)"]
fn the_managed_browser_finishes_the_web_subset_with_decide_picking_every_move() {
    let Ok(url) = std::env::var("CITRATE_DECIDE_LIVE_URL") else {
        eprintln!("CITRATE_DECIDE_LIVE_URL is not set; nothing to run");
        return;
    };
    let model = std::env::var("CITRATE_DECIDE_LIVE_MODEL").unwrap_or_else(|_| "local".into());
    let bearer = std::env::var("CITRATE_DECIDE_LIVE_BEARER").unwrap_or_default();
    let managed = std::env::var_os(MANAGED_CHROMIUM_ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    let chromium = discover(managed.as_deref(), &system_candidates());
    let Some(exe) = chromium.path() else {
        eprintln!("SKIPPED: no Chromium is installed");
        return;
    };
    println!("browser: {chromium:?}");
    let subset = WebSubset::parse(SUBSET).expect("subset");
    let base = serve(subset.clone());

    let decide = Arc::new(DecideService::default());
    let mgr = SessionManager::new(
        Arc::new(
            |_ep: &LlmEndpoint| -> Arc<dyn citrate_agent_loop::LlmClient> {
                Arc::new(agent_sidecar::llm_http::OpenAiCompatClient::new(
                    "http://127.0.0.1:9",
                    "",
                    std::time::Duration::from_secs(1),
                ))
            },
        ),
        std::time::Duration::from_secs(5),
    )
    .with_decide(decide.clone());
    let state = Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: Arc::new(ApprovalQueue::new()),
        skills: vec![],
        dispatch: None,
        bearer: BEARER.to_string(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
        sessions: Arc::new(mgr),
    });
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let picker = SessionPicker::new(
        decide.clone(),
        serde_json::from_value(serde_json::json!({"baseUrl": url, "bearer": bearer}))
            .expect("endpoint"),
        &model,
    );
    // One browser for the whole run (the fixture pages keep no state between tasks); generous
    // timeouts because a loaded machine can take many seconds to start Chromium (A51).
    let svc = BrowserService::new(BrowserConfig {
        managed_path: Some(exe.clone()),
        candidates: Vec::new(),
        launch_timeout: std::time::Duration::from_secs(90),
        command_timeout: std::time::Duration::from_secs(30),
        navigation_timeout: std::time::Duration::from_secs(40),
        ..BrowserConfig::default()
    });
    let mut runs: Vec<TaskRun> = Vec::new();
    for task in &subset.tasks {
        let run = run_task(&svc, &picker, &base, task, true);
        println!(
            "{}: success {} (done {}, reached {}), {} steps{}",
            run.task_id,
            run.success,
            run.declared_done,
            run.reached,
            run.steps.len(),
            run.error
                .as_deref()
                .map(|e| format!(", {e}"))
                .unwrap_or_default()
        );
        let body = serde_json::json!({
            "backend": "local",
            "suite": subset.suite,
            "taskId": run.task_id,
            "success": run.success,
        });
        let resp = rt.block_on(
            app(state.clone()).oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/decide/outcomes")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {BEARER}"))
                    .body(Body::from(body.to_string()))
                    .expect("request"),
            ),
        );
        let ok = resp.map(|r| r.status().is_success()).unwrap_or(false);
        assert!(ok, "POST /decide/outcomes refused {body}");
        runs.push(run);
    }
    let stats = rt
        .block_on(
            app(state.clone()).oneshot(
                Request::builder()
                    .uri("/decide/stats")
                    .header("authorization", format!("Bearer {BEARER}"))
                    .body(Body::empty())
                    .expect("request"),
            ),
        )
        .expect("stats");
    let bytes = rt
        .block_on(axum::body::to_bytes(stats.into_body(), 1 << 20))
        .unwrap_or_default();
    let stats: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    println!(
        "{}",
        serde_json::to_string_pretty(&stats).unwrap_or_default()
    );
    let succeeded = runs.iter().filter(|r| r.success).count();
    println!(
        "web-subset-v2 local ({model}): {succeeded}/{} = {:.1}%",
        runs.len(),
        succeeded as f64 * 100.0 / runs.len().max(1) as f64
    );
    if let Ok(out) = std::env::var("CITRATE_BROWSE_LIVE_OUT") {
        let doc = serde_json::json!({
            "suite": subset.suite,
            "backend": "local",
            "model": model,
            "browser": format!("{chromium:?}"),
            "runs": runs,
            "stats": stats,
        });
        std::fs::write(&out, serde_json::to_string_pretty(&doc).unwrap_or_default())
            .expect("write the run record");
        println!("run record written to {out}");
    }
    assert_eq!(
        stats["report"]["backends"]["local"]["tasks_attempted"]
            .as_u64()
            .or_else(|| stats["report"]["backends"]["local"]["tasksAttempted"].as_u64()),
        Some(subset.tasks.len() as u64),
        "every task outcome is in the metering"
    );
    assert!(
        runs.iter().any(|r| !r.steps.is_empty()),
        "no task got a single decision: {runs:#?}"
    );
}
