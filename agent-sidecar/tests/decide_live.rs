//! HUP-S5.3 AC1/AC3, live: the local grammar backend against a real llama-server, scored on the
//! WebVoyager-style single-step subset (`agent-loop/evals/web-subset-v1.json`).
//!
//! Ignored by default (it needs a running model). Run it with:
//!
//! ```text
//! CITRATE_DECIDE_LIVE_URL=http://127.0.0.1:18091/v1 CITRATE_DECIDE_LIVE_MODEL=gemma-4-e4b \
//!   cargo test -p agent-sidecar --test decide_live -- --ignored --nocapture
//! ```
//!
//! It prints the suite result as JSON (per-task choice, latency, confidence) and the per-backend
//! metering report, and fails only when a decision errors (a bad grammar answer or transport
//! failure), not on a wrong pick: the success rate is the measurement.

use agent_sidecar::decide::HttpDecideTransport;
use citrate_agent_loop::decide::{run_suite, BackendPref, Decider, LocalGrammarBackend, WebTask};
use citrate_agent_metering::{DecisionLine, DecisionReport, TaskRecord};
use std::sync::Arc;
use std::time::Duration;

#[test]
#[ignore = "needs a running llama-server (CITRATE_DECIDE_LIVE_URL)"]
fn local_backend_scores_the_web_subset_on_a_real_model() {
    let Ok(url) = std::env::var("CITRATE_DECIDE_LIVE_URL") else {
        eprintln!("CITRATE_DECIDE_LIVE_URL is not set; nothing to run");
        return;
    };
    let model = std::env::var("CITRATE_DECIDE_LIVE_MODEL").unwrap_or_else(|_| "local".into());
    let bearer = std::env::var("CITRATE_DECIDE_LIVE_BEARER").unwrap_or_default();
    let tasks: Vec<WebTask> =
        serde_json::from_str(include_str!("../../agent-loop/evals/web-subset-v1.json"))
            .expect("subset fixture");
    let transport = Arc::new(HttpDecideTransport::chat_completions(
        &url,
        &bearer,
        Duration::from_secs(120),
    ));
    let decider = Decider::local_only(LocalGrammarBackend::new(transport, &model));
    let result = run_suite(&decider, BackendPref::Local, &tasks);
    println!(
        "{}",
        serde_json::to_string_pretty(&result).unwrap_or_default()
    );
    let lines: Vec<DecisionLine> = result
        .outcomes
        .iter()
        .filter_map(|o| {
            TaskRecord::new(0, result.backend, "web-subset-v1", &o.task_id, o.success)
                .ok()
                .map(DecisionLine::Task)
        })
        .collect();
    println!("{}", DecisionReport::build(&lines).to_markdown());
    println!(
        "success rate: {}/{} = {:.1}%",
        result.succeeded,
        result.attempted,
        result.success_rate() * 100.0
    );
    assert_eq!(result.errors, 0, "decisions errored: {result:?}");
}
