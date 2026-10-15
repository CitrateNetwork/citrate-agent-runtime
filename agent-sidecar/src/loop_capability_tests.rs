//! HGW-4 — the loop can finish a build: more steps per turn by default (8 → 24, configurable),
//! and a failing command or toolchain run hands the model its exit status and the end of its
//! output (bounded), so it can read the cause and fix it.
//!
//! BDD map:
//! - `a_session_runs_up_to_24_steps_by_default`
//! - `max_steps_is_configurable_per_session_and_per_sidecar`
//! - `the_sidecar_default_comes_from_the_environment` (CITRATE_HERMES_MAX_STEPS)
//! - shell_run and toolchain failures: `shell_run_tests::a_failing_command_reports_*`,
//!   `toolchain::tests::an_unparsed_report_hands_back_the_end_of_stderr_as_untrusted`.

#![cfg(unix)]

use super::hgw_support::*;
use super::*;
use citrate_agent_loop::AssistantTurn;

fn list_calls(fx: &Fx, n: usize) -> Vec<AssistantTurn> {
    let mut t: Vec<AssistantTurn> = (0..n)
        .map(|i| {
            AssistantTurn::tools(vec![tool_call(
                &format!("l{i}"),
                grants::FILE_LIST_TOOL,
                serde_json::json!({ "path": fx.proj() }),
            )])
        })
        .collect();
    t.push(AssistantTurn::text("Listed."));
    t
}

async fn outcome(mgr: Arc<sessions::SessionManager>, req: sessions::CreateSessionReq) -> String {
    let id = mgr.create(req).expect("session");
    let s = mgr.get(&id).expect("session");
    mgr.send(&id, "list it a lot".into(), None).expect("send");
    wait_done(&s).await;
    events(&s)
        .into_iter()
        .rev()
        .find(|e| e["type"] == "done")
        .map(|e| e["outcome"].as_str().unwrap_or_default().to_string())
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_runs_up_to_24_steps_by_default() {
    let fx = Fx::new("steps-default");
    // 20 tool steps and an answer: more than the old default of 8.
    let mgr = Arc::new(manager_with(&fx, list_calls(&fx, 20), None));
    assert_eq!(
        outcome(mgr, create_req(fx.rw_doc(), true)).await,
        "answered"
    );
    assert_eq!(sessions::DEFAULT_MAX_STEPS, 24);
}

#[tokio::test(flavor = "multi_thread")]
async fn max_steps_is_configurable_per_session_and_per_sidecar() {
    let fx = Fx::new("steps-config");
    let mgr = Arc::new(manager_with(&fx, list_calls(&fx, 20), None));
    let req = create_req_with(fx.rw_doc(), true, serde_json::json!({"maxSteps": 4})).expect("req");
    assert_eq!(outcome(mgr, req).await, "step_limit");
    // A sidecar-wide default below the work also stops it; a session's own maxSteps wins.
    let mgr = Arc::new(manager_with(&fx, list_calls(&fx, 10), None).with_default_max_steps(6));
    assert_eq!(
        outcome(mgr, create_req(fx.rw_doc(), true)).await,
        "step_limit"
    );
    let mgr = Arc::new(manager_with(&fx, list_calls(&fx, 10), None).with_default_max_steps(6));
    let req = create_req_with(fx.rw_doc(), true, serde_json::json!({"maxSteps": 12})).expect("req");
    assert_eq!(outcome(mgr, req).await, "answered");
}

#[test]
fn the_sidecar_default_comes_from_the_environment() {
    assert_eq!(
        sessions::max_steps_from_env(None),
        sessions::DEFAULT_MAX_STEPS
    );
    assert_eq!(sessions::max_steps_from_env(Some("16")), 16);
    assert_eq!(
        sessions::max_steps_from_env(Some("999")),
        sessions::MAX_STEPS_CAP
    );
    assert_eq!(sessions::max_steps_from_env(Some("0")), 1);
    assert_eq!(
        sessions::max_steps_from_env(Some("lots")),
        sessions::DEFAULT_MAX_STEPS
    );
}
