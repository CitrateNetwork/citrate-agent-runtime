//! HUP-S7.5 + S9.3 sidecar wiring: every session meters its turns (records derived from the loop's
//! event stream, tokens from the model client when the provider reports them), the daily report
//! route serves real numbers with unknowns left unknown, and trajectory recording is off unless
//! configured. Driven over the real control-plane routes (tower::oneshot, no socket).

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_loop::{
    AssistantTurn, CompletionRequest, LlmClient, LlmError, TokenUsage, ToolCall,
};
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-metering-0001";
const CANARY: &str = "canary-content-7f3e9a";

/// A scripted model that reports usage on every call when `usage` is set.
struct Script {
    turns: Mutex<Vec<AssistantTurn>>,
    usage: Option<TokenUsage>,
}
impl LlmClient for Script {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        self.complete_with_usage(req).map(|(t, _)| t)
    }
    fn complete_with_usage(
        &self,
        _req: &CompletionRequest,
    ) -> Result<(AssistantTurn, Option<TokenUsage>), LlmError> {
        let mut t = self.turns.lock().unwrap();
        let turn = if t.is_empty() {
            AssistantTurn::text("(done)")
        } else {
            t.remove(0)
        };
        Ok((turn, self.usage))
    }
}

fn manager(turns: Vec<AssistantTurn>, usage: Option<TokenUsage>) -> sessions::SessionManager {
    let script: Arc<dyn LlmClient> = Arc::new(Script {
        turns: Mutex::new(turns),
        usage,
    });
    sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| script.clone()),
        Duration::from_secs(5),
    )
}

fn state(mgr: sessions::SessionManager) -> Arc<AppState> {
    Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: Arc::new(ApprovalQueue::new()),
        skills: vec![],
        dispatch: None,
        bearer: BEARER.to_string(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
        sessions: Arc::new(mgr),
    })
}

fn req(method: &str, path: &str, body: serde_json::Value, auth: bool) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if auth {
        b = b.header("authorization", format!("Bearer {BEARER}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

async fn json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

async fn create(st: &Arc<AppState>, tools: serde_json::Value) -> String {
    let body = serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes.",
        "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        "tools": tools,
    });
    let r = app(st.clone())
        .oneshot(req("POST", "/sessions", body, true))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    json(r).await["id"].as_str().unwrap().to_string()
}

/// Send one message and wait until the session is idle again (the turn has fully finished,
/// including the metering append that follows it).
async fn turn(st: &Arc<AppState>, id: &str, text: &str) {
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/messages"),
            serde_json::json!({ "text": text }),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::ACCEPTED);
    for _ in 0..200 {
        let s = st.sessions.get(id).unwrap();
        if !s.is_busy() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the turn did not finish");
}

fn today() -> String {
    citrate_agent_metering::utc_day_of_ms(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    )
}

async fn daily(st: &Arc<AppState>, day: &str) -> (StatusCode, serde_json::Value) {
    let r = app(st.clone())
        .oneshot(req(
            "GET",
            &format!("/metering/daily?day={day}"),
            serde_json::Value::Null,
            true,
        ))
        .await
        .unwrap();
    let s = r.status();
    (s, json(r).await)
}

fn no_tools() -> serde_json::Value {
    serde_json::json!([])
}

// ---------------------------------------------------------------------------------------------
// usage from the provider response

#[test]
fn usage_is_parsed_from_the_provider_response_when_present() {
    let body = r#"{"choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":31,"completion_tokens":7,"total_tokens":38}}"#;
    assert_eq!(
        llm_http::parse_usage(body),
        Some(TokenUsage {
            prompt_tokens: 31,
            completion_tokens: 7,
            generation_ms: None,
        })
    );
}

#[test]
fn missing_or_malformed_usage_is_unknown_not_zero() {
    for body in [
        r#"{"choices":[{"message":{"content":"hi"}}]}"#,
        r#"{"choices":[],"usage":{"prompt_tokens":"many"}}"#,
        r#"{"usage":{"completion_tokens":3}}"#,
        r#"{"usage":{"prompt_tokens":5}}"#,
        r#"{"usage":{"prompt_tokens":-1,"completion_tokens":2}}"#,
        r#"{"usage":null}"#,
        "not json",
    ] {
        assert_eq!(llm_http::parse_usage(body), None, "{body}");
    }
}

// ---------------------------------------------------------------------------------------------
// metering in sessions + the daily report route

#[tokio::test]
async fn a_turn_produces_a_metering_record_with_reported_tokens() {
    let st = state(manager(
        vec![AssistantTurn::text("hello")],
        Some(TokenUsage {
            prompt_tokens: 12,
            completion_tokens: 3,
            generation_ms: None,
        }),
    ));
    let id = create(&st, no_tools()).await;
    turn(&st, &id, "hi there").await;
    let (s, v) = daily(&st, &today()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["day"], today());
    assert_eq!(v["report"]["turns"], 1);
    assert_eq!(v["report"]["sessions"], 1);
    assert_eq!(v["report"]["outcomes"]["answered"], 1);
    assert_eq!(v["report"]["tokens"]["tokens_in"], 12);
    assert_eq!(v["report"]["tokens"]["tokens_out"], 3);
    assert_eq!(v["report"]["tokens"]["turns_reporting"], 1);
    // an answered turn with no verifier is unverified, never a success
    assert_eq!(v["report"]["verification"]["unverified"], 1);
    assert!(v["report"]["verified_success_bps"].is_null());
    assert_eq!(v["source"], "memory");
    assert_eq!(v["persisted"], false);
}

#[tokio::test]
async fn tokens_stay_unknown_when_the_provider_reports_none() {
    let st = state(manager(vec![AssistantTurn::text("hello")], None));
    let id = create(&st, no_tools()).await;
    turn(&st, &id, "hi").await;
    let (_, v) = daily(&st, &today()).await;
    assert_eq!(v["report"]["turns"], 1);
    assert_eq!(v["report"]["tokens"]["turns_reporting"], 0);
    let md = v["markdown"].as_str().unwrap();
    assert!(md.contains("tokens reported for 0 of 1 turns"), "{md}");
}

#[tokio::test]
async fn usage_from_every_step_of_a_turn_is_summed() {
    let call = ToolCall {
        id: "c1".into(),
        name: "nope".into(),
        arguments: "{}".into(),
    };
    let st = state(manager(
        vec![AssistantTurn::tools(vec![call]), AssistantTurn::text("ok")],
        Some(TokenUsage {
            prompt_tokens: 10,
            completion_tokens: 2,
            generation_ms: None,
        }),
    ));
    let id = create(&st, no_tools()).await;
    turn(&st, &id, "do it").await;
    let (_, v) = daily(&st, &today()).await;
    assert_eq!(v["report"]["turns"], 1);
    assert_eq!(v["report"]["steps_total"], 2);
    assert_eq!(v["report"]["tokens"]["tokens_in"], 20);
    assert_eq!(v["report"]["tokens"]["tokens_out"], 4);
    // a model-invented tool name is pooled, never recorded verbatim
    assert!(
        v["report"]["tool_calls"]["(unknown tool)"].is_object(),
        "{v}"
    );
    assert!(v["report"]["tool_calls"].get("nope").is_none());
}

#[tokio::test]
async fn the_report_lists_what_is_not_measured_yet() {
    let st = state(manager(vec![], None));
    let (s, v) = daily(&st, &today()).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["report"]["turns"], 0);
    let nm: Vec<String> = v["notMeasured"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    for m in ["time to first token", "SALT spent", "energy estimate"] {
        assert!(nm.iter().any(|x| x == m), "{m} missing from {nm:?}");
    }
}

#[tokio::test]
async fn the_daily_route_needs_the_bearer_and_a_valid_day() {
    let st = state(manager(vec![], None));
    let r = app(st.clone())
        .oneshot(req(
            "GET",
            "/metering/daily?day=2026-10-01",
            serde_json::Value::Null,
            false,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    for bad in ["2026-13-01", "yesterday", "2026-1-1"] {
        let (s, _) = daily(&st, bad).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
    }
    // no day = today (UTC)
    let r = app(st.clone())
        .oneshot(req("GET", "/metering/daily", serde_json::Value::Null, true))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(json(r).await["day"], today());
}

#[tokio::test]
async fn a_persistent_store_survives_a_restart_and_holds_no_content() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(metering::MeteringStore::persistent(dir.path()));
    let st = state(manager(vec![AssistantTurn::text(CANARY)], None).with_metering(store));
    let id = create(&st, no_tools()).await;
    turn(&st, &id, &format!("please {CANARY}")).await;
    let (_, v) = daily(&st, &today()).await;
    assert_eq!(v["source"], "log");
    assert_eq!(v["persisted"], true);
    assert_eq!(v["report"]["turns"], 1);

    let log = std::fs::read_to_string(dir.path().join(metering::METERING_LOG_FILE)).unwrap();
    assert_eq!(log.lines().count(), 1);
    assert!(!log.contains(CANARY), "metering must not record content");

    // a fresh store over the same directory (a sidecar restart) reads the same day
    let st2 = state(
        manager(vec![], None)
            .with_metering(Arc::new(metering::MeteringStore::persistent(dir.path()))),
    );
    let (_, v2) = daily(&st2, &today()).await;
    assert_eq!(v2["report"]["turns"], 1);
}

#[tokio::test]
async fn the_benchmark_payload_route_builds_calldata_only_for_an_opt_in() {
    let st = state(manager(vec![AssistantTurn::text("x")], None));
    let id = create(&st, no_tools()).await;
    turn(&st, &id, "hi").await;
    let post = |body: serde_json::Value| {
        let st = st.clone();
        async move {
            let r = app(st)
                .oneshot(req("POST", "/metering/benchmark", body, true))
                .await
                .unwrap();
            let s = r.status();
            (s, json(r).await)
        }
    };
    // no registry or agent id: not an opt-in
    let (s, _) = post(serde_json::json!({ "day": today() })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // a malformed registry address is refused
    let (s, _) =
        post(serde_json::json!({ "day": today(), "agentId": "7", "registry": "0x1234" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let registry = "0x00000000000000000000000000000000000000b1";
    let (s, v) =
        post(serde_json::json!({ "day": today(), "agentId": "7", "registry": registry })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["sent"], false);
    assert_eq!(v["to"], registry);
    assert_eq!(v["chain_id"], 40204);
    assert!(!v["calls"].as_array().unwrap().is_empty());
    // a day with no turns has nothing to share
    let (s, _) =
        post(serde_json::json!({ "day": "2001-01-01", "agentId": "7", "registry": registry }))
            .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
}

// ---------------------------------------------------------------------------------------------
// trajectories: off by default, opt-in by configuration, exported at close

#[tokio::test]
async fn trajectories_are_off_by_default() {
    let st = state(manager(vec![AssistantTurn::text("x")], None));
    assert!(st.sessions.trajectories().is_none());
    let id = create(&st, no_tools()).await;
    turn(&st, &id, "hi").await;
    let r = app(st.clone())
        .oneshot(req(
            "DELETE",
            &format!("/sessions/{id}"),
            serde_json::Value::Null,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = json(r).await;
    assert!(
        v.get("trajectory").is_none() || v["trajectory"].is_null(),
        "{v}"
    );
}

#[tokio::test]
async fn an_opted_in_session_writes_a_report_at_close_and_exports_only_verified_turns() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = trajectory::TrajectoryConfig::new(dir.path().to_path_buf());
    let st = state(manager(vec![AssistantTurn::text(CANARY)], None).with_trajectories(cfg));
    let id = create(&st, no_tools()).await;
    turn(&st, &id, "hi").await;
    let r = app(st.clone())
        .oneshot(req(
            "DELETE",
            &format!("/sessions/{id}"),
            serde_json::Value::Null,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = json(r).await;
    let t = &v["trajectory"];
    assert_eq!(t["considered"], 1, "{v}");
    // no verifier judged the turn, so nothing is exported (the model's answer is not proof)
    assert_eq!(t["exported"], 0);
    assert_eq!(t["unverified"], 1);
    assert!(t["examplesFile"].is_null());
    let files: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(files.len(), 1, "{files:?}");
    assert!(files[0].ends_with(".report.json"));
    let report = std::fs::read_to_string(dir.path().join(&files[0])).unwrap();
    assert!(!report.contains(CANARY), "the report never carries content");
}

#[test]
fn trajectory_config_reads_only_an_explicit_directory() {
    assert!(trajectory::TrajectoryConfig::from_value(None).is_none());
    assert!(trajectory::TrajectoryConfig::from_value(Some("")).is_none());
    assert!(trajectory::TrajectoryConfig::from_value(Some("   ")).is_none());
    assert!(trajectory::TrajectoryConfig::from_value(Some("relative/dir")).is_none());
    let abs = std::env::temp_dir();
    let c = trajectory::TrajectoryConfig::from_value(Some(abs.to_str().unwrap())).unwrap();
    assert_eq!(c.dir(), abs.as_path());
}

// ---------------------------------------------------------------------------------------------
// HUP-S7.6: llama-server's generation time rides along with the usage

#[test]
fn llama_server_generation_time_is_read_from_timings() {
    let body = r#"{"choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":31,"completion_tokens":7},"timings":{"prompt_n":31,"predicted_n":7,"predicted_ms":233.6,"predicted_per_second":29.97}}"#;
    assert_eq!(
        llm_http::parse_usage(body),
        Some(TokenUsage {
            prompt_tokens: 31,
            completion_tokens: 7,
            generation_ms: Some(234),
        })
    );
}

#[test]
fn a_missing_or_nonsense_generation_time_is_unknown() {
    for timings in [
        r#""timings":{}"#,
        r#""timings":{"predicted_ms":"fast"}"#,
        r#""timings":{"predicted_ms":-4}"#,
        r#""timings":{"predicted_ms":1e300}"#,
        r#""timings":null"#,
    ] {
        let body = format!(r#"{{"usage":{{"prompt_tokens":1,"completion_tokens":2}},{timings}}}"#);
        assert_eq!(
            llm_http::parse_usage(&body).and_then(|u| u.generation_ms),
            None,
            "{body}"
        );
    }
}
