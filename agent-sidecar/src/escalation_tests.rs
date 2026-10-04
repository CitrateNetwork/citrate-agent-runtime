//! HUP-S1.5 — `POST /escalations` and `GET /escalations/registry`: bearer-gated, refused while the
//! e-stop is engaged, coarse errors that never echo the key, a real call to a loopback endpoint,
//! and the registry route reported as disabled.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_core::hitl::ApprovalQueue;
use citrate_agent_legacy::estop::EmergencyStop;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-0123456789";
const KEY: &str = "sk-escalation-secret-abcdef";

fn state() -> Arc<AppState> {
    Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: Arc::new(ApprovalQueue::new()),
        skills: vec![],
        dispatch: None,
        bearer: BEARER.to_string(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
        sessions: production_sessions(),
    })
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn post(path: &str, bearer: Option<&str>, body: String) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(t) = bearer {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    b.body(Body::from(body)).expect("request")
}

/// A one-shot loopback chat-completions server answering `status` + `body`.
fn serve_once(status: u16, body: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut reader = BufReader::new(sock.try_clone().expect("clone"));
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            let mut buf = vec![0u8; len];
            let _ = reader.read_exact(&mut buf);
            let resp = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes());
        }
    });
    format!("http://127.0.0.1:{port}/v1")
}

fn escalation_body(base_url: &str, reserved: u64) -> String {
    serde_json::json!({
        "escalationId": "esc-7",
        "baseUrl": base_url,
        "model": "planner",
        "apiKey": KEY,
        "prompt": "Plan it.",
        "maxTokens": 64,
        "price": {"inputMicrosPerMtok": 1_000_000u64, "outputMicrosPerMtok": 2_000_000u64},
        "reservedMicros": reserved,
    })
    .to_string()
}

#[tokio::test]
async fn escalation_routes_require_the_bearer() {
    let resp = app(state())
        .oneshot(post(
            "/escalations",
            None,
            escalation_body("https://x.example/v1", 1000),
        ))
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = app(state())
        .oneshot(
            Request::builder()
                .uri("/escalations/registry")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn escalation_is_refused_while_the_estop_is_engaged_and_nothing_is_sent() {
    let st = state();
    st.estop.trigger();
    let resp = app(st)
        .oneshot(post(
            "/escalations",
            Some(BEARER),
            escalation_body("https://x.example/v1", 1000),
        ))
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let j = body_json(resp).await;
    assert_eq!(j["sent"], false);
}

#[tokio::test]
async fn a_malformed_body_gets_a_coarse_error_that_never_echoes_the_key() {
    let body =
        serde_json::json!({"escalationId": "e", "apiKey": KEY, "maxTokens": "lots"}).to_string();
    let resp = app(state())
        .oneshot(post("/escalations", Some(BEARER), body))
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let j = body_json(resp).await;
    assert_eq!(j["sent"], false);
    assert!(!j.to_string().contains(KEY));
}

#[tokio::test]
async fn an_under_reserved_request_is_refused_before_egress() {
    let resp = app(state())
        .oneshot(post(
            "/escalations",
            Some(BEARER),
            escalation_body("https://x.example/v1", 0),
        ))
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let j = body_json(resp).await;
    assert_eq!(j["sent"], false);
    assert!(j["error"].as_str().unwrap_or("").contains("reservation"));
}

#[tokio::test]
async fn a_real_loopback_endpoint_answers_and_the_charge_is_settled() {
    let base = serve_once(
        200,
        serde_json::json!({"choices": [{"message": {"content": "step 1, step 2"}}], "usage": {"prompt_tokens": 10, "completion_tokens": 20}}).to_string(),
    );
    let resp = app(state())
        .oneshot(post(
            "/escalations",
            Some(BEARER),
            escalation_body(&base, 1_000),
        ))
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["content"], "step 1, step 2");
    assert_eq!(j["escalationId"], "esc-7");
    // 10 * 1 + 20 * 2 = 50 micros
    assert_eq!(j["chargedMicros"], 50);
    assert_eq!(j["usageReported"], true);
    assert!(!j.to_string().contains(KEY));
}

#[tokio::test]
async fn a_provider_error_reports_that_the_request_may_have_been_sent() {
    let base = serve_once(500, "{}".into());
    let resp = app(state())
        .oneshot(post(
            "/escalations",
            Some(BEARER),
            escalation_body(&base, 1_000),
        ))
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let j = body_json(resp).await;
    assert_eq!(j["sent"], true);
    assert!(j["error"].as_str().unwrap_or("").contains("500"));
}

#[tokio::test]
async fn the_registry_route_reports_disabled() {
    let resp = app(state())
        .oneshot(
            Request::builder()
                .uri("/escalations/registry")
                .header("authorization", format!("Bearer {BEARER}"))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["enabled"], false);
    assert!(j["missing"]
        .as_array()
        .map(|a| !a.is_empty())
        .unwrap_or(false));
}

// ---- US-1.5 AC3: escalation receipts land in metering ----

fn get(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header("authorization", format!("Bearer {BEARER}"))
        .body(Body::empty())
        .expect("req")
}

#[tokio::test]
async fn a_settled_escalation_leaves_a_content_free_receipt_in_the_daily_report() {
    let base = serve_once(
        200,
        serde_json::json!({"choices": [{"message": {"content": "step 1, step 2"}}], "usage": {"prompt_tokens": 10, "completion_tokens": 20}}).to_string(),
    );
    let st = state();
    let resp = app(st.clone())
        .oneshot(post(
            "/escalations",
            Some(BEARER),
            escalation_body(&base, 1_000),
        ))
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::OK);
    let receipts = st
        .sessions
        .metering()
        .escalation_receipts()
        .expect("receipts");
    assert_eq!(receipts.len(), 1);
    let r = &receipts[0];
    assert_eq!(r.escalation_id, "esc-7");
    assert_eq!(r.model, "planner");
    assert_eq!((r.tokens_in, r.tokens_out), (Some(10), Some(20)));
    assert_eq!((r.reserved_micros, r.charged_micros), (1_000, 50));
    let line = serde_json::to_string(r).expect("json");
    assert!(!line.contains(KEY) && !line.contains("Plan it.") && !line.contains("step 1"));
    assert!(
        !line.contains("127.0.0.1"),
        "no endpoint URL in the receipt"
    );

    let day = citrate_agent_metering::utc_day_of_ms(r.started_unix_ms);
    let resp = app(st)
        .oneshot(get(&format!("/metering/daily?day={day}")))
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["escalations"]["count"], 1);
    assert_eq!(j["escalations"]["chargedMicros"], 50);
    assert!(j["markdown"]
        .as_str()
        .unwrap_or("")
        .contains("## Escalations"));
}

#[tokio::test]
async fn a_failure_after_sending_charges_the_reservation_in_its_receipt() {
    let base = serve_once(500, "{}".into());
    let st = state();
    let resp = app(st.clone())
        .oneshot(post(
            "/escalations",
            Some(BEARER),
            escalation_body(&base, 1_000),
        ))
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let receipts = st
        .sessions
        .metering()
        .escalation_receipts()
        .expect("receipts");
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].settlement,
        citrate_agent_metering::EscalationSettlement::FailedAfterSend
    );
    assert_eq!(receipts[0].charged_micros, 1_000);
}

#[tokio::test]
async fn a_request_refused_before_sending_leaves_no_receipt() {
    let st = state();
    let resp = app(st.clone())
        .oneshot(post(
            "/escalations",
            Some(BEARER),
            escalation_body("https://x.example/v1", 0),
        ))
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(st
        .sessions
        .metering()
        .escalation_receipts()
        .expect("receipts")
        .is_empty());
}
