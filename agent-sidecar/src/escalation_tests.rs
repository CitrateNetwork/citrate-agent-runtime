//! HUP-S1.5 — `POST /escalations` and `GET /escalations/registry`: bearer-gated, refused while the
//! e-stop is engaged, coarse errors that never echo the key, a real call to a loopback endpoint,
//! the paid registry route over a real loopback provider, and escalation metering.

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
async fn the_registry_route_reports_the_sidecar_half_and_leaves_the_decision_to_core() {
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
    assert_eq!(j["enabled"], true);
    assert!(j["transport"].as_str().unwrap_or("").contains("x402"));
    assert!(j["reason"].as_str().unwrap_or("").contains("Citrate Core"));
}

// ---------------------------------------------------------------------------
// HUP-S1.5: the paid registry route and escalation metering
// ---------------------------------------------------------------------------

fn now_secs_for_test() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn registry_body(id: &str, base_url: &str, valid_before: u64) -> String {
    serde_json::json!({
        "escalationId": id,
        "baseUrl": base_url,
        "model": format!("0x{}", "cd".repeat(32)),
        "prompt": "Plan it.",
        "maxTokens": 64,
        "payment": {
            "network": "eip155:40204",
            "asset": "0xaa918302b94a4b0e75e01e019cc6b819b4f7c906",
            "from": "0x9858effd232b4033e47d90003d41ec34ecaeda94",
            "to": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
            "value": "10000000000000000",
            "validAfter": 1u64,
            "validBefore": valid_before,
            "nonce": format!("0x{}", "01".repeat(32)),
            "signature": format!("0x{}1c", "ab".repeat(64)),
        },
    })
    .to_string()
}

fn records_for(id: &str) -> Vec<citrate_agent_metering::EscalationRecord> {
    escalation::escalation_store()
        .records()
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.escalation_id == id)
        .collect()
}

/// A one-shot loopback provider that answers with a completion and an x402 receipt header.
fn serve_paid_once(tx: &str) -> String {
    use base64::Engine as _;
    let receipt = base64::engine::general_purpose::STANDARD.encode(
        serde_json::json!({"success": true, "transaction": tx, "network": "eip155:40204",
            "payer": "0x9858effd232b4033e47d90003d41ec34ecaeda94"})
        .to_string(),
    );
    let body = serde_json::json!({"choices": [{"message": {"content": "paid plan"}}],
        "usage": {"prompt_tokens": 7, "completion_tokens": 9}})
    .to_string();
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
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-PAYMENT-RESPONSE: {receipt}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes());
        }
    });
    format!("http://127.0.0.1:{port}/v1")
}

#[tokio::test]
async fn the_paid_registry_route_requires_the_bearer_and_respects_the_estop() {
    let body = registry_body("esc-reg-auth", "https://x.example/v1", now_secs_for_test() + 600);
    let resp = app(state())
        .oneshot(post("/escalations/registry", None, body.clone()))
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let st = state();
    st.estop.trigger();
    let resp = app(st)
        .oneshot(post("/escalations/registry", Some(BEARER), body))
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(resp).await["sent"], false);
}

#[tokio::test]
async fn a_malformed_registry_body_is_a_coarse_400() {
    let resp = app(state())
        .oneshot(post(
            "/escalations/registry",
            Some(BEARER),
            "{\"escalationId\": 3}".into(),
        ))
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["sent"], false);
}

#[tokio::test]
async fn an_expired_payment_is_refused_unsent_and_metered_at_zero() {
    let resp = app(state())
        .oneshot(post(
            "/escalations/registry",
            Some(BEARER),
            registry_body("esc-reg-expired", "https://x.example/v1", 2),
        ))
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let j = body_json(resp).await;
    assert_eq!(j["sent"], false);
    assert!(j["error"].as_str().unwrap_or("").contains("expired"));
    let recs = records_for("esc-reg-expired");
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].charged, "0");
    assert_eq!(
        recs[0].outcome,
        citrate_agent_metering::EscalationOutcomeKind::FailedNotSent
    );
}

#[tokio::test]
async fn a_paid_request_returns_the_answer_and_receipt_and_meters_them() {
    let tx = format!("0x{}", "56".repeat(32));
    let base = serve_paid_once(&tx);
    let resp = app(state())
        .oneshot(post(
            "/escalations/registry",
            Some(BEARER),
            registry_body("esc-reg-paid", &base, now_secs_for_test() + 600),
        ))
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["content"], "paid plan");
    assert_eq!(j["chargedBaseUnits"], "10000000000000000");
    assert_eq!(j["receipt"]["transaction"], tx);
    let recs = records_for("esc-reg-paid");
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    assert_eq!(r.route, citrate_agent_metering::EscalationRoute::Registry);
    assert_eq!(r.charged, "10000000000000000");
    assert_eq!(r.tokens_in, Some(7));
    assert_eq!(
        r.receipt.as_ref().and_then(|x| x.transaction.clone()),
        Some(tx.clone())
    );
    // The day's report lists the receipt.
    let resp = app(state())
        .oneshot(
            Request::builder()
                .uri("/metering/escalations")
                .header("authorization", format!("Bearer {BEARER}"))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["source"], "memory");
    let ids: Vec<String> = j["report"]["receipts"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| e[0].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(ids.contains(&"esc-reg-paid".to_string()), "{ids:?}");
}

#[tokio::test]
async fn endpoint_escalations_are_metered_too() {
    let base = serve_once(
        200,
        serde_json::json!({"choices": [{"message": {"content": "ok"}}], "usage": {"prompt_tokens": 10, "completion_tokens": 20}}).to_string(),
    );
    let body = escalation_body(&base, 1_000).replace("esc-7", "esc-metered-1");
    let resp = app(state())
        .oneshot(post("/escalations", Some(BEARER), body))
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::OK);
    let recs = records_for("esc-metered-1");
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].route, citrate_agent_metering::EscalationRoute::Endpoint);
    assert_eq!(recs[0].charged, "50");
    assert_eq!(recs[0].unit, citrate_agent_metering::ChargeUnit::MicroUsd);
    assert!(!serde_json::to_string(&recs[0]).unwrap_or_default().contains(KEY));
}

#[tokio::test]
async fn the_escalation_report_refuses_a_bad_day_and_needs_the_bearer() {
    let resp = app(state())
        .oneshot(
            Request::builder()
                .uri("/metering/escalations?day=2026-13-40")
                .header("authorization", format!("Bearer {BEARER}"))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = app(state())
        .oneshot(
            Request::builder()
                .uri("/metering/escalations")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
