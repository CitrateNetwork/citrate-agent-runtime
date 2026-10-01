//! HUP-S5.3: `POST /decide`, `GET /decide/stats`, `POST /decide/outcomes` against real loopback
//! HTTP servers standing in for llama-server (grammar + logprobs) and the Jev endpoint.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_loop::decide::DecidePolicy;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::Mutex;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-0123456789";

/// A loopback server that answers every POST with `reply` and records each request body.
fn json_server(reply: String) -> (String, Arc<Mutex<Vec<serde_json::Value>>>) {
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let b2 = bodies.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let Ok(r) = stream.try_clone() else { continue };
            let mut reader = BufReader::new(r);
            let mut len = 0usize;
            loop {
                let mut l = String::new();
                if reader.read_line(&mut l).is_err() || l.trim().is_empty() {
                    break;
                }
                if let Some((k, v)) = l.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
            }
            let mut buf = vec![0u8; len];
            let _ = reader.read_exact(&mut buf);
            if let Ok(v) = serde_json::from_slice(&buf) {
                if let Ok(mut b) = b2.lock() {
                    b.push(v);
                }
            }
            let mut out = stream;
            let _ = write!(
                out,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
        }
    });
    (format!("http://{addr}"), bodies)
}

fn llama_reply(key: &str) -> String {
    serde_json::json!({
        "choices": [{
            "message": {"role": "assistant", "content": key},
            "logprobs": {"content": [{"token": key, "logprob": -0.05, "top_logprobs": [
                {"token": key, "logprob": -0.05}, {"token": "A", "logprob": -3.2}
            ]}]}
        }]
    })
    .to_string()
}

fn state(svc: decide::DecideService) -> Arc<AppState> {
    let mgr = sessions::SessionManager::new(
        Arc::new(
            |_ep: &sessions::LlmEndpoint| -> Arc<dyn citrate_agent_loop::LlmClient> {
                Arc::new(llm_http::OpenAiCompatClient::new(
                    "http://127.0.0.1:9",
                    "",
                    std::time::Duration::from_secs(1),
                ))
            },
        ),
        std::time::Duration::from_secs(5),
    )
    .with_decide(Arc::new(svc));
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
    b.body(Body::from(body.to_string())).expect("request")
}

async fn json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn decide_body(base: &str, origin: Option<&str>, backend: &str) -> serde_json::Value {
    let mut request = serde_json::json!({
        "purpose": "pick_element",
        "question": "Which element starts a search?",
        "options": [
            {"id": "e1", "label": "link \"Home\""},
            {"id": "e7", "label": "textbox \"Search\""},
            {"id": "e9", "label": "button \"Go\""}
        ],
        "context": "a page"
    });
    if let Some(o) = origin {
        request["origin"] = serde_json::json!({"origin": o});
    }
    serde_json::json!({
        "llm": {"baseUrl": format!("{base}/v1"), "bearer": ""},
        "model": "gemma-4",
        "request": request,
        "backend": backend
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_local_decision_is_grammar_constrained_and_metered() {
    let (base, bodies) = json_server(llama_reply("B"));
    let st = state(decide::DecideService::default());
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            "/decide",
            decide_body(&base, None, "auto"),
            true,
        ))
        .await
        .expect("decide");
    assert_eq!(r.status(), StatusCode::OK);
    let d = json(r).await;
    assert_eq!(d["choice"], "e7");
    assert_eq!(d["backend"], "local");
    assert_eq!(d["probs_source"], "model");
    assert!(d.get("egress").is_none(), "{d}");
    let sent = bodies.lock().map(|b| b.clone()).unwrap_or_default();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["grammar"], "root ::= \"A\" | \"B\" | \"C\"");

    // A task outcome, then the per-backend report.
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            "/decide/outcomes",
            serde_json::json!({"backend": "local", "suite": "web-subset-v1", "taskId": "repo-star", "success": true}),
            true,
        ))
        .await
        .expect("outcome");
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let r = app(st.clone())
        .oneshot(req("GET", "/decide/stats", serde_json::Value::Null, true))
        .await
        .expect("stats");
    let s = json(r).await;
    assert_eq!(s["jevEnabled"], false);
    assert_eq!(s["report"]["backends"]["local"]["decisions"], 1);
    assert_eq!(s["report"]["backends"]["local"]["tasks_succeeded"], 1);
    assert_eq!(s["report"]["backends"]["local"]["task_success_bps"], 10_000);
}

#[tokio::test(flavor = "multi_thread")]
async fn jev_is_refused_by_default_and_never_contacted() {
    let (base, _b) = json_server(llama_reply("A"));
    let st = state(decide::DecideService::default());
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            "/decide",
            decide_body(&base, Some("https://shop.example"), "jev"),
            true,
        ))
        .await
        .expect("decide");
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let v = json(r).await;
    assert!(
        v["error"]
            .as_str()
            .unwrap_or_default()
            .contains("not permitted"),
        "{v}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn jev_opted_in_for_an_origin_reports_egress_and_is_metered_separately() {
    let (local, _lb) = json_server(llama_reply("A"));
    let jev_reply = serde_json::json!({
        "answers": {"pick": {"choice": "e9", "probabilities": {"e1": 0.05, "e7": 0.15, "e9": 0.8}, "confidence": 0.8}}
    })
    .to_string();
    let (jev, jev_bodies) = json_server(jev_reply);
    let svc = decide::DecideService::new(decide::DecideSettings {
        policy: DecidePolicy {
            jev_enabled: true,
            jev_origins: vec!["https://shop.example".into()],
            jev_non_web: false,
        },
        jev: Some(decide::JevSettings {
            endpoint: format!("{jev}/v1/systemone"),
            api_key: "ts-test".into(),
            model: "jev-latest".into(),
        }),
        log: None,
    });
    let st = state(svc);
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            "/decide",
            decide_body(&local, Some("https://shop.example"), "auto"),
            true,
        ))
        .await
        .expect("decide");
    assert_eq!(r.status(), StatusCode::OK);
    let d = json(r).await;
    assert_eq!(d["backend"], "jev");
    assert_eq!(d["choice"], "e9");
    assert!(d["egress"]["bytes_sent"].as_u64().unwrap_or(0) > 0, "{d}");
    assert!(d["egress"]["destination"]
        .as_str()
        .unwrap_or_default()
        .ends_with("/v1/systemone"));
    assert!(!d.to_string().contains("ts-test"));
    assert_eq!(jev_bodies.lock().map(|b| b.len()).unwrap_or(0), 1);
    // Another origin stays local.
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            "/decide",
            decide_body(&local, Some("https://bank.example"), "auto"),
            true,
        ))
        .await
        .expect("decide");
    assert_eq!(json(r).await["backend"], "local");
    assert_eq!(jev_bodies.lock().map(|b| b.len()).unwrap_or(0), 1);
    let r = app(st.clone())
        .oneshot(req("GET", "/decide/stats", serde_json::Value::Null, true))
        .await
        .expect("stats");
    let s = json(r).await;
    assert_eq!(s["jevEnabled"], true);
    assert_eq!(s["report"]["backends"]["jev"]["decisions"], 1);
    assert_eq!(s["report"]["backends"]["local"]["decisions"], 1);
    assert!(
        s["report"]["backends"]["jev"]["egress_bytes"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn decide_routes_are_bearer_gated_validated_and_stopped_by_the_estop() {
    let (base, bodies) = json_server(llama_reply("A"));
    let st = state(decide::DecideService::default());
    for (m, p) in [
        ("POST", "/decide"),
        ("GET", "/decide/stats"),
        ("POST", "/decide/outcomes"),
        ("GET", "/search/status"),
    ] {
        let r = app(st.clone())
            .oneshot(req(m, p, serde_json::json!({}), false))
            .await
            .expect("route");
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{p}");
    }
    let mut empty = decide_body(&base, None, "auto");
    empty["request"]["options"] = serde_json::json!([]);
    let r = app(st.clone())
        .oneshot(req("POST", "/decide", empty, true))
        .await
        .expect("decide");
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let mut remote = decide_body(&base, None, "auto");
    remote["llm"]["baseUrl"] = serde_json::json!("http://10.0.0.5:8080/v1");
    let r = app(st.clone())
        .oneshot(req("POST", "/decide", remote, true))
        .await
        .expect("decide");
    assert_eq!(
        r.status(),
        StatusCode::BAD_REQUEST,
        "plain http to a non-loopback host"
    );
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            "/decide/outcomes",
            serde_json::json!({"backend": "local", "suite": "a b", "taskId": "x", "success": true}),
            true,
        ))
        .await
        .expect("outcome");
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    st.estop.trigger();
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            "/decide",
            decide_body(&base, None, "auto"),
            true,
        ))
        .await
        .expect("decide");
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(bodies.lock().map(|b| b.is_empty()).unwrap_or(false));
}

#[tokio::test(flavor = "multi_thread")]
async fn without_an_llm_and_without_jev_there_is_no_backend() {
    let st = state(decide::DecideService::default());
    let mut body = decide_body("http://127.0.0.1:9", None, "auto");
    body.as_object_mut().map(|o| o.remove("llm"));
    let r = app(st.clone())
        .oneshot(req("POST", "/decide", body, true))
        .await
        .expect("decide");
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
}
