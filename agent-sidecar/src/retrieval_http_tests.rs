//! HUP-S1.2 / US-1.4 AC1 — llama-server `/tokenize` and `/v1/embeddings` transports, and what a
//! session reports about how it counts tokens and ranks tools.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_loop::retrieval::{Embedder, Tokenizer};
use citrate_agent_loop::skills::{SkillLibrary, SkillSource, SKILL_LOAD_TOOL};
use citrate_agent_loop::{AssistantTurn, CompletionRequest, LlmClient, LlmError};
use retrieval_http::*;
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-0123456789";
/// `/tokenize` answers recorded from the bundled llama-server with the T0 model.
const RECORDED: &str = include_str!("../../agent-loop/tests/fixtures/tokenize_gemma4_e4b_t0.json");

fn recorded() -> serde_json::Value {
    serde_json::from_str(RECORDED).unwrap()
}

// ---- Wire mapping -----------------------------------------------------------------------------

#[test]
fn urls_map_from_the_chat_base_url() {
    assert_eq!(
        server_root("http://127.0.0.1:18080/v1"),
        "http://127.0.0.1:18080"
    );
    assert_eq!(
        server_root("http://127.0.0.1:18080/v1/"),
        "http://127.0.0.1:18080"
    );
    assert_eq!(
        server_root("http://127.0.0.1:18080"),
        "http://127.0.0.1:18080"
    );
    assert_eq!(
        tokenize_url("http://127.0.0.1:18080/v1"),
        "http://127.0.0.1:18080/tokenize"
    );
    assert_eq!(
        embeddings_url("http://127.0.0.1:18081"),
        "http://127.0.0.1:18081/v1/embeddings"
    );
    assert_eq!(
        embeddings_url("https://embed.example/v1"),
        "https://embed.example/v1/embeddings"
    );
    assert!(is_loopback_http("http://127.0.0.1:18080/v1"));
    assert!(is_loopback_http("http://localhost:18080"));
    assert!(!is_loopback_http("https://gateway.example/v1"));
    assert!(!is_loopback_http("http://10.0.0.5:18080/v1"));
}

#[test]
fn the_recorded_tokenize_answers_parse_to_their_token_counts() {
    for case in recorded()["cases"].as_array().unwrap() {
        let body = case["response"].to_string();
        assert_eq!(
            parse_tokenize(&body).unwrap(),
            case["response"]["tokens"].as_array().unwrap().len()
        );
    }
    assert!(parse_tokenize("not json").is_err());
    assert!(parse_tokenize(r#"{"error":"x"}"#).is_err());
}

#[test]
fn embeddings_parse_in_index_order_and_reject_bad_shapes() {
    let body = r#"{"data":[{"index":1,"embedding":[0.5,0.25]},{"index":0,"embedding":[1,0]}]}"#;
    assert_eq!(
        parse_embeddings(body, 2).unwrap(),
        vec![vec![1.0, 0.0], vec![0.5, 0.25]]
    );
    assert!(parse_embeddings(body, 3).is_err(), "too few vectors");
    let dup = r#"{"data":[{"index":0,"embedding":[1]},{"index":0,"embedding":[2]}]}"#;
    assert!(parse_embeddings(dup, 2).is_err());
    let out = r#"{"data":[{"index":5,"embedding":[1]}]}"#;
    assert!(parse_embeddings(out, 1).is_err());
    let nan = r#"{"data":[{"index":0,"embedding":["x"]}]}"#;
    assert!(parse_embeddings(nan, 1).is_err());
    // The 501 a chat-only llama-server answers is not an embeddings body.
    let not_supported = recorded()["embeddings_on_chat_server"]["body"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(parse_embeddings(&not_supported, 1).is_err());
}

// ---- A loopback stand-in for llama-server -----------------------------------------------------

/// Serves `/tokenize` with the recorded answers (and one token per word for any other text, so a
/// session's probe and prompt can be counted), and `/v1/embeddings` with the recorded 501 a
/// chat-only llama-server gives, or with `embed` vectors when set.
async fn llama_stand_in(embed: Option<Vec<f32>>) -> String {
    use axum::routing::post;
    let rec = recorded();
    let tokenize = move |axum::Json(v): axum::Json<serde_json::Value>| {
        let rec = rec.clone();
        async move {
            let content = v["content"].as_str().unwrap_or("").to_string();
            let hit = rec["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["content"] == content.as_str())
                .map(|c| c["response"].clone());
            axum::Json(hit.unwrap_or_else(|| {
                serde_json::json!({ "tokens": content.split_whitespace().map(|_| 1).collect::<Vec<_>>() })
            }))
        }
    };
    let embeddings = move |axum::Json(v): axum::Json<serde_json::Value>| {
        let embed = embed.clone();
        async move {
            match embed {
                None => (
                    StatusCode::NOT_IMPLEMENTED,
                    axum::Json(
                        serde_json::from_str::<serde_json::Value>(
                            recorded()["embeddings_on_chat_server"]["body"]
                                .as_str()
                                .unwrap(),
                        )
                        .unwrap(),
                    ),
                ),
                Some(vec) => {
                    let n = v["input"].as_array().map(Vec::len).unwrap_or(0);
                    let data: Vec<serde_json::Value> = (0..n)
                        .map(|i| serde_json::json!({ "index": i, "embedding": vec }))
                        .collect();
                    (
                        StatusCode::OK,
                        axum::Json(serde_json::json!({ "data": data })),
                    )
                }
            }
        }
    };
    let app = axum::Router::new()
        .route("/tokenize", post(tokenize))
        .route("/v1/embeddings", post(embeddings));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}/v1")
}

#[tokio::test(flavor = "multi_thread")]
async fn the_tokenizer_counts_over_http_and_the_embedder_reports_a_501() {
    let base = llama_stand_in(None).await;
    let rec = recorded();
    let case = &rec["cases"][5];
    let text = case["content"].as_str().unwrap().to_string();
    let want = case["response"]["tokens"].as_array().unwrap().len();
    let b = base.clone();
    let (count, embed) = tokio::task::spawn_blocking(move || {
        (
            LlamaTokenizer::new(&b, "").token_count(&text),
            HttpEmbedder::new(&b, "").embed(&["x".to_string()]),
        )
    })
    .await
    .unwrap();
    assert_eq!(count.unwrap(), want);
    let err = embed.unwrap_err();
    assert!(err.contains("HTTP 501"), "{err}");
    assert!(
        !err.contains("127.0.0.1"),
        "errors never carry the endpoint: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_tokenizer_fails_coarsely() {
    let err = tokio::task::spawn_blocking(|| {
        LlamaTokenizer::new("http://127.0.0.1:9/v1", "").token_count("hello")
    })
    .await
    .unwrap()
    .unwrap_err();
    assert!(err.contains("did not answer"), "{err}");
}

#[test]
fn the_production_embedder_only_reaches_endpoints_it_may() {
    let local = sessions::LlmEndpoint {
        base_url: "http://127.0.0.1:18080/v1".into(),
        bearer: String::new(),
    };
    let remote = sessions::LlmEndpoint {
        base_url: "https://gateway.example/v1".into(),
        bearer: String::new(),
    };
    assert!(production_embedder(None)(&local).is_ok());
    let err = production_embedder(None)(&remote).err().unwrap();
    assert!(err.contains(EMBED_URL_ENV), "{err}");
    assert!(production_embedder(Some("https://embed.example".into()))(&remote).is_ok());
    let err = production_embedder(Some("http://10.0.0.5:8080".into()))(&local)
        .err()
        .unwrap();
    assert!(err.contains("refused"), "{err}");
    assert!(
        production_embedder(Some("  ".into()))(&local).is_ok(),
        "blank = unset"
    );
    assert!(production_tokenizer()(&local).is_ok());
    let err = production_tokenizer()(&remote).err().unwrap();
    assert!(err.contains("estimated"), "{err}");
}

// ---- Sessions report how they count and rank --------------------------------------------------

struct Recorder(Mutex<Vec<CompletionRequest>>);
impl LlmClient for Recorder {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        self.0.lock().unwrap().push(req.clone());
        Ok(AssistantTurn::text("(done)"))
    }
}

fn state(skills: Option<Arc<SkillLibrary>>, production: bool) -> (Arc<AppState>, Arc<Recorder>) {
    let rec = Arc::new(Recorder(Mutex::new(vec![])));
    let r2 = rec.clone();
    let mut mgr = sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| r2.clone() as Arc<dyn LlmClient>),
        Duration::from_secs(5),
    );
    if production {
        mgr = mgr
            .with_tokenizer(production_tokenizer())
            .with_embedder(production_embedder(None));
    }
    if let Some(lib) = skills {
        mgr = mgr.with_skills(lib);
    }
    let st = Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: Arc::new(ApprovalQueue::new()),
        skills: vec![],
        dispatch: None,
        bearer: BEARER.to_string(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
        sessions: Arc::new(mgr),
    });
    (st, rec)
}

fn req(method: &str, path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {BEARER}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

async fn create(st: &Arc<AppState>, body: serde_json::Value) -> serde_json::Value {
    let r = app(st.clone())
        .oneshot(req("POST", "/sessions", body))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    json(r).await
}

fn body(base_url: &str, tools: serde_json::Value, context: Option<usize>) -> serde_json::Value {
    let mut b = serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes.",
        "llm": {"baseUrl": base_url},
        "tools": tools,
    });
    if let Some(c) = context {
        b["contextTokens"] = serde_json::json!(c);
    }
    b
}

#[tokio::test(flavor = "multi_thread")]
async fn a_local_session_counts_with_the_model_tokenizer_and_says_why_it_ranks_lexically() {
    let base = llama_stand_in(None).await;
    let (st, _) = state(None, true);
    let v = create(&st, body(&base, serde_json::json!([]), Some(8192))).await;
    assert_eq!(
        v["tokenCounting"],
        serde_json::json!({"mode": "model"}),
        "{v}"
    );
    assert_eq!(v["retrieval"]["mode"], "lexical", "{v}");
    assert!(
        v["retrieval"]["reason"]
            .as_str()
            .unwrap()
            .contains("HTTP 501"),
        "{v}"
    );
    assert_eq!(v["maxToolSchemas"], 8);
    let id = v["id"].as_str().unwrap();
    let r = app(st.clone())
        .oneshot(req(
            "GET",
            &format!("/sessions/{id}/retrieval"),
            serde_json::Value::Null,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let g = json(r).await;
    assert_eq!(g["tokenCounting"], v["tokenCounting"]);
    assert_eq!(g["retrieval"], v["retrieval"]);
    assert_eq!(g["maxToolSchemas"], 8);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_local_embedding_server_turns_hybrid_retrieval_on() {
    let base = llama_stand_in(Some(vec![0.25, 0.5, 1.0])).await;
    let (st, _) = state(None, true);
    let v = create(&st, body(&base, serde_json::json!([]), None)).await;
    assert_eq!(
        v["retrieval"],
        serde_json::json!({"mode": "embedding"}),
        "{v}"
    );
    assert!(
        v.get("tokenCounting").is_none() || v["tokenCounting"].is_null(),
        "no budget, nothing counted: {v}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dead_local_server_means_estimated_tokens_with_the_reason() {
    let (st, _) = state(None, true);
    let v = create(
        &st,
        body("http://127.0.0.1:9/v1", serde_json::json!([]), Some(4096)),
    )
    .await;
    assert_eq!(v["tokenCounting"]["mode"], "estimated", "{v}");
    assert!(
        v["tokenCounting"]["reason"]
            .as_str()
            .unwrap()
            .contains("did not answer"),
        "{v}"
    );
    assert_eq!(v["retrieval"]["mode"], "lexical");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_gateway_session_estimates_and_never_sends_text_for_embedding() {
    let (st, _) = state(None, true);
    let v = create(
        &st,
        body(
            "https://gateway.example/v1",
            serde_json::json!([]),
            Some(4096),
        ),
    )
    .await;
    assert_eq!(v["tokenCounting"]["mode"], "estimated");
    assert!(v["tokenCounting"]["reason"]
        .as_str()
        .unwrap()
        .contains("not the local llama-server"));
    assert!(v["retrieval"]["reason"]
        .as_str()
        .unwrap()
        .contains(EMBED_URL_ENV));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sidecar_without_a_tokenizer_reports_that_too() {
    let (st, _) = state(None, false);
    let v = create(
        &st,
        body(
            "http://127.0.0.1:18080/v1",
            serde_json::json!([]),
            Some(4096),
        ),
    )
    .await;
    assert_eq!(
        v["tokenCounting"],
        serde_json::json!({"mode": "estimated", "reason": sessions::NO_TOKENIZER_REASON})
    );
    assert_eq!(
        v["retrieval"],
        serde_json::json!({"mode": "lexical", "reason": sessions::NO_EMBEDDER_REASON})
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_default_session_offers_at_most_eight_tool_schemas_with_skill_load_pinned() {
    // US-1.4 AC1: twenty tools that all match the request, plus the pinned skill_load.
    let root = std::env::temp_dir().join(format!("citrate-sidecar-ceiling-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("node-report")).unwrap();
    std::fs::write(
        root.join("node-report/SKILL.md"),
        "---\nname: node-report\ndescription: Write a node report.\n---\nBODY",
    )
    .unwrap();
    let lib = Arc::new(SkillLibrary::load(&[SkillSource::new("user", &root)]));
    let (st, rec) = state(Some(lib), false);
    let tools: Vec<serde_json::Value> = (0..20)
        .map(|i| serde_json::json!({"name": format!("node_tool_{i}"), "description": "node height peers", "parameters": {"type": "object"}, "host": "core"}))
        .collect();
    let v = create(
        &st,
        body("http://127.0.0.1:18080/v1", serde_json::json!(tools), None),
    )
    .await;
    let id = v["id"].as_str().unwrap().to_string();
    st.sessions
        .send(&id, "node height and peers".into(), None)
        .unwrap();
    let session = st.sessions.get(&id).unwrap();
    let mut after = 0;
    for _ in 0..200 {
        let page = session.wait_events(after, Duration::from_millis(25)).await;
        let done = page.events.iter().any(|e| e.event.kind() == "done");
        after = page.events.iter().map(|e| e.seq).max().unwrap_or(after);
        if done {
            break;
        }
    }
    let seen = rec.0.lock().unwrap();
    let names: Vec<&str> = seen[0].tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names.len(), sessions::TOOL_SCHEMA_CEILING, "{names:?}");
    assert_eq!(names[0], SKILL_LOAD_TOOL);
    let _ = std::fs::remove_dir_all(&root);
}
