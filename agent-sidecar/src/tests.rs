//! Control-plane tests — the bearer gate, /health (open), status/skills/approvals shapes, stop flips
//! the emergency stop, and runSkill honestly refuses (S6.3). In-process via tower::oneshot; no socket.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-0123456789";

fn state() -> Arc<AppState> {
    Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: Arc::new(ApprovalQueue::new()),
        skills: vec![
            SkillView {
                name: "list-compliance-posture".into(),
                description: "".into(),
            },
            SkillView {
                name: "eth-sender-test".into(),
                description: "".into(),
            },
        ],
        dispatch: None,
        bearer: BEARER.to_string(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
    })
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn authed(method: &str, path: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {BEARER}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn health_is_open_and_reports_liveness_only() {
    // AR-B-024 (RC-8): /health is unauthenticated, so it must NOT leak the
    // emergency-stop state to an anonymous prober. This test previously
    // asserted `stopped == false` on the open route (the leak encoded as
    // correct); the stop state now lives only on bearer-gated /status.
    let st = state();
    let resp = app(st.clone())
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["status"], "ok");
    assert!(
        j.get("stopped").is_none(),
        "unauthenticated /health must not expose the e-stop state; got: {j}"
    );
}

#[tokio::test]
async fn control_routes_require_the_bearer() {
    for (m, p) in [
        ("GET", "/status"),
        ("GET", "/skills"),
        ("GET", "/approvals"),
        ("POST", "/stop"),
        ("POST", "/run_skill"),
    ] {
        let resp = app(state())
            .oneshot(
                Request::builder()
                    .method(m)
                    .uri(p)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{m} {p} must require the bearer"
        );
    }
}

#[tokio::test]
async fn status_reports_running_skills_and_pending() {
    let resp = app(state())
        .oneshot(authed("GET", "/status"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["running"], true);
    assert_eq!(j["skills"], 2);
    assert_eq!(j["pendingApprovals"], 0);
}

#[tokio::test]
async fn skills_lists_the_catalog() {
    let resp = app(state())
        .oneshot(authed("GET", "/skills"))
        .await
        .unwrap();
    let j = body_json(resp).await;
    let arr = j.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["name"], "list-compliance-posture");
}

#[tokio::test]
async fn approvals_is_empty_until_a_skill_runs() {
    let resp = app(state())
        .oneshot(authed("GET", "/approvals"))
        .await
        .unwrap();
    let j = body_json(resp).await;
    assert_eq!(j.as_array().unwrap().len(), 0);
}

// runSkill now RUNS a skill (S6.3 slice-2) via CapsuleDispatch::call_json, spawning it so a chain
// effect can park on the ApprovalGate. The unit tests below pin the guard rails (auth, bad body,
// unknown skill, no-dispatch, estop); the real gate-path e2e (a skill's effect surfaces on the queue)
// is `run_skill_surfaces_a_chain_effect_on_the_queue` further down, driven from the real capsule dir.

// PBA-L6b-015: the eth-sender-test capsule is a test fixture, not part of the shipped fleet. It is
// loaded from test-fixtures/ with an allowlist that admits exactly its signed build.
fn fixture_capsules_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-fixtures/capsules")
}

fn fixture_dispatch(queue: Arc<ApprovalQueue>) -> Option<Arc<CapsuleDispatch>> {
    use citrate_agent_core::capsule::allowlist::AllowEntry;
    let allow = FleetAllowlist::from_entries(vec![AllowEntry {
        name: "eth-sender-test".into(),
        min_version: "0.1.0".into(),
        content_hashes: vec![
            "sha256:f6364f40f252d5212a3bc3f203ccf4019dfb8850ce96bfb5c67ecedcbffd8086".into(),
        ],
    }]);
    crate::load_dispatch_with_allowlist(&fixture_capsules_dir(), &allow, queue)
}

/// PBA-L6b-015: the production loader (bundled allowlist) does not run the test capsule even when
/// its signed archive sits in the capsule dir.
#[test]
fn production_loader_refuses_the_test_capsule_pba_l6b_015() {
    let d = crate::load_dispatch(&fixture_capsules_dir(), Arc::new(ApprovalQueue::new()))
        .expect("dir loads");
    assert!(!d.has("eth-sender-test"));
}

fn run_body(name: &str, args: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/run_skill")
        .header("authorization", format!("Bearer {BEARER}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "name": name, "args": args }).to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn run_skill_rejects_a_malformed_body_after_auth() {
    // Authed but empty body → 400 (auth still runs first; Bytes never rejects).
    let resp = app(state())
        .oneshot(authed("POST", "/run_skill"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn run_skill_503s_when_no_dispatch_loaded() {
    // state() has dispatch: None — a valid request must NOT pretend to run (Rule 1).
    let resp = app(state())
        .oneshot(run_body("list-compliance-posture", serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_skill_surfaces_a_chain_effect_on_the_queue() {
    // AR-B-003 (RC-8): the eth-sender-test capsule declares tier = "high",
    // required_roles = [Reviewer, ComplianceOfficer]. This test previously
    // proved the VULNERABILITY: the tier-high eth-send parked on the anonymous
    // FIFO queue and a single anonymous `queue.approve()` released it. Post-fix
    // the effect is routed to the role-bound quorum track and the anonymous
    // FIFO approve CANNOT release it.
    //
    // (Follow-up: the sidecar's HTTP /approvals + /approvals/approve ceremony
    // is still FIFO-only; to approve a privileged effect an operator surface
    // must adopt the role-aware submit_for_action/add_signature track.)
    let queue = Arc::new(ApprovalQueue::new());
    let dispatch = fixture_dispatch(queue.clone());
    assert!(dispatch.is_some(), "the test-fixtures capsule dir must load");
    let st = Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: queue.clone(),
        skills: vec![SkillView {
            name: "eth-sender-test".into(),
            description: String::new(),
        }],
        dispatch,
        bearer: BEARER.to_string(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
    });

    // `to` must be the capsule's allow-listed address so the effect reaches the gate (not rejected at
    // the allow-list). `data` is a 1-byte payload. call_json maps both hex strings → list<u8>.
    let resp = app(st.clone())
        .oneshot(run_body(
            "eth-sender-test",
            serde_json::json!({
                "to": "0x4a86659BDab24dc444C72fbbaD4cd83491820E40",
                "data": "0x01",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "skill accepted");
    let j = body_json(resp).await;
    assert_eq!(j["ok"], true);
    assert_eq!(j["submitted"], true);

    // PBA-L6b-012 / PBA-L6b-032: the sidecar binds no invoking human to its gate and exposes no
    // quorum-signature route, so a tier-high effect can never be approved here. It is refused at
    // once instead of parking on the role track for 5 minutes (invisible to /approvals, holding a
    // worker). It never reaches the anonymous FIFO queue either.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(queue.role_pending_depth(), 0, "no privileged effect parks");
    assert_eq!(
        queue.depth(),
        0,
        "tier-high effect must not surface on the anonymous FIFO queue"
    );
}

#[tokio::test]
async fn run_skill_404s_for_an_unknown_skill() {
    // A loaded dispatch, but the name isn't in the catalog.
    let queue = Arc::new(ApprovalQueue::new());
    let dispatch = fixture_dispatch(queue.clone());
    assert!(dispatch.is_some(), "the test-fixtures capsule dir must load");
    let st = Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue,
        skills: vec![SkillView {
            name: "eth-sender-test".into(),
            description: String::new(),
        }],
        dispatch,
        bearer: BEARER.to_string(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
    });
    let resp = app(st)
        .oneshot(run_body("no-such-skill", serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn stop_triggers_the_emergency_stop() {
    let st = state();
    assert!(!st.estop.is_stopped());
    let resp = app(st.clone())
        .oneshot(authed("POST", "/stop"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(st.estop.is_stopped(), "stop flips the emergency stop");
    // AR-B-024: the stop state is reflected on the bearer-gated /status route
    // (`running`), not on the unauthenticated /health route.
    let s = app(st.clone())
        .oneshot(authed("GET", "/status"))
        .await
        .unwrap();
    assert_eq!(body_json(s).await["running"], false);
}

#[test]
fn enforce_loopback_bind_rejects_nonloopback_without_optin() {
    // AR-B-024: loopback literals pass; a routable IP or hostname is refused
    // unless the explicit override is set.
    assert!(enforce_loopback_bind("127.0.0.1:19700", false).is_ok());
    assert!(enforce_loopback_bind("[::1]:19700", false).is_ok());
    assert!(
        enforce_loopback_bind("0.0.0.0:19700", false).is_err(),
        "0.0.0.0 must be refused without the opt-in"
    );
    assert!(
        enforce_loopback_bind("192.168.1.10:19700", false).is_err(),
        "a routable IP must be refused"
    );
    assert!(
        enforce_loopback_bind("example.com:19700", false).is_err(),
        "a hostname must be refused (could resolve off-loopback)"
    );
    // Deliberate override lets it through.
    assert!(enforce_loopback_bind("0.0.0.0:19700", true).is_ok());
}

#[test]
fn load_skills_parses_manifests_and_is_empty_on_a_missing_dir() {
    assert!(load_skills(std::path::Path::new("/no/such/capsule/dir")).is_empty());
    // A temp capsule dir with one manifest.
    let d = std::env::temp_dir().join(format!("agentsidecar-skills-{}", std::process::id()));
    let cap = d.join("demo-skill");
    std::fs::create_dir_all(&cap).unwrap();
    std::fs::write(
        cap.join("manifest.toml"),
        "[capsule]\nname = \"demo-skill\"\ndescription = \"a demo\"\n",
    )
    .unwrap();
    let skills = load_skills(&d);
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].name, "demo-skill");
    assert_eq!(skills[0].description, "a demo");
    let _ = std::fs::remove_dir_all(&d);
}

// ── S6.3 — the ceremony-resolution bridge (approve/reject the head) ──

#[tokio::test]
async fn approve_reject_require_the_bearer() {
    for p in ["/approvals/approve", "/approvals/reject"] {
        let resp = app(state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(p)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{p} must require the bearer"
        );
    }
}

#[tokio::test]
async fn approve_without_an_id_is_a_bad_request() {
    // PBA-L6b-009: the id-less "approve whatever is at the FIFO head" path is gone. This test
    // previously asserted an empty-body approve was a 200 no-op, i.e. it pinned the unbound path
    // as correct. An approve that does not name the call the human reviewed is now a 400.
    let resp = app(state())
        .oneshot(authed("POST", "/approvals/approve"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn approve_with_a_mismatched_call_id_is_a_conflict() {
    // AR-B-023: a call-id-bound approve whose id is not the current head must
    // be refused (409), resolving nothing — a human decision can never land on
    // an action the human did not review. On an empty queue any id mismatches.
    let resp = app(state())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/approvals/approve")
                .header("authorization", format!("Bearer {BEARER}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"id":"not-the-head"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn reject_without_an_id_is_a_bad_request() {
    // PBA-L6b-009: see approve_without_an_id_is_a_bad_request.
    let resp = app(state())
        .oneshot(authed("POST", "/approvals/reject"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── S6.3 — end-to-end ceremony bridge: an effect submitted (as a capsule's ApprovalGate does)
// surfaces on the queue and is resolved by the same approve/reject the HTTP endpoints call. This is
// the safety property of gD-hermes proven through the real ApprovalQueue submit→resolve path.

use citrate_agent_core::hitl::{ApprovalOutcomePublic, ToolCall};

fn effect_call(id: &str) -> ToolCall {
    ToolCall {
        call_id: id.to_string(),
        name: "eth-send".to_string(), // not trusted → must pend for human approval
        args: serde_json::json!({ "to": "0x1111111111111111111111111111111111111111", "data": "0x01" }),
    }
}

async fn wait_depth(q: &ApprovalQueue, want: usize) {
    for _ in 0..400 {
        if q.depth() == want {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("queue never reached depth {want} (was {})", q.depth());
}

/// AR-B-003: wait for the role-bound (quorum) pending track to reach `want`.
async fn wait_role_depth(q: &ApprovalQueue, want: usize) {
    for _ in 0..400 {
        if q.role_pending_depth() == want {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!(
        "role-pending never reached depth {want} (was {})",
        q.role_pending_depth()
    );
}

#[tokio::test]
async fn a_chain_effect_surfaces_and_approve_lets_it_proceed() {
    let queue = Arc::new(ApprovalQueue::new());
    let q = queue.clone();
    // A capsule's eth-send submits + blocks on the outcome (here, directly via the queue's async API).
    let submitter = tokio::spawn(async move { q.submit_with_outcome(effect_call("c1")).await });
    wait_depth(&queue, 1).await; // the effect is now a pending approval (what /approvals shows)
    queue.approve_by_id("c1").expect("c1 is the head"); // what POST /approvals/approve {id} calls
    let outcome = submitter.await.unwrap();
    assert!(
        matches!(outcome, ApprovalOutcomePublic::Approved),
        "approved → the effect proceeds"
    );
}

#[tokio::test]
async fn a_chain_effect_that_is_rejected_does_not_proceed() {
    let queue = Arc::new(ApprovalQueue::new());
    let q = queue.clone();
    let submitter = tokio::spawn(async move { q.submit_with_outcome(effect_call("c2")).await });
    wait_depth(&queue, 1).await;
    queue.reject_by_id("c2").expect("c2 is the head"); // POST /approvals/reject {id}
    let outcome = submitter.await.unwrap();
    assert!(
        matches!(outcome, ApprovalOutcomePublic::Rejected),
        "rejected → the effect is refused"
    );
}

/// A ToolCall shaped exactly as the QueuedApprovalGate submits a chain effect ({to, data_hex}).
fn chain_effect_call(id: &str) -> ToolCall {
    ToolCall {
        call_id: id.to_string(),
        name: "cap::eth-send".to_string(), // not trusted → pends
        args: serde_json::json!({
            "to": "0x4a86659BDab24dc444C72fbbaD4cd83491820E40",
            "data_hex": "0xdeadbeef",
            "data_len": 4
        }),
    }
}

#[tokio::test]
async fn approvals_exposes_the_raw_calldata_for_the_ceremony_bridge() {
    // S6.3: citrate-core's ceremony needs the raw (to, data) to build the SignatureIntent. /approvals
    // must surface them from the pending chain effect, not just a human summary.
    let queue = Arc::new(ApprovalQueue::new());
    let q = queue.clone();
    let submitter = tokio::spawn(async move { q.submit_with_outcome(chain_effect_call("cd1")).await });
    wait_depth(&queue, 1).await;

    let st = Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: queue.clone(),
        skills: vec![],
        dispatch: None,
        bearer: BEARER.to_string(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
    });
    let resp = app(st).oneshot(authed("GET", "/approvals")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(
        j[0]["to"], "0x4a86659BDab24dc444C72fbbaD4cd83491820E40",
        "the chain target is exposed"
    );
    assert_eq!(j[0]["data"], "0xdeadbeef", "the calldata is exposed");
    assert_eq!(j[0]["id"], "cd1", "the call-id the ceremony must echo back is exposed");

    queue.approve_by_id("cd1").expect("cd1 is the head");
    let _ = submitter.await;
}

fn resolve_req(path: &str, body: &'static str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", format!("Bearer {BEARER}"))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

fn state_with(queue: Arc<ApprovalQueue>) -> Arc<AppState> {
    Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue,
        skills: vec![],
        dispatch: None,
        bearer: BEARER.to_string(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
    })
}

/// PBA-L6b-009 regression: with a real effect pending, an approve/reject that does not name the
/// call (empty body, `{}`, a non-string id, malformed JSON) must be refused with 400 and must NOT
/// resolve the FIFO head. Pre-fix every one of these fell through to `queue.approve()` and released
/// whatever was at the head, reviewed or not.
#[tokio::test]
async fn an_unbound_approve_never_resolves_the_head_pba_l6b_009() {
    let queue = Arc::new(ApprovalQueue::new());
    let q = queue.clone();
    let submitter = tokio::spawn(async move { q.submit_with_outcome(chain_effect_call("u1")).await });
    wait_depth(&queue, 1).await;
    let st = state_with(queue.clone());

    for path in ["/approvals/approve", "/approvals/reject"] {
        for body in ["", "{}", r#"{"id":5}"#, "not json", r#"{"call_id":"u1"}"#] {
            let resp = app(st.clone()).oneshot(resolve_req(path, body)).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "{path} with body {body:?} must be refused"
            );
            assert_eq!(queue.depth(), 1, "{path} {body:?} must not resolve the head");
        }
    }
    assert!(!submitter.is_finished(), "the effect must still be waiting on a human");

    // The id-bound approve is the only way through.
    let resp = app(st.clone())
        .oneshot(resolve_req("/approvals/approve", r#"{"id":"u1"}"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["resolved"], true);
    assert_eq!(submitter.await.unwrap(), ApprovalOutcomePublic::Approved);
}

/// PBA-L6b-009 tripwire (class: "resolve whatever is at the head"). The core queue must not regrow
/// an id-less resolve API, and the sidecar must not call one. Source scan over both files so a
/// re-introduction fails here even if a new test forgets to cover it.
#[test]
fn tripwire_no_idless_head_resolution_pba_l6b_009() {
    let core = include_str!("../../agent/core/src/hitl/mod.rs");
    let sidecar = include_str!("lib.rs");
    for needle in ["pub fn approve(&self)", "pub fn reject(&self)", "fn pop_head_with"] {
        assert!(!core.contains(needle), "hitl/mod.rs regrew an id-less resolve path: {needle}");
    }
    for needle in [".approve()", ".reject()"] {
        assert!(!sidecar.contains(needle), "sidecar calls an id-less resolve path: {needle}");
    }
}

/// PBA-L6b-010 regression: POST /stop must freeze and drain the approval surface. Pre-fix /stop only
/// flipped the e-stop: /approvals kept serving to/data, an id-bound approve still released the
/// effect, and parked effects on both tracks stayed live.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_freezes_and_drains_the_approval_queue_pba_l6b_010() {
    use citrate_agent_core::hitl::{Quorum, Role, Signer};
    let queue = Arc::new(ApprovalQueue::new());
    // One FIFO effect and one role-track (quorum) effect, both parked.
    let q = queue.clone();
    let fifo = tokio::spawn(async move { q.submit_with_outcome(chain_effect_call("s1")).await });
    let q = queue.clone();
    let role = tokio::spawn(async move {
        q.submit_for_action(
            chain_effect_call("s2"),
            b"payload".to_vec(),
            Quorum::for_tier(
                citrate_agent_core::capsule::manifest::RiskTier::High,
                &[Role::Reviewer, Role::ComplianceOfficer],
            ),
            Signer {
                id: "operator-1".into(),
                role: Role::Operator,
            },
        )
        .await
    });
    wait_depth(&queue, 1).await;
    wait_role_depth(&queue, 1).await;
    let st = state_with(queue.clone());

    let resp = app(st.clone()).oneshot(authed("POST", "/stop")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Both parked effects are refused, not left pending.
    let fifo_out = tokio::time::timeout(std::time::Duration::from_secs(2), fifo)
        .await
        .expect("FIFO effect must be resolved by /stop")
        .unwrap();
    assert_eq!(fifo_out, ApprovalOutcomePublic::Rejected);
    let role_out = tokio::time::timeout(std::time::Duration::from_secs(2), role)
        .await
        .expect("role-track effect must be resolved by /stop")
        .unwrap();
    assert_eq!(role_out, ApprovalOutcomePublic::Rejected);
    assert_eq!(queue.depth(), 0);
    assert_eq!(queue.role_pending_depth(), 0);

    // While stopped the approval surface is closed.
    let resp = app(st.clone()).oneshot(authed("GET", "/approvals")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    for path in ["/approvals/approve", "/approvals/reject"] {
        let resp = app(st.clone())
            .oneshot(resolve_req(path, r#"{"id":"s1"}"#))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{path} while stopped");
    }

    // A skill still running when the stop landed cannot queue a new effect: the gate refuses it
    // at once instead of parking it for a human who can no longer act.
    let q = queue.clone();
    let late = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::spawn(async move { q.submit_with_outcome(chain_effect_call("s3")).await }),
    )
    .await
    .expect("a post-stop submission must not park")
    .unwrap();
    assert_eq!(late, ApprovalOutcomePublic::Rejected);
    assert_eq!(queue.depth(), 0);
}

/// PBA-L6b-032 regression: /status must count role-track (quorum) pending actions too. Pre-fix
/// `pendingApprovals` was the FIFO depth only, so a parked privileged effect was invisible.
#[tokio::test]
async fn status_counts_role_track_pending_pba_l6b_032() {
    use citrate_agent_core::hitl::{Quorum, Role, Signer};
    let queue = Arc::new(ApprovalQueue::new());
    let q = queue.clone();
    let h = tokio::spawn(async move {
        q.submit_for_action(
            chain_effect_call("rp1"),
            b"p".to_vec(),
            Quorum::for_tier(
                citrate_agent_core::capsule::manifest::RiskTier::Medium,
                &[Role::Reviewer],
            ),
            Signer {
                id: "op".into(),
                role: Role::Operator,
            },
        )
        .await
    });
    wait_role_depth(&queue, 1).await;
    let resp = app(state_with(queue.clone()))
        .oneshot(authed("GET", "/status"))
        .await
        .unwrap();
    let j = body_json(resp).await;
    assert_eq!(j["rolePendingApprovals"], 1, "role-track pending must be visible: {j}");
    queue.reject_action("rp1").unwrap();
    let _ = h.await;
}

/// PBA-L6b-032: run_skill is refused with 429 when every run slot is taken, instead of spawning
/// another task that may block a worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_skill_is_capped_pba_l6b_032() {
    let queue = Arc::new(ApprovalQueue::new());
    let dispatch = fixture_dispatch(queue.clone());
    assert!(dispatch.is_some());
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS));
    let held = slots.clone().acquire_many_owned(MAX_CONCURRENT_SKILLS as u32).await.unwrap();
    let st = Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue,
        skills: vec![SkillView {
            name: "eth-sender-test".into(),
            description: String::new(),
        }],
        dispatch,
        bearer: BEARER.to_string(),
        run_slots: slots.clone(),
    });
    let body = || run_body("eth-sender-test", serde_json::json!({"to": "0x00", "data": "0x00"}));
    let resp = app(st.clone()).oneshot(body()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let s = body_json(app(st.clone()).oneshot(authed("GET", "/status")).await.unwrap()).await;
    assert_eq!(s["runningSkills"], MAX_CONCURRENT_SKILLS);
    drop(held);
    let resp = app(st.clone()).oneshot(body()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "a free slot admits the skill");
    // The permit is released when the skill task ends.
    for _ in 0..400 {
        if slots.available_permits() == MAX_CONCURRENT_SKILLS {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("run slot never released");
}
