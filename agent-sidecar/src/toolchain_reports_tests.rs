//! HUP-S6.3 → S6.4 (retro A27): the toolchain's raw reports for core's deploy gate.
//!
//! - the digests that bind a run to the project (sources before and after, forge's bytecode);
//! - medusa's coverage report and the tier budget from the renderer's lock;
//! - the session keeps each run's raw report and hands the model the envelope without it;
//! - core reads them over `GET /sessions/:id/toolchain/reports`.
//!
//! The captured fixtures under `agent-loop/tests/fixtures/toolchain/captured/` are real runs of
//! slither 0.11.6, aderyn 0.6.8 and medusa 1.5.1 on a rendered erc20 template (2026-10-04,
//! scratch paths replaced by `/work`), so the runtime verifiers are checked against real output
//! (retro A29), and core's gate parses the same bytes.

use super::toolchain::*;
use super::toolchain_reports::*;
use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_loop::verifiers_tooling::{
    verify_medusa_output, verify_sarif_output, GateReport, RunStatus, SarifProfile, Severity,
    ToolchainEnvelope, ADERYN_SCAN_TOOL, FORGE_TEST_TOOL, MEDUSA_FUZZ_TOOL, SLITHER_SCAN_TOOL,
};
use citrate_agent_loop::{
    AssistantTurn, CompletionRequest, LlmClient, LlmError, ToolCall, ToolHost, ToolOutcome,
};
use citrate_agent_shell::sandbox::SandboxMode;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use tower::ServiceExt;

static N: AtomicUsize = AtomicUsize::new(0);
const BEARER: &str = "test-bearer-token-reports-0123";

struct Scratch {
    base: PathBuf,
}
impl Scratch {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "citrate-sidecar-tcreports-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("root/proj/src")).unwrap();
        std::fs::create_dir_all(base.join("bin")).unwrap();
        std::fs::create_dir_all(base.join("home")).unwrap();
        let s = Scratch {
            base: base.canonicalize().unwrap(),
        };
        s.write("src/Token.sol", "contract Token {}\n");
        s
    }
    fn proj(&self) -> PathBuf {
        self.base.join("root/proj")
    }
    fn write(&self, rel: &str, body: &str) {
        let p = self.proj().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }
    fn host(&self) -> ToolchainHost {
        ToolchainHost::new(ToolchainConfig {
            roots: vec![self.base.join("root")],
            search_path: vec![self.base.join("bin")],
            solc: None,
            home: self.base.join("home"),
            sandbox: SandboxMode::Off,
        })
        .unwrap()
    }
    /// A stand-in program printing `fixture` and running `extra` shell first.
    fn fake(&self, program: &str, fixture: &str, extra: &str) {
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{args}'\n{extra}\n/bin/cat '{f}'\nexit 0\n",
            args = self.base.join(format!("{program}.args")).display(),
            f = fixture_path(fixture).display(),
        );
        let p = self.base.join("bin").join(program);
        std::fs::write(&p, script).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    fn args_of(&self, program: &str) -> Vec<String> {
        std::fs::read_to_string(self.base.join(format!("{program}.args")))
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agent-loop/tests/fixtures/toolchain")
        .join(name)
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(fixture_path(name)).unwrap()
}

fn call(tool: &str, project: &Path) -> ToolCall {
    ToolCall {
        id: "c1".into(),
        name: tool.into(),
        arguments: serde_json::json!({ "project": project }).to_string(),
    }
}

fn content(o: &ToolOutcome) -> String {
    match o {
        ToolOutcome::Ok(s) | ToolOutcome::Untrusted(s) | ToolOutcome::Error(s) => s.clone(),
        ToolOutcome::Denied(s) => panic!("unexpected denial: {s}"),
    }
}

const ARTIFACT: &str = r#"{"abi":[],"bytecode":{"object":"0x6080604052"},"metadata":{"compiler":{"version":"0.8.36+commit.8a079791"}}}"#;

// ---- digests ---------------------------------------------------------------------------------

#[test]
fn the_source_digest_follows_sources_and_ignores_build_output() {
    let s = Scratch::new();
    let a = sources_sha256(&s.proj()).unwrap();
    // Build output, caches, coverage, git history and the tools' own reports are not sources.
    s.write("out/Token.sol/Token.json", ARTIFACT);
    s.write("cache/solidity-files-cache.json", "{}");
    s.write("medusa-corpus/coverage/lcov.info", "SF:x\n");
    s.write("crytic-export/x.json", "{}");
    s.write(".git/HEAD", "ref: refs/heads/main\n");
    s.write("aderyn-report.sarif", "{}");
    assert_eq!(sources_sha256(&s.proj()).unwrap(), a);
    // A source edit, a new test or a library change moves it.
    s.write("src/Token.sol", "contract Token { uint x; }\n");
    let b = sources_sha256(&s.proj()).unwrap();
    assert_ne!(a, b);
    s.write("lib/forge-std/src/Test.sol", "contract Test {}\n");
    assert_ne!(sources_sha256(&s.proj()).unwrap(), b);
}

#[test]
fn the_source_digest_is_path_sensitive() {
    let s = Scratch::new();
    s.write("src/A.sol", "x");
    let a = sources_sha256(&s.proj()).unwrap();
    std::fs::rename(s.proj().join("src/A.sol"), s.proj().join("src/B.sol")).unwrap();
    assert_ne!(sources_sha256(&s.proj()).unwrap(), a);
}

#[test]
fn bytecode_digest_ignores_prefix_and_case_and_refuses_empty_or_junk() {
    assert_eq!(bytecode_digest("0x60AB"), bytecode_digest("60ab"));
    assert!(bytecode_digest("0x").is_none());
    assert!(bytecode_digest("").is_none());
    assert!(bytecode_digest("0x6g").is_none());
    assert!(bytecode_digest("0x601").is_none());
    // SHA-256 over the ASCII hex "60ab".
    assert_eq!(
        bytecode_digest("0x60ab").unwrap(),
        "52bd87a0b63441df940c79c082a02cee57ce93a553af675a32a6c9cdfe40aeda"
    );
}

#[test]
fn forge_artifacts_records_built_bytecode_only() {
    let s = Scratch::new();
    s.write("out/Token.sol/Token.json", ARTIFACT);
    s.write(
        "out/IToken.sol/IToken.json",
        r#"{"abi":[],"bytecode":{"object":"0x"}}"#,
    );
    s.write("out/build-info/abc.json", ARTIFACT);
    s.write("out/Broken.sol/Broken.json", "not json");
    let a = forge_artifacts(&s.proj());
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(
        a.get("Token.sol/Token.json"),
        bytecode_digest("0x6080604052").as_ref()
    );
}

#[test]
fn medusa_coverage_is_taken_only_from_this_run() {
    let s = Scratch::new();
    let before = SystemTime::now() - Duration::from_secs(5);
    s.write(
        "medusa-corpus/coverage/lcov.info",
        "SF:/work/src/Token.sol\nDA:1,1\nend_of_record\n",
    );
    assert!(medusa_lcov(&s.proj(), before).unwrap().contains("DA:1,1"));
    // Written before the run started: stale, not this run's.
    let later = SystemTime::now() + Duration::from_secs(60);
    assert!(medusa_lcov(&s.proj(), later).is_none());
}

#[test]
fn medusa_coverage_follows_the_configured_corpus_and_refuses_escapes() {
    let s = Scratch::new();
    let before = SystemTime::now() - Duration::from_secs(5);
    s.write("medusa.json", r#"{"fuzzing":{"corpusDirectory":"corp"}}"#);
    s.write("corp/coverage/lcov.info", "SF:a\n");
    assert_eq!(medusa_lcov(&s.proj(), before).as_deref(), Some("SF:a\n"));
    s.write(
        "medusa.json",
        r#"{"fuzzing":{"corpusDirectory":"../corp"}}"#,
    );
    assert!(medusa_lcov(&s.proj(), before).is_none());
    s.write("medusa.json", r#"{"fuzzing":{"corpusDirectory":"/etc"}}"#);
    assert!(medusa_lcov(&s.proj(), before).is_none());
}

#[test]
fn the_tier_budget_comes_from_the_renderer_lock_here_or_above() {
    let s = Scratch::new();
    assert_eq!(lock_test_limit(&s.proj()), None);
    s.write(
        TEMPLATE_LOCK_FILE,
        r#"{"medusa_budget":{"test_limit":10000},"includes":[]}"#,
    );
    assert_eq!(lock_test_limit(&s.proj()), Some(10_000));
    // hello-mint: the contract project is contracts/ and the lock (with an include) is above it.
    std::fs::remove_file(s.proj().join(TEMPLATE_LOCK_FILE)).unwrap();
    std::fs::create_dir_all(s.proj().join("contracts")).unwrap();
    s.write(
        TEMPLATE_LOCK_FILE,
        r#"{"medusa_budget":null,"includes":[{"medusa_budget":{"test_limit":200000}}]}"#,
    );
    assert_eq!(lock_test_limit(&s.proj().join("contracts")), Some(200_000));
}

// ---- the host attaches the report --------------------------------------------------------------

#[test]
fn a_forge_run_carries_its_raw_report_digest_and_built_bytecode() {
    let s = Scratch::new();
    s.write("out/Token.sol/Token.json", ARTIFACT);
    s.fake("forge", "forge-test-pass.json", "");
    let out = s.host().execute(&call(FORGE_TEST_TOOL, &s.proj()));
    let env = ToolchainEnvelope::from_content(&content(&out)).unwrap();
    let g = env.gate.expect("a completed run carries its gate report");
    assert_eq!(g.output, fixture("forge-test-pass.json"));
    assert_eq!(g.project, s.proj().to_string_lossy());
    assert_eq!(g.sources_sha256, sources_sha256(&s.proj()));
    assert_eq!(
        g.artifacts.get("Token.sol/Token.json"),
        bytecode_digest("0x6080604052").as_ref()
    );
    assert_eq!(g.test_limit, None);
}

#[test]
fn a_run_that_changes_the_sources_while_it_runs_is_not_bound() {
    let s = Scratch::new();
    let edit = format!(
        "echo changed >> '{}'",
        s.proj().join("src/Token.sol").display()
    );
    s.fake("slither", "slither-info-only.sarif", &edit);
    let out = s.host().execute(&call(SLITHER_SCAN_TOOL, &s.proj()));
    let env = ToolchainEnvelope::from_content(&content(&out)).unwrap();
    assert_eq!(env.gate.unwrap().sources_sha256, None);
}

#[test]
fn medusa_uses_the_lock_budget_and_reports_this_runs_coverage() {
    let s = Scratch::new();
    s.write(
        TEMPLATE_LOCK_FILE,
        r#"{"medusa_budget":{"test_limit":10000},"includes":[]}"#,
    );
    let lcov = s.proj().join("medusa-corpus/coverage/lcov.info");
    let extra = format!(
        "/bin/mkdir -p '{}' && printf 'SF:x\\nDA:1,3\\nend_of_record\\n' > '{}'",
        lcov.parent().unwrap().display(),
        lcov.display()
    );
    s.fake("medusa", "captured/medusa-erc20-T0.txt", &extra);
    let out = s.host().execute(&call(MEDUSA_FUZZ_TOOL, &s.proj()));
    assert_eq!(
        &s.args_of("medusa")[2..4],
        &["--test-limit".to_string(), "10000".to_string()]
    );
    let env = ToolchainEnvelope::from_content(&content(&out)).unwrap();
    assert!(env.verdict.as_ref().unwrap().passed, "{}", env.summary);
    let g = env.gate.unwrap();
    assert_eq!(g.test_limit, Some(10_000));
    assert!(g.coverage_lcov.unwrap().contains("DA:1,3"));
}

#[test]
fn an_explicit_budget_still_wins_over_the_lock() {
    let s = Scratch::new();
    s.write(
        TEMPLATE_LOCK_FILE,
        r#"{"medusa_budget":{"test_limit":10000},"includes":[]}"#,
    );
    s.fake("medusa", "captured/medusa-erc20-T0.txt", "");
    let c = ToolCall {
        id: "c".into(),
        name: MEDUSA_FUZZ_TOOL.into(),
        arguments: serde_json::json!({"project": s.proj(), "test_limit": 50000}).to_string(),
    };
    s.host().execute(&c);
    assert_eq!(s.args_of("medusa")[3], "50000");
}

#[test]
fn a_tool_that_is_not_installed_carries_no_report() {
    let s = Scratch::new();
    let out = s.host().execute(&call(ADERYN_SCAN_TOOL, &s.proj()));
    let env = ToolchainEnvelope::from_content(&content(&out)).unwrap();
    assert_eq!(env.status, RunStatus::NotInstalled);
    assert!(env.gate.is_none());
}

// ---- capture --------------------------------------------------------------------------------

fn envelope_with_gate(tool: &str, project: &str, output: &str) -> ToolOutcome {
    let v = verify_sarif_output(output, SarifProfile::Slither, Severity::High);
    ToolOutcome::Ok(
        ToolchainEnvelope::completed(tool, v)
            .with_gate(GateReport {
                project: project.into(),
                output: output.into(),
                duration_ms: 7,
                sources_sha256: Some("ab".into()),
                test_limit: None,
                coverage_lcov: None,
                artifacts: Default::default(),
            })
            .to_content(),
    )
}

#[test]
fn capture_keeps_the_report_and_hands_the_model_the_envelope_without_it() {
    let r = ToolchainReports::default();
    let raw = fixture("captured/slither-erc20-suicidal.sarif");
    let c = call(SLITHER_SCAN_TOOL, Path::new("/nonexistent/proj"));
    let out = capture(&r, &c, envelope_with_gate(SLITHER_SCAN_TOOL, "/p", &raw));
    let seen = content(&out);
    assert!(!seen.contains("\"gate\""), "{seen}");
    assert!(
        !seen.contains("\"runs\"") && !seen.contains("sarif-schema"),
        "the raw report never reaches the model"
    );
    let env = ToolchainEnvelope::from_content(&seen).unwrap();
    assert!(
        !env.verdict.unwrap().passed,
        "the step verdict still reads the High"
    );
    let kept = r.list(None);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].project, "/p");
    assert_eq!(kept[0].gate.as_ref().unwrap().output, raw);
}

#[test]
fn capture_records_not_installed_by_the_called_project_and_skips_refusals() {
    let s = Scratch::new();
    let r = ToolchainReports::default();
    let c = call(ADERYN_SCAN_TOOL, &s.proj());
    let ni = ToolchainEnvelope::not_run(
        ADERYN_SCAN_TOOL,
        RunStatus::NotInstalled,
        "aderyn is not installed",
    );
    capture(&r, &c, ToolOutcome::Error(ni.to_content()));
    let refused = ToolchainEnvelope::not_run(ADERYN_SCAN_TOOL, RunStatus::Refused, "no");
    capture(&r, &c, ToolOutcome::Error(refused.to_content()));
    let kept = r.list(Some(&s.proj().to_string_lossy()));
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].status, RunStatus::NotInstalled);
    assert!(kept[0].gate.is_none());
    // Something that is not a toolchain envelope passes through untouched.
    let plain = capture(&r, &c, ToolOutcome::Ok("hello".into()));
    assert_eq!(content(&plain), "hello");
}

#[test]
fn the_latest_report_per_project_and_tool_wins_and_the_store_is_bounded() {
    let r = ToolchainReports::default();
    let c = call(SLITHER_SCAN_TOOL, Path::new("/x"));
    let raw = fixture("slither-info-only.sarif");
    capture(&r, &c, envelope_with_gate(SLITHER_SCAN_TOOL, "/a", &raw));
    capture(&r, &c, envelope_with_gate(SLITHER_SCAN_TOOL, "/a", &raw));
    capture(&r, &c, envelope_with_gate(FORGE_TEST_TOOL, "/a", &raw));
    let kept = r.list(Some("/a"));
    assert_eq!(kept.len(), 2);
    assert!(kept[0].seq < kept[1].seq);
    assert_eq!(kept[1].tool, FORGE_TEST_TOOL);
    for i in 0..(MAX_REPORTS + 5) {
        capture(
            &r,
            &c,
            envelope_with_gate(SLITHER_SCAN_TOOL, &format!("/p{i}"), &raw),
        );
    }
    let all = r.list(None);
    assert_eq!(all.len(), MAX_REPORTS);
    assert!(
        all.iter().all(|k| k.project != "/a"),
        "the oldest went first"
    );
}

// ---- real captured output through the runtime verifiers (A29) ------------------------------------

#[test]
fn captured_aderyn_and_medusa_runs_are_judged_like_the_gate_judges_them() {
    let clean = verify_sarif_output(
        &fixture("captured/aderyn-erc20-clean.txt"),
        SarifProfile::Aderyn,
        Severity::High,
    );
    assert!(clean.passed, "{}", clean.reason);
    let bug = verify_sarif_output(
        &fixture("captured/aderyn-erc20-selfdestruct.txt"),
        SarifProfile::Aderyn,
        Severity::High,
    );
    assert!(!bug.passed, "aderyn's selfdestruct issue is High");
    let slither = verify_sarif_output(
        &fixture("captured/slither-erc20-suicidal.sarif"),
        SarifProfile::Slither,
        Severity::High,
    );
    assert!(!slither.passed);
    let medusa = verify_medusa_output(&fixture("captured/medusa-erc20-T0.txt"));
    assert!(medusa.passed, "{}", medusa.reason);
}

// ---- the session and the route ----------------------------------------------------------------

struct Script(Mutex<Vec<AssistantTurn>>);
impl LlmClient for Script {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let mut t = self.0.lock().unwrap();
        Ok(if t.is_empty() {
            AssistantTurn::text("(done)")
        } else {
            t.remove(0)
        })
    }
}

fn state(turns: Vec<AssistantTurn>, host: Option<ToolchainHost>) -> Arc<AppState> {
    let llm = Arc::new(Script(Mutex::new(turns)));
    let mut mgr = sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| llm.clone() as Arc<dyn LlmClient>),
        Duration::from_secs(5),
    );
    if let Some(h) = host {
        mgr = mgr.with_toolchain(Arc::new(h));
    }
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

async fn get(st: &Arc<AppState>, path: &str, auth: bool) -> (StatusCode, serde_json::Value) {
    let mut b = Request::builder().method("GET").uri(path);
    if auth {
        b = b.header("authorization", format!("Bearer {BEARER}"));
    }
    let r = app(st.clone())
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = r.status();
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 24).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn create_req() -> sessions::CreateSessionReq {
    serde_json::from_value(serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes.",
        "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        "tools": [],
        "maxToolsPerRequest": 8
    }))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_keeps_the_raw_report_for_core_and_the_model_never_sees_it() {
    let s = Scratch::new();
    s.write("out/Token.sol/Token.json", ARTIFACT);
    s.fake("forge", "forge-test-pass.json", "");
    let st = state(
        vec![
            AssistantTurn::tools(vec![call(FORGE_TEST_TOOL, &s.proj())]),
            AssistantTurn::text("Tests pass."),
        ],
        Some(s.host()),
    );
    let id = st.sessions.create(create_req()).unwrap();
    st.sessions.send(&id, "run the tests".into(), None).unwrap();
    let sess = st.sessions.get(&id).unwrap();
    let mut after = 0;
    let mut events = vec![];
    for _ in 0..100 {
        let page = sess.wait_events(after, Duration::from_millis(200)).await;
        for e in page.events {
            after = after.max(e.seq);
            events.push(serde_json::to_value(&e.event).unwrap());
        }
        if events.iter().any(|e| e["type"] == "done") {
            break;
        }
    }
    let tr = events
        .iter()
        .find(|e| e["type"] == "tool_result")
        .expect("a tool result");
    let seen = tr["content"].as_str().unwrap();
    assert!(!seen.contains("\"gate\""), "{seen}");
    assert!(
        ToolchainEnvelope::from_content(seen)
            .unwrap()
            .verdict
            .unwrap()
            .passed
    );

    let proj = s.proj().to_string_lossy().into_owned();
    let (code, body) = get(
        &st,
        &format!("/sessions/{id}/toolchain/reports?project={proj}"),
        true,
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{body}");
    let reps = body["reports"].as_array().unwrap();
    assert_eq!(reps.len(), 1);
    assert_eq!(reps[0]["tool"], FORGE_TEST_TOOL);
    assert_eq!(reps[0]["status"], "completed");
    assert_eq!(reps[0]["gate"]["output"], fixture("forge-test-pass.json"));
    assert_eq!(
        reps[0]["gate"]["artifacts"]["Token.sol/Token.json"],
        bytecode_digest("0x6080604052").unwrap()
    );
    // Another project's filter finds nothing; no bearer, no reports.
    let (_, other) = get(
        &st,
        &format!("/sessions/{id}/toolchain/reports?project=/elsewhere"),
        true,
    )
    .await;
    assert_eq!(other["reports"].as_array().unwrap().len(), 0);
    let (code, _) = get(&st, &format!("/sessions/{id}/toolchain/reports"), false).await;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_the_toolchain_the_reports_route_is_not_found() {
    let st = state(vec![], None);
    let id = st.sessions.create(create_req()).unwrap();
    let (code, _) = get(&st, &format!("/sessions/{id}/toolchain/reports"), true).await;
    assert_eq!(code, StatusCode::NOT_FOUND);
    let (code, _) = get(&st, "/sessions/nope/toolchain/reports", true).await;
    assert_eq!(code, StatusCode::NOT_FOUND);
}

#[test]
fn medusas_slither_results_file_is_output_not_a_source() {
    // medusa 1.5 writes slither_results.json into the project during every campaign (captured
    // in the hello-mint e2e, fan-out 7); the digest before and after the run must still agree.
    let s = Scratch::new();
    let a = sources_sha256(&s.proj()).unwrap();
    s.write("slither_results.json", "{\"success\": true}");
    assert_eq!(sources_sha256(&s.proj()).unwrap(), a);
    // A source that merely starts with the same letters is still a source.
    s.write("src/slither_results_reader.sol", "contract R {}\n");
    assert_ne!(sources_sha256(&s.proj()).unwrap(), a);
}
