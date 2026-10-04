//! HUP-S6 US-6.2 "Refuses unready code" and US-6.1 AC2 "NOT READY with the finding and a
//! proposed fix", as BDD scenarios on a real sidecar session.
//!
//! The toolchain programs are stand-ins that print the **captured** output of the real tools
//! (slither 0.11.6 and aderyn 0.6.8 on the erc20 template with an injected `selfdestruct`;
//! forge 1.5.1 on the hello-mint template with the supply cap removed), so the session keeps the
//! same raw reports a real run keeps. The model is scripted. "The ceremony store is empty" is
//! checked from the sidecar's side, where it is decided: core opens a SignatureCeremony for a
//! deploy only when a `contract_deploy` call is announced to it with host `core`; the scenarios
//! assert that no such event exists and that no core call is waiting.

use super::toolchain::*;
use super::*;
use citrate_agent_loop::verifiers_tooling::{ADERYN_SCAN_TOOL, FORGE_TEST_TOOL, SLITHER_SCAN_TOOL};
use citrate_agent_loop::{
    AssistantTurn, CompletionRequest, LlmClient, LlmError, ToolCall, ToolOutcome,
};
use citrate_agent_shell::sandbox::SandboxMode;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

static N: AtomicUsize = AtomicUsize::new(0);
const BEARER: &str = "test-bearer-token-deployguard-01";

struct Scratch {
    base: PathBuf,
}
impl Scratch {
    fn new(source_fixture: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "citrate-sidecar-deployguard-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&base);
        for d in ["root/proj/src", "bin", "home"] {
            std::fs::create_dir_all(base.join(d)).expect("scratch dir");
        }
        let s = Scratch {
            base: base.canonicalize().expect("canonical scratch"),
        };
        std::fs::write(s.proj().join("src/Token.sol"), captured(source_fixture)).expect("source");
        s
    }
    fn proj(&self) -> PathBuf {
        self.base.join("root/proj")
    }
    fn host(&self) -> ToolchainHost {
        ToolchainHost::new(ToolchainConfig {
            roots: vec![self.base.join("root")],
            search_path: vec![self.base.join("bin")],
            solc: None,
            home: self.base.join("home"),
            sandbox: SandboxMode::Off,
        })
        .expect("toolchain host")
    }
    /// A stand-in `program` that prints the captured output `fixture`.
    fn fake(&self, program: &str, fixture: &str) {
        let script = format!(
            "#!/bin/sh\n/bin/cat '{}'\nexit 0\n",
            captured_path(fixture).display()
        );
        let p = self.base.join("bin").join(program);
        std::fs::write(&p, script).expect("fake program");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn captured_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agent-loop/tests/fixtures/toolchain/captured")
        .join(name)
}

fn captured(name: &str) -> String {
    std::fs::read_to_string(captured_path(name)).expect("fixture")
}

/// A scripted model that counts its calls.
struct Script {
    turns: Mutex<Vec<AssistantTurn>>,
    calls: AtomicUsize,
}
impl LlmClient for Script {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut t = self
            .turns
            .lock()
            .map_err(|_| LlmError::Transport("lock".into()))?;
        Ok(if t.is_empty() {
            AssistantTurn::text("(done)")
        } else {
            t.remove(0)
        })
    }
}

fn state(llm: Arc<Script>, host: ToolchainHost) -> Arc<AppState> {
    let mgr = sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| llm.clone() as Arc<dyn LlmClient>),
        Duration::from_secs(5),
    )
    .with_toolchain(Arc::new(host));
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

/// A session offered core's `contract_deploy`, as the app opens it.
fn create_req() -> sessions::CreateSessionReq {
    serde_json::from_value(serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes.",
        "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        "tools": [{
            "name": "contract_deploy",
            "description": "Deploy a gated contract through the SignatureCeremony.",
            "parameters": {"type": "object"},
            "host": "core",
            "annotations": {"effect": "sign", "trust": "trusted"}
        }],
        "maxToolsPerRequest": 8
    }))
    .expect("create request")
}

fn tool_call(id: &str, tool: &str, project: &Path) -> ToolCall {
    ToolCall {
        id: id.into(),
        name: tool.into(),
        arguments: serde_json::json!({ "project": project }).to_string(),
    }
}

fn deploy_call(id: &str) -> ToolCall {
    ToolCall {
        id: id.into(),
        name: "contract_deploy".into(),
        arguments: r#"{"bytecodeHex":"0x6080"}"#.into(),
    }
}

/// Send `text` and collect this turn's events (until `done`), answering any core call with
/// `core_answer` so a dispatched core call does not wait out its deadline.
async fn turn(st: &Arc<AppState>, id: &str, text: &str, after: &mut u64) -> Vec<serde_json::Value> {
    st.sessions
        .send(id, text.into(), None)
        .expect("the turn starts");
    let sess = st.sessions.get(id).expect("session");
    let mut events = vec![];
    for _ in 0..200 {
        let page = sess.wait_events(*after, Duration::from_millis(100)).await;
        for e in page.events {
            *after = (*after).max(e.seq);
            events.push(serde_json::to_value(&e.event).expect("event json"));
        }
        for call in sess.pending_core_calls() {
            sess.deliver(&call, ToolOutcome::Ok("core answered".into()));
        }
        if events.iter().any(|e| e["type"] == "done") && !sess.is_busy() {
            break;
        }
    }
    events
}

fn final_text(events: &[serde_json::Value]) -> String {
    events
        .iter()
        .rev()
        .find(|e| e["type"] == "final")
        .and_then(|e| e["content"].as_str())
        .unwrap_or_default()
        .to_string()
}

fn core_deploy_announced(events: &[serde_json::Value]) -> bool {
    events.iter().any(|e| {
        e["type"] == "tool_call" && e["call"]["name"] == "contract_deploy" && e["host"] == "core"
    })
}

// Feature: Refuses unready code (US-6.2)
//   Scenario: Gate blocks deploy
//     Given the contract has a High slither finding
//     When the Dev asks Hermes to deploy anyway
//     Then Hermes refuses, cites the finding, and offers a fix
//     And no ceremony is created
#[tokio::test(flavor = "multi_thread")]
async fn us_6_2_deploy_anyway_after_a_high_slither_finding_is_refused_with_a_fix() {
    let s = Scratch::new("erc20-Token-selfdestruct.sol");
    s.fake("slither", "slither-erc20-suicidal.sarif");
    s.fake("aderyn", "aderyn-erc20-selfdestruct.txt");
    let llm = Arc::new(Script {
        turns: Mutex::new(vec![
            AssistantTurn::tools(vec![
                tool_call("s1", SLITHER_SCAN_TOOL, &s.proj()),
                tool_call("a1", ADERYN_SCAN_TOOL, &s.proj()),
            ]),
            AssistantTurn::text("Slither and Aderyn each report a High finding."),
        ]),
        calls: AtomicUsize::new(0),
    });
    let st = state(llm.clone(), s.host());
    let id = st.sessions.create(create_req()).expect("session");
    let mut after = 0;

    // Given the contract has a High slither finding
    let ev = turn(&st, &id, "scan the contract", &mut after).await;
    assert!(final_text(&ev).contains("High"), "{ev:?}");
    let model_calls = llm.calls.load(Ordering::SeqCst);

    // When the Dev asks Hermes to deploy anyway
    let ev = turn(&st, &id, "Deploy it anyway, I accept the risk.", &mut after).await;

    // Then Hermes refuses, cites the finding, and offers a fix
    let text = final_text(&ev);
    assert!(text.starts_with("I won't deploy this contract."), "{text}");
    assert!(
        text.contains("Slither `0-0-suicidal` (High) at `src/Token.sol:19`"),
        "{text}"
    );
    assert!(text.contains("Aderyn `selfdestruct` (High)"), "{text}");
    assert!(text.contains("Proposed fix:"), "{text}");
    assert!(
        text.contains("-    function shutdown() external {\n-        selfdestruct(payable(msg.sender));\n-    }"),
        "{text}"
    );
    assert_eq!(
        llm.calls.load(Ordering::SeqCst),
        model_calls,
        "the refusal is the sidecar's own answer, not a model call"
    );
    // And no ceremony is created: nothing was announced to core and no core call waits.
    assert!(!ev.iter().any(|e| e["type"] == "tool_call"), "{ev:?}");
    let sess = st.sessions.get(&id).expect("session");
    assert!(sess.pending_core_calls().is_empty());
    // The refusal is part of the conversation the model sees next.
    assert!(sess
        .history_snapshot()
        .iter()
        .any(|m| m.content.starts_with("I won't deploy this contract.")));
}

#[tokio::test(flavor = "multi_thread")]
async fn us_6_2_a_contract_deploy_call_the_model_makes_anyway_never_reaches_core() {
    let s = Scratch::new("erc20-Token-selfdestruct.sol");
    s.fake("slither", "slither-erc20-suicidal.sarif");
    let llm = Arc::new(Script {
        turns: Mutex::new(vec![
            AssistantTurn::tools(vec![tool_call("s1", SLITHER_SCAN_TOOL, &s.proj())]),
            // The model ignores the finding and tries to deploy in the same turn.
            AssistantTurn::tools(vec![deploy_call("d1")]),
            AssistantTurn::text("The deploy was declined."),
        ]),
        calls: AtomicUsize::new(0),
    });
    let st = state(llm, s.host());
    let id = st.sessions.create(create_req()).expect("session");
    let mut after = 0;
    let ev = turn(&st, &id, "scan it and finish up", &mut after).await;
    let call = ev
        .iter()
        .find(|e| e["type"] == "tool_call" && e["call"]["name"] == "contract_deploy")
        .expect("the model's deploy call is recorded");
    assert!(call["host"].is_null(), "announced to no host: {call}");
    let result = ev
        .iter()
        .find(|e| e["type"] == "tool_result" && e["call_id"] == "d1")
        .expect("a result");
    assert_eq!(result["status"], "denied");
    let content = result["content"].as_str().unwrap_or_default();
    assert!(content.contains("0-0-suicidal"), "{content}");
    assert!(!core_deploy_announced(&ev));
    assert!(st
        .sessions
        .get(&id)
        .expect("session")
        .pending_core_calls()
        .is_empty());
}

// Feature: hello mint (US-6.1 AC2)
//   Scenario: an injected unbounded mint yields NOT READY with the finding and a proposed fix
#[tokio::test(flavor = "multi_thread")]
async fn us_6_1_ac2_the_unbounded_mint_is_refused_naming_the_cap_test_with_the_soldout_patch() {
    let s = Scratch::new("hellomint-Token-unbounded.sol");
    s.fake("forge", "forge-hellomint-unbounded-mint.json");
    let llm = Arc::new(Script {
        turns: Mutex::new(vec![
            AssistantTurn::tools(vec![tool_call("f1", FORGE_TEST_TOOL, &s.proj())]),
            AssistantTurn::text("One test fails."),
        ]),
        calls: AtomicUsize::new(0),
    });
    let st = state(llm, s.host());
    let id = st.sessions.create(create_req()).expect("session");
    let mut after = 0;
    let _ = turn(&st, &id, "run the tests", &mut after).await;
    let ev = turn(&st, &id, "ok, deploy", &mut after).await;
    let text = final_text(&ev);
    assert!(
        text.contains(
            "Forge tests failing: `test/Token.t.sol:LemonDropsTest::test_mint_stops_at_the_cap()`"
        ),
        "{text}"
    );
    assert!(
        text.contains("+        if (quantity > remaining) revert SoldOut(quantity, remaining);"),
        "{text}"
    );
    assert!(!ev.iter().any(|e| e["type"] == "tool_call"));
}

// The control: with clean reports nothing is declined; the deploy request goes to the model and
// its contract_deploy call is announced to core as before (core's gate still decides).
#[tokio::test(flavor = "multi_thread")]
async fn with_clean_reports_the_guard_changes_nothing() {
    let s = Scratch::new("erc20-Token-selfdestruct.sol");
    s.fake("slither", "slither-erc20-clean.sarif");
    let llm = Arc::new(Script {
        turns: Mutex::new(vec![
            AssistantTurn::tools(vec![tool_call("s1", SLITHER_SCAN_TOOL, &s.proj())]),
            AssistantTurn::text("Clean."),
            AssistantTurn::tools(vec![deploy_call("d1")]),
            AssistantTurn::text("Core has the deploy."),
        ]),
        calls: AtomicUsize::new(0),
    });
    let st = state(llm.clone(), s.host());
    let id = st.sessions.create(create_req()).expect("session");
    let mut after = 0;
    let _ = turn(&st, &id, "scan it", &mut after).await;
    let before = llm.calls.load(Ordering::SeqCst);
    let ev = turn(&st, &id, "deploy it", &mut after).await;
    assert!(
        llm.calls.load(Ordering::SeqCst) > before,
        "the model answered"
    );
    assert!(core_deploy_announced(&ev), "{ev:?}");
}

#[test]
fn proposals_read_only_plain_sources_inside_the_project() {
    let s = Scratch::new("erc20-Token-selfdestruct.sol");
    let p = s.proj();
    assert!(deploy_guard::read_project_source(&p, "src/Token.sol").is_some());
    assert!(deploy_guard::read_project_source(&p, "../root/proj/src/Token.sol").is_none());
    assert!(deploy_guard::read_project_source(&p, "src/Missing.sol").is_none());
    // A symlinked source is not followed.
    let outside = s.base.join("home/Outside.sol");
    std::fs::write(&outside, "contract Outside {}").expect("outside");
    std::os::unix::fs::symlink(&outside, p.join("src/Link.sol")).expect("symlink");
    assert!(deploy_guard::read_project_source(&p, "src/Link.sol").is_none());
    // A symlinked folder on the way is not followed either.
    std::fs::create_dir_all(s.base.join("home/evil")).expect("dir");
    std::fs::write(s.base.join("home/evil/E.sol"), "x").expect("file");
    std::os::unix::fs::symlink(s.base.join("home/evil"), p.join("src/evil")).expect("symlink dir");
    assert!(deploy_guard::read_project_source(&p, "src/evil/E.sol").is_none());
}
