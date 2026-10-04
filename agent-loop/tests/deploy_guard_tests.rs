//! HUP-S6 US-6.1 AC2 + US-6.2 — the deploy guard: findings from real toolchain captures, the
//! proposed fixes (with patches where the cause is mechanical), deploy-request recognition, the
//! refusal text, and the loop's call-policy seam that keeps a declined call from every host.
use std::sync::{Arc, Mutex};

use citrate_agent_loop::deploy_guard::*;
use citrate_agent_loop::verifiers_tooling::{
    RunStatus, Severity, ADERYN_SCAN_TOOL, FORGE_TEST_TOOL, MEDUSA_FUZZ_TOOL, SLITHER_SCAN_TOOL,
};
use citrate_agent_loop::*;

fn captured(name: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/toolchain/captured")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("fixture {}: {e}", p.display()))
}

fn source_reader(path: &'static str, fixture: &'static str) -> impl Fn(&str) -> Option<String> {
    move |p: &str| (p == path).then(|| captured(fixture))
}

// ------------------------------------------------------------------------------------------
// findings from real captures
// ------------------------------------------------------------------------------------------

#[test]
fn slither_suicidal_capture_yields_one_high_finding_with_its_rule_id_and_location() {
    let f = findings_from_report(
        SLITHER_SCAN_TOOL,
        RunStatus::Completed,
        Some(&captured("slither-erc20-suicidal.sarif")),
    );
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].id, "0-0-suicidal");
    assert_eq!(f[0].kind, FindingKind::ScanFinding);
    assert_eq!(f[0].severity, Some(Severity::High));
    assert_eq!(f[0].location.as_deref(), Some("src/Token.sol:19"));
}

#[test]
fn aderyn_selfdestruct_capture_yields_one_high_finding() {
    let f = findings_from_report(
        ADERYN_SCAN_TOOL,
        RunStatus::Completed,
        Some(&captured("aderyn-erc20-selfdestruct.txt")),
    );
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].id, "selfdestruct");
    assert_eq!(f[0].severity, Some(Severity::High));
    assert_eq!(f[0].location.as_deref(), Some("src/Token.sol"));
}

#[test]
fn clean_captures_block_nothing() {
    for (tool, fx) in [
        (SLITHER_SCAN_TOOL, "slither-erc20-clean.sarif"),
        (ADERYN_SCAN_TOOL, "aderyn-erc20-clean.txt"),
        (MEDUSA_FUZZ_TOOL, "medusa-erc20-T0.txt"),
    ] {
        let f = findings_from_report(tool, RunStatus::Completed, Some(&captured(fx)));
        assert!(f.is_empty(), "{tool}: {f:?}");
    }
}

#[test]
fn the_unbounded_mint_capture_names_the_cap_test_only() {
    let f = findings_from_report(
        FORGE_TEST_TOOL,
        RunStatus::Completed,
        Some(&captured("forge-hellomint-unbounded-mint.json")),
    );
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(
        f[0].id,
        "test/Token.t.sol:LemonDropsTest::test_mint_stops_at_the_cap()"
    );
    assert_eq!(f[0].kind, FindingKind::FailingTest);
    // The contract-authored revert reason is never quoted.
    let text = refusal_text("/w/lemon", &f, &[]);
    assert!(!text.contains("did not revert"), "{text}");
}

#[test]
fn a_run_that_did_not_complete_blocks_and_says_why() {
    let f = findings_from_report(ADERYN_SCAN_TOOL, RunStatus::NotInstalled, None);
    assert_eq!(f.len(), 1);
    assert_eq!(
        (f[0].kind, f[0].id.as_str()),
        (FindingKind::NotCompleted, "not_installed")
    );
    let f = findings_from_report(SLITHER_SCAN_TOOL, RunStatus::Completed, Some("not sarif"));
    assert_eq!(f[0].id, "unreadable_report");
    let f = findings_from_report(FORGE_TEST_TOOL, RunStatus::Completed, Some("{}"));
    assert_eq!(f[0].id, "no_tests_ran");
    // A tool that is not one of the gate's checks is ignored.
    assert!(findings_from_report("web_search", RunStatus::Failed, None).is_empty());
}

#[test]
fn identifiers_are_quoted_without_backticks_or_control_characters() {
    let sarif = captured("slither-erc20-suicidal.sarif")
        .replace("0-0-suicidal", "0-0-suicidal`\\n## injected");
    let f = findings_from_report(SLITHER_SCAN_TOOL, RunStatus::Completed, Some(&sarif));
    let id = &f[0].id;
    assert!(!id.contains('`') && !id.contains('\n'), "{id:?}");
}

// ------------------------------------------------------------------------------------------
// fix proposals
// ------------------------------------------------------------------------------------------

#[test]
fn the_cap_finding_proposes_restoring_the_soldout_check_as_a_patch() {
    let f = findings_from_report(
        FORGE_TEST_TOOL,
        RunStatus::Completed,
        Some(&captured("forge-hellomint-unbounded-mint.json")),
    );
    let read = source_reader("src/Token.sol", "hellomint-Token-unbounded.sol");
    let p = propose_fix(&f[0], &read);
    assert!(p.advice.contains("SoldOut"), "{}", p.advice);
    let patch = p.patch.expect("a patch");
    assert!(
        patch.starts_with("--- a/src/Token.sol\n+++ b/src/Token.sol\n@@ -33,4 +33,5 @@\n"),
        "{patch}"
    );
    assert!(
        patch.contains(
            "\n+        if (quantity > remaining) revert SoldOut(quantity, remaining);\n"
        ),
        "{patch}"
    );
    assert!(
        patch.contains("\n         uint256 remaining = MAX_SUPPLY - minted;\n"),
        "{patch}"
    );
    // Applying the patch gives back the rendered template exactly.
    let fixed = apply(&captured("hellomint-Token-unbounded.sol"), &patch);
    assert!(fixed.contains("        if (quantity > remaining) revert SoldOut(quantity, remaining);\n        uint256 expected"));
}

#[test]
fn a_source_that_already_has_the_check_gets_advice_but_no_patch() {
    let f = GateFinding {
        tool: FORGE_TEST_TOOL.into(),
        kind: FindingKind::FailingTest,
        id: "test/Token.t.sol:LemonDropsTest::test_mint_stops_at_the_cap()".into(),
        severity: None,
        location: None,
    };
    let whole = captured("hellomint-Token-unbounded.sol").replace(
        "uint256 remaining = MAX_SUPPLY - minted;\n",
        "uint256 remaining = MAX_SUPPLY - minted;\n        if (quantity > remaining) revert SoldOut(quantity, remaining);\n",
    );
    let p = propose_fix(&f, &move |_: &str| Some(whole.clone()));
    assert!(p.patch.is_none());
    assert!(p.advice.contains("SoldOut"));
}

#[test]
fn slither_and_aderyn_selfdestruct_findings_propose_removing_the_function() {
    let read = source_reader("src/Token.sol", "erc20-Token-selfdestruct.sol");
    for (tool, fx) in [
        (SLITHER_SCAN_TOOL, "slither-erc20-suicidal.sarif"),
        (ADERYN_SCAN_TOOL, "aderyn-erc20-selfdestruct.txt"),
    ] {
        let f = findings_from_report(tool, RunStatus::Completed, Some(&captured(fx)));
        let p = propose_fix(&f[0], &read);
        assert!(p.advice.contains("selfdestruct"), "{tool}: {}", p.advice);
        let patch = p.patch.unwrap_or_else(|| panic!("{tool}: no patch"));
        assert!(patch.contains("\n-    function shutdown() external {\n-        selfdestruct(payable(msg.sender));\n-    }\n"), "{patch}");
        let fixed = apply(&captured("erc20-Token-selfdestruct.sol"), &patch);
        assert!(!fixed.contains("selfdestruct"), "{fixed}");
        assert!(
            fixed.ends_with("        _mint(INITIAL_HOLDER, INITIAL_SUPPLY);\n    }\n}\n"),
            "{fixed}"
        );
    }
}

#[test]
fn the_reader_is_only_asked_for_plain_src_paths() {
    let asked = Arc::new(Mutex::new(Vec::<String>::new()));
    let a = asked.clone();
    let read = move |p: &str| {
        a.lock().expect("lock").push(p.to_string());
        None
    };
    for loc in [
        "../../etc/passwd:1",
        "/etc/passwd",
        "src/../x.sol",
        "lib/oz/Evil.sol:3",
        "src\\Token.sol",
    ] {
        let f = GateFinding {
            tool: SLITHER_SCAN_TOOL.into(),
            kind: FindingKind::ScanFinding,
            id: "0-0-suicidal".into(),
            severity: Some(Severity::High),
            location: Some(loc.into()),
        };
        let p = propose_fix(&f, &read);
        assert!(p.patch.is_none());
    }
    assert!(asked.lock().expect("lock").is_empty(), "{asked:?}");
    assert!(safe_src_path("src/Token.sol"));
    assert!(safe_src_path("src/sub/A.sol"));
    assert!(!safe_src_path("src/./A.sol"));
}

#[test]
fn unknown_rules_and_tests_get_honest_generic_advice() {
    let f = GateFinding {
        tool: ADERYN_SCAN_TOOL.into(),
        kind: FindingKind::ScanFinding,
        id: "some-new-detector".into(),
        severity: Some(Severity::High),
        location: Some("src/Token.sol".into()),
    };
    let p = propose_fix(&f, &|_: &str| None);
    assert!(p.advice.contains("some-new-detector") && p.advice.contains("do not suppress"));
    let t = GateFinding {
        tool: FORGE_TEST_TOOL.into(),
        kind: FindingKind::FailingTest,
        id: "test/X.t.sol:XTest::test_something()".into(),
        severity: None,
        location: None,
    };
    let p = propose_fix(&t, &|_: &str| None);
    assert!(
        p.advice.contains("test_something()")
            && p.advice.contains("do not edit or delete the test")
    );
}

// ------------------------------------------------------------------------------------------
// intent + refusal
// ------------------------------------------------------------------------------------------

#[test]
fn deploy_requests_are_recognized_and_negations_are_not() {
    for yes in [
        "deploy anyway",
        "Deploy it anyway, I accept the risk",
        "please deploy the contract",
        "No, deploy it now.",
        "ship it",
        "just push it live",
        "redeploy",
        "can you deploy?",
    ] {
        assert!(is_deploy_request(yes), "{yes}");
    }
    for no in [
        "don't deploy yet",
        "do not deploy it",
        "never deploy without the gate",
        "what does the deployment do?",
        "run slither again",
        "",
    ] {
        assert!(!is_deploy_request(no), "{no}");
    }
}

#[test]
fn the_refusal_declines_names_every_finding_and_carries_the_patch() {
    let mut findings = findings_from_report(
        SLITHER_SCAN_TOOL,
        RunStatus::Completed,
        Some(&captured("slither-erc20-suicidal.sarif")),
    );
    findings.extend(findings_from_report(
        ADERYN_SCAN_TOOL,
        RunStatus::Completed,
        Some(&captured("aderyn-erc20-selfdestruct.txt")),
    ));
    let read = source_reader("src/Token.sol", "erc20-Token-selfdestruct.sol");
    let fixes: Vec<FixProposal> = findings.iter().map(|f| propose_fix(f, &read)).collect();
    let text = refusal_text("/work/dapps/lemon/", &findings, &fixes);
    assert!(text.starts_with("I won't deploy this contract."), "{text}");
    assert!(text.contains("NOT READY for `lemon`"), "{text}");
    assert!(
        text.contains("Slither `0-0-suicidal` (High) at `src/Token.sol:19`"),
        "{text}"
    );
    assert!(
        text.contains("Aderyn `selfdestruct` (High) at `src/Token.sol`"),
        "{text}"
    );
    assert!(text.contains("```diff\n--- a/src/Token.sol"), "{text}");
    assert!(text.contains("No signature request was opened"), "{text}");
    assert!(!text.contains('\u{2014}'), "no em dashes in member prose");
}

// ------------------------------------------------------------------------------------------
// the loop's call-policy seam
// ------------------------------------------------------------------------------------------

struct Scripted(Mutex<Vec<AssistantTurn>>);
impl LlmClient for Scripted {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let mut g = self
            .0
            .lock()
            .map_err(|_| LlmError::Transport("lock".into()))?;
        if g.is_empty() {
            return Ok(AssistantTurn::text("done"));
        }
        Ok(g.remove(0))
    }
}

#[derive(Default)]
struct Recorder(Mutex<Vec<Event>>);
impl EventSink for Recorder {
    fn emit(&self, ev: Event) {
        if let Ok(mut g) = self.0.lock() {
            g.push(ev);
        }
    }
}

struct CountingHost(Mutex<Vec<String>>);
impl ToolHost for CountingHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        if let Ok(mut g) = self.0.lock() {
            g.push(call.name.clone());
        }
        ToolOutcome::Ok("ran".into())
    }
}

struct DeclineDeploy;
impl CallPolicy for DeclineDeploy {
    fn decline(&self, call: &ToolCall) -> Option<String> {
        (call.name == CONTRACT_DEPLOY_TOOL).then(|| "the deploy gate is NOT READY".to_string())
    }
}

fn core_spec(name: &str) -> ToolSpec {
    ToolSpec {
        name: name.into(),
        description: name.into(),
        parameters: serde_json::json!({"type": "object"}),
        host: HostKind::Core,
        annotations: ToolAnnotations::default(),
    }
}

#[test]
fn a_declined_call_is_announced_with_no_host_and_reaches_no_host() {
    let host = Arc::new(CountingHost(Mutex::new(Vec::new())));
    let tools = ToolRegistry::new(vec![core_spec("contract_deploy"), core_spec("chain_head")])
        .with_host(HostKind::Core, host.clone())
        .with_policy(Arc::new(DeclineDeploy));
    let llm = Scripted(Mutex::new(vec![
        AssistantTurn::tools(vec![
            ToolCall {
                id: "a".into(),
                name: "contract_deploy".into(),
                arguments: "{}".into(),
            },
            ToolCall {
                id: "b".into(),
                name: "chain_head".into(),
                arguments: "{}".into(),
            },
        ]),
        AssistantTurn::text("ok"),
    ]));
    let sink = Recorder::default();
    let cfg = LoopConfig {
        model: "m".into(),
        system_prompt: "s".into(),
        max_steps: 4,
        max_tool_calls_per_step: 4,
        max_tokens: 64,
    };
    let mut history = Vec::new();
    run_turn(
        &cfg,
        &llm,
        &tools,
        &sink,
        &StopFlag::default(),
        &mut history,
        "go",
    );
    // Only the undeclined call ran.
    assert_eq!(
        *host.0.lock().expect("lock"),
        vec!["chain_head".to_string()]
    );
    let evs = sink.0.lock().expect("lock");
    let deploy_call = evs.iter().find_map(|e| match e {
        Event::ToolCall { call, host, .. } if call.name == "contract_deploy" => Some(*host),
        _ => None,
    });
    assert_eq!(deploy_call, Some(None), "the declined call names no host");
    let deploy_result = evs.iter().find_map(|e| match e {
        Event::ToolResult {
            call_id,
            status,
            content,
            ..
        } if call_id == "a" => Some((status.to_string(), content.clone())),
        _ => None,
    });
    let (status, content) = deploy_result.expect("a result for the declined call");
    assert_eq!(status, "denied");
    assert!(content.contains("NOT READY"), "{content}");
}

/// Applies a one-hunk unified diff made by the guard (test helper).
fn apply(source: &str, patch: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mut it = patch.lines();
    let _ = it.next();
    let _ = it.next();
    let header = it.next().expect("hunk header");
    let old = header
        .trim_start_matches("@@ -")
        .split(' ')
        .next()
        .expect("old range");
    let (start, _) = old.split_once(',').expect("start,len");
    let start: usize = start.parse().expect("start");
    let mut out: Vec<String> = lines[..start.saturating_sub(1)]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut idx = start.saturating_sub(1);
    for l in it {
        if let Some(c) = l.strip_prefix(' ') {
            assert_eq!(lines[idx], c, "context mismatch");
            out.push(c.to_string());
            idx += 1;
        } else if let Some(r) = l.strip_prefix('-') {
            assert_eq!(lines[idx], r, "removed line mismatch");
            idx += 1;
        } else if let Some(a) = l.strip_prefix('+') {
            out.push(a.to_string());
        }
    }
    out.extend(lines[idx..].iter().map(|s| s.to_string()));
    out.join("\n") + "\n"
}
