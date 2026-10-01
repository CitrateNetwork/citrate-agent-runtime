//! HUP-S3.3 (US-3.3 AC2): five tracks, each mapped to a workflow family and an interview, with
//! every workflow judged by verifiers. One BDD scenario group per track (the Gherkin lives in
//! `PERSONAS.md`). A scripted model that satisfies the verifiers finishes the default workflow; a
//! model that only claims success does not.

use citrate_agent_loop::interview::{bundled_tracks, Brief, Track};
use citrate_agent_loop::personas::bundled_personas;
use citrate_agent_loop::verifiers_tooling::{
    verify_forge_test_output, verify_medusa_output, verify_sarif_output, SarifProfile, Severity,
    ToolchainEnvelope, ADERYN_SCAN_TOOL, FORGE_TEST_TOOL, MEDUSA_FUZZ_TOOL, SLITHER_SCAN_TOOL,
};
use citrate_agent_loop::workflows::{
    bundled_workflows, parse_workflows, workflow_views, workflows_for_track, Evidence,
    VerifierSpec, WorkflowSpec, KNOWN_TOOLS, WORKFLOWS_SOURCE,
};
use citrate_agent_loop::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

// ---- harness ---------------------------------------------------------------------------------

fn fixture(name: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/toolchain")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// What a passing run of each toolchain tool returns (a real report, judged by the real parser).
fn passing_output(tool: &str) -> String {
    let verdict = match tool {
        FORGE_TEST_TOOL => verify_forge_test_output(&fixture("forge-test-pass.json")),
        SLITHER_SCAN_TOOL => verify_sarif_output(
            &fixture("slither-info-only.sarif"),
            SarifProfile::Slither,
            Severity::High,
        ),
        ADERYN_SCAN_TOOL => verify_sarif_output(
            &fixture("aderyn-lows-only.sarif"),
            SarifProfile::Aderyn,
            Severity::High,
        ),
        MEDUSA_FUZZ_TOOL => verify_medusa_output(&fixture("medusa-pass.txt")),
        _ => return "{}".into(),
    };
    ToolchainEnvelope::completed(tool, verdict).to_content()
}

struct Script(Mutex<Vec<AssistantTurn>>);
impl LlmClient for Script {
    fn complete(&self, _r: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let mut t = self.0.lock().unwrap();
        Ok(if t.is_empty() {
            AssistantTurn::text("done")
        } else {
            t.remove(0)
        })
    }
}

/// Answers every tool with its passing output (JSON tools get the value their verifier expects).
struct Host(BTreeMap<String, String>);
impl ToolHost for Host {
    fn execute(&self, c: &ToolCall) -> ToolOutcome {
        ToolOutcome::Ok(self.0.get(&c.name).cloned().unwrap_or_else(|| "{}".into()))
    }
}
struct Sink;
impl EventSink for Sink {
    fn emit(&self, _e: Event) {}
}

fn registry(wf: &WorkflowSpec) -> ToolRegistry {
    let mut outputs = BTreeMap::new();
    let mut names = BTreeSet::new();
    for st in &wf.steps {
        for v in &st.verifiers {
            match v {
                VerifierSpec::JsonFieldEquals {
                    tool,
                    pointer,
                    value,
                } => {
                    let mut obj = serde_json::json!({});
                    if let Some(key) = pointer.strip_prefix('/') {
                        obj[key] = value.clone();
                    }
                    outputs.insert(tool.clone(), obj.to_string());
                    names.insert(tool.clone());
                }
                other => {
                    if let Some(t) = other.tool() {
                        outputs
                            .entry(t.to_string())
                            .or_insert_with(|| passing_output(t));
                        names.insert(t.to_string());
                    }
                }
            }
        }
    }
    let specs = names
        .iter()
        .map(|n| ToolSpec {
            name: n.clone(),
            description: n.clone(),
            parameters: serde_json::json!({"type":"object"}),
            host: HostKind::Core,
            annotations: ToolAnnotations {
                effect: Some(Effect::None),
                trust: Some(Trust::Trusted),
                ..Default::default()
            },
        })
        .collect();
    ToolRegistry::new(specs).with_host(HostKind::Core, Arc::new(Host(outputs)))
}

/// The turns of a model that does exactly what each step's verifiers ask for.
fn satisfying_turns(wf: &WorkflowSpec) -> Vec<AssistantTurn> {
    let mut turns = Vec::new();
    for (i, st) in wf.steps.iter().enumerate() {
        let calls: Vec<ToolCall> = st
            .verifiers
            .iter()
            .filter(|v| v.requires_call())
            .filter_map(|v| v.tool())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .enumerate()
            .map(|(j, t)| ToolCall {
                id: format!("c{i}-{j}"),
                name: t.to_string(),
                arguments: r#"{"project":"/p"}"#.into(),
            })
            .collect();
        if !calls.is_empty() {
            turns.push(AssistantTurn::tools(calls));
        }
        let mut answer = format!("Step {} finished.", st.id);
        for v in &st.verifiers {
            if let VerifierSpec::AnswerContains { text } = v {
                answer.push('\n');
                answer.push_str(text);
            }
        }
        turns.push(AssistantTurn::text(answer));
    }
    turns
}

fn cfg() -> LoopConfig {
    LoopConfig {
        model: "m".into(),
        system_prompt: "s".into(),
        max_steps: 4,
        max_tool_calls_per_step: 8,
        max_tokens: 256,
    }
}

fn run(wf: &WorkflowSpec, turns: Vec<AssistantTurn>) -> WorkflowOutcome {
    let built = wf.build().unwrap_or_else(|e| panic!("{}: {e}", wf.id));
    let mut h = vec![];
    run_workflow(
        &cfg(),
        &TurnOptions::default(),
        &Script(Mutex::new(turns)),
        &registry(wf),
        &Sink,
        &StopFlag::default(),
        &mut h,
        &built,
    )
}

fn track(id: &str) -> Track {
    bundled_tracks()
        .expect("tracks")
        .into_iter()
        .find(|t| t.id == id)
        .unwrap_or_else(|| panic!("no track {id}"))
}

fn default_workflow(track_id: &str) -> WorkflowSpec {
    let t = track(track_id);
    bundled_workflows()
        .expect("workflows")
        .into_iter()
        .find(|w| w.id == t.workflow)
        .unwrap_or_else(|| panic!("track {track_id}: workflow {} in the catalog", t.workflow))
}

/// Given a persona on its track, when the member takes the defaults, then the brief names the
/// track's workflow and that workflow finishes only when its verifiers pass.
fn scenario(track_id: &str) {
    let t = track(track_id);
    let brief = Brief::from_answers(&t, "make the thing", &BTreeMap::new()).expect("brief");
    assert_eq!(brief.workflow, t.workflow);
    let wf = default_workflow(track_id);
    assert_eq!(wf.track, track_id);
    // A model that satisfies every verifier finishes the workflow.
    match run(&wf, satisfying_turns(&wf)) {
        WorkflowOutcome::Succeeded { answers } => assert_eq!(answers.len(), wf.steps.len()),
        other => panic!("{track_id}: a satisfying run must succeed: {other:?}"),
    }
    // A model that only says "done" never does.
    let claims: Vec<AssistantTurn> = (0..32)
        .map(|_| AssistantTurn::text("All done, everything passed."))
        .collect();
    assert!(
        matches!(run(&wf, claims), WorkflowOutcome::Failed { .. }),
        "{track_id}: a claim of success is not success"
    );
}

// ---- catalog ---------------------------------------------------------------------------------

#[test]
fn every_track_maps_to_a_workflow_family_whose_first_member_is_its_default() {
    let tracks = bundled_tracks().expect("tracks");
    assert_eq!(tracks.len(), 5, "US-3.3 AC2: five tracks");
    for t in &tracks {
        let fam = workflows_for_track(&t.id).expect("catalog");
        assert!(fam.len() >= 2, "{}: a family, not a single workflow", t.id);
        assert_eq!(
            fam[0].id, t.workflow,
            "{}: the default workflow leads",
            t.id
        );
        assert!(fam.iter().all(|w| w.track == t.id));
    }
}

#[test]
fn every_workflow_builds_into_a_verifier_judged_workflow() {
    for w in bundled_workflows().expect("catalog") {
        let built = w.build().unwrap_or_else(|e| panic!("{}: {e}", w.id));
        assert_eq!(built.steps.len(), w.steps.len());
        assert!(built.steps.iter().all(|s| !s.verifiers.is_empty()));
    }
}

#[test]
fn workflow_ids_are_unique_and_reference_only_known_tools() {
    let all = bundled_workflows().expect("catalog");
    let ids: BTreeSet<&str> = all.iter().map(|w| w.id.as_str()).collect();
    assert_eq!(ids.len(), all.len());
    for w in &all {
        for t in w.tools() {
            assert!(
                KNOWN_TOOLS.contains(&t.as_str()),
                "{}: unknown tool {t}",
                w.id
            );
        }
    }
}

#[test]
fn contract_workflows_are_backed_by_the_toolchain_reports() {
    for id in ["contract-build", "hello-mint"] {
        let w = bundled_workflows()
            .expect("catalog")
            .into_iter()
            .find(|w| w.id == id)
            .expect(id);
        assert_eq!(w.evidence(), Evidence::ToolReport, "{id}");
        let tools = w.tools();
        for t in [
            FORGE_TEST_TOOL,
            SLITHER_SCAN_TOOL,
            ADERYN_SCAN_TOOL,
            MEDUSA_FUZZ_TOOL,
        ] {
            assert!(tools.contains(t), "{id} runs {t}");
        }
        // Nothing in these workflows deploys: a deploy is the member's ceremony, after the gate.
        assert!(w.steps.iter().all(|s| s.verifiers.iter().any(|v| matches!(
            v,
            VerifierSpec::ToolNotCalled { tool } if tool == "contract_deploy"
        ))));
    }
}

#[test]
fn answer_shape_workflows_say_so() {
    let w = default_workflow("creative");
    assert_eq!(w.evidence(), Evidence::AnswerShape);
    let j = serde_json::to_value(workflow_views().expect("views")).expect("json");
    let first = &j[0];
    assert!(first.get("evidence").is_some(), "{first}");
    assert!(first.get("verifier_names").is_some(), "{first}");
}

#[test]
fn a_workflow_file_with_a_broken_entry_is_refused() {
    let bad_track = WORKFLOWS_SOURCE.replacen("track = \"creative\"", "track = \"nope\"", 1);
    assert!(parse_workflows(&bad_track).is_err(), "unknown track");
    let bad_threshold =
        WORKFLOWS_SOURCE.replacen("threshold = \"high\"", "threshold = \"loud\"", 1);
    assert!(parse_workflows(&bad_threshold).is_err(), "unknown severity");
    let bad_tool = WORKFLOWS_SOURCE.replacen(
        "tool = \"contract_deploy\"",
        "tool = \"contract_deploy_typo\"",
        1,
    );
    assert!(parse_workflows(&bad_tool).is_err(), "unknown tool");
    let no_attempts = WORKFLOWS_SOURCE.replacen("max_attempts = 2", "max_attempts = 0", 1);
    assert!(parse_workflows(&no_attempts).is_err(), "attempts 1..=5");
    let no_default =
        WORKFLOWS_SOURCE.replacen("id = \"creative-project\"", "id = \"creative-other\"", 1);
    assert!(
        parse_workflows(&no_default).is_err(),
        "the track's default workflow must lead its family"
    );
}

#[test]
fn every_persona_default_workflow_belongs_to_its_default_track() {
    for p in bundled_personas().expect("personas") {
        let fam = workflows_for_track(&p.default_track).expect("catalog");
        assert!(
            fam.iter().any(|w| w.id == p.default_workflow),
            "{}: {} is in the {} family",
            p.id,
            p.default_workflow,
            p.default_track
        );
    }
}

// ---- BDD: one scenario group per track ------------------------------------------------------

#[test]
fn track_creative_maker_offers_directions_and_waits_for_review() {
    scenario("creative");
    let w = default_workflow("creative");
    assert!(w.steps.iter().any(|s| s.verifiers.iter().any(|v| matches!(
        v,
        VerifierSpec::AnswerContains { text } if text.contains("Review before publishing")
    ))));
}

#[test]
fn track_code_builder_states_the_test_first() {
    scenario("code");
}

#[test]
fn track_smart_contract_is_gated_by_forge_slither_aderyn_and_medusa() {
    scenario("smart-contract");
}

#[test]
fn track_smart_contract_a_high_slither_finding_fails_the_workflow() {
    let wf = default_workflow("smart-contract");
    let mut reg_outputs = BTreeMap::new();
    for t in wf.tools() {
        reg_outputs.insert(t.clone(), passing_output(&t));
    }
    reg_outputs.insert(
        SLITHER_SCAN_TOOL.to_string(),
        ToolchainEnvelope::completed(
            SLITHER_SCAN_TOOL,
            verify_sarif_output(
                &fixture("slither-high.sarif"),
                SarifProfile::Slither,
                Severity::High,
            ),
        )
        .to_content(),
    );
    let built = wf.build().expect("build");
    let base = registry(&wf);
    let reg = ToolRegistry::new(base.specs().to_vec())
        .with_host(HostKind::Core, Arc::new(Host(reg_outputs)));
    let mut h = vec![];
    let out = run_workflow(
        &cfg(),
        &TurnOptions::default(),
        &Script(Mutex::new(
            (0..3).flat_map(|_| satisfying_turns(&wf)).collect(),
        )),
        &reg,
        &Sink,
        &StopFlag::default(),
        &mut h,
        &built,
    );
    match out {
        WorkflowOutcome::Failed { reason, .. } => {
            assert!(reason.contains("slither_scan"), "{reason}")
        }
        other => panic!("a High finding must fail the gate: {other:?}"),
    }
}

#[test]
fn track_project_management_steward_plans_before_writing() {
    scenario("project-management");
    let w = default_workflow("project-management");
    assert!(w.steps.iter().all(|s| s.verifiers.iter().any(|v| matches!(
        v,
        VerifierSpec::ToolNotCalled { tool } if tool == "journal_append"
    ))));
}

#[test]
fn track_full_project_hello_mint_ends_at_the_ceremony_not_a_deploy() {
    scenario("full-project");
    let w = default_workflow("full-project");
    let last = w.steps.last().expect("steps");
    assert!(last.verifiers.iter().any(|v| matches!(
        v,
        VerifierSpec::AnswerContains { text } if text.contains("SignatureCeremony")
    )));
}

#[test]
fn every_secondary_workflow_also_finishes_on_a_satisfying_run() {
    for w in bundled_workflows().expect("catalog") {
        match run(&w, satisfying_turns(&w)) {
            WorkflowOutcome::Succeeded { .. } => {}
            other => panic!("{}: {other:?}", w.id),
        }
    }
}
