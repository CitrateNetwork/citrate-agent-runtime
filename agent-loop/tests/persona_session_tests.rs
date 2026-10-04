//! HUP-S3.3 + S3.7, the rest of US-3.3: a persona is more than prompt text.
//!
//! - The skill allowlist decides which skills a session offers (`SkillLibrary::restricted_to`).
//! - The tool emphasis decides which of the session's tools are always offered
//!   (`SessionPersona::pinned_tools`).
//! - Every track's workflow family can be run by a session route, so each track says so
//!   (`workflow_available = true`), and each workflow names the tools a pass needs.

use citrate_agent_loop::interview::bundled_tracks;
use citrate_agent_loop::personas::{
    bundled_personas, session_persona, session_persona_fragment, CustomPersona, SessionPersona, MAX_PINNED_EMPHASIS,
};
use citrate_agent_loop::skills::{SkillLibrary, SkillSource};
use citrate_agent_loop::verifiers_tooling::{
    ADERYN_SCAN_TOOL, FORGE_TEST_TOOL, MEDUSA_FUZZ_TOOL, SLITHER_SCAN_TOOL,
};
use citrate_agent_loop::workflows::{bundled_workflows, find_workflow, workflow_views};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A scratch directory removed on drop (no extra dev-dependency).
struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "persona-session-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn custom(skills: Vec<&str>, tools: Vec<&str>) -> CustomPersona {
    CustomPersona {
        id: "custom-night-owl".into(),
        name: "Night Owl".into(),
        summary: "Late-night pair programmer.".into(),
        voice: "Quiet and focused.".into(),
        tone: "Dry.".into(),
        style_rules: vec!["Lead with the answer.".into()],
        default_track: "code".into(),
        tool_emphasis: tools.into_iter().map(String::from).collect(),
        skills: skills.into_iter().map(String::from).collect(),
        tts_voice: None,
    }
}

fn write_skill(root: &Path, name: &str) {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("SKILL.md"),
        format!("---\nname: {name}\ndescription: The {name} skill\n---\n\nBody of {name}.\n"),
    )
    .unwrap();
}

// ---- session persona -------------------------------------------------------------------------

#[test]
fn a_shipped_persona_id_resolves_to_its_allowlist_and_tool_emphasis() {
    let auditor = bundled_personas()
        .unwrap()
        .into_iter()
        .find(|p| p.id == "auditor")
        .unwrap();
    let sp = session_persona(Some("auditor"), None)
        .unwrap()
        .expect("a persona");
    assert_eq!(sp.id, "auditor");
    assert_eq!(sp.skills, auditor.skills);
    assert_eq!(sp.tool_emphasis, auditor.tool_emphasis);
}

#[test]
fn no_persona_means_no_session_persona() {
    assert_eq!(session_persona(None, None).unwrap(), None);
}

#[test]
fn an_unknown_id_or_both_kinds_at_once_is_refused() {
    assert!(session_persona(Some("nobody"), None).is_err());
    assert!(session_persona(Some("custom-night-owl"), None).is_err());
    let c = custom(vec![], vec![]);
    assert!(
        session_persona(Some("auditor"), Some(&c)).is_err(),
        "one persona per session"
    );
}

#[test]
fn a_custom_persona_is_checked_and_brings_its_own_lists() {
    let c = custom(vec!["red-green"], vec!["forge_test"]);
    let sp = session_persona(None, Some(&c)).unwrap().expect("custom");
    assert_eq!(sp.id, "custom-night-owl");
    assert_eq!(sp.skills, vec!["red-green".to_string()]);
    assert_eq!(sp.tool_emphasis, vec!["forge_test".to_string()]);
    // A custom persona that fails its check never reaches a session.
    let mut bad = c.clone();
    bad.name = "Pith".into();
    let shipped_name_taken = bundled_personas().unwrap().iter().any(|p| p.name == "Pith");
    if shipped_name_taken {
        assert!(session_persona(None, Some(&bad)).is_err());
    }
    let mut bad_track = c;
    bad_track.default_track = "nope".into();
    assert!(session_persona(None, Some(&bad_track)).is_err());
}

#[test]
fn pinned_tools_are_the_emphasised_tools_the_session_offers_capped_and_in_order() {
    let sp = SessionPersona {
        id: "x".into(),
        skills: vec![],
        tool_emphasis: vec![
            "slither_scan".into(),
            "not_offered".into(),
            "forge_test".into(),
            "aderyn_scan".into(),
            "medusa_fuzz".into(),
            "journal_read".into(),
        ],
    };
    let offered: Vec<String> = [
        "journal_read",
        "forge_test",
        "slither_scan",
        "aderyn_scan",
        "medusa_fuzz",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let pinned = sp.pinned_tools(&offered);
    assert_eq!(
        pinned,
        vec!["slither_scan", "forge_test", "aderyn_scan", "medusa_fuzz"],
        "emphasis order, only offered tools, at most {MAX_PINNED_EMPHASIS}"
    );
    assert_eq!(pinned.len(), MAX_PINNED_EMPHASIS);
    // An emphasis never grants a tool the session does not already offer.
    assert!(!pinned.iter().any(|t| t == "not_offered"));
}

#[test]
fn an_empty_allowlist_does_not_restrict_skills() {
    let sp = SessionPersona {
        id: "x".into(),
        skills: vec![],
        tool_emphasis: vec![],
    };
    assert!(!sp.restricts_skills());
    let sp = SessionPersona {
        id: "x".into(),
        skills: vec!["red-green".into()],
        tool_emphasis: vec![],
    };
    assert!(sp.restricts_skills());
}

// ---- skill allowlist -------------------------------------------------------------------------

#[test]
fn a_library_restricted_to_an_allowlist_offers_only_those_skills() {
    let root = TempDir::new("allow");
    for n in ["red-green", "planset", "frontend-design"] {
        write_skill(root.path(), n);
    }
    let lib = SkillLibrary::load(&[SkillSource::new("bundled", root.path())]);
    assert_eq!(lib.len(), 3);
    let allow = vec![
        "planset".to_string(),
        "red-green".to_string(),
        "not-installed".to_string(),
    ];
    let (only, missing) = lib.restricted_to(&allow);
    let names: BTreeSet<&str> = only.names().into_iter().collect();
    assert_eq!(names, BTreeSet::from(["planset", "red-green"]));
    assert_eq!(missing, vec!["not-installed".to_string()]);
    assert!(
        only.get("frontend-design").is_none(),
        "outside the allowlist"
    );
    assert!(only.load_body("frontend-design").is_err());
    assert!(only.load_body("planset").is_ok());
    // The original library is untouched.
    assert_eq!(lib.len(), 3);
}

#[test]
fn shipped_allowlists_are_skill_slugs_without_repeats() {
    for p in bundled_personas().unwrap() {
        let set: BTreeSet<&String> = p.skills.iter().collect();
        assert_eq!(set.len(), p.skills.len(), "{}: repeated skill", p.id);
        assert!(!p.skills.is_empty(), "{}", p.id);
    }
}

// ---- track workflows are runnable ------------------------------------------------------------

#[test]
fn every_track_says_its_workflow_is_available_and_the_catalog_has_it() {
    let all = bundled_workflows().unwrap();
    for t in bundled_tracks().unwrap() {
        assert!(
            t.workflow_available,
            "{}: a session route runs track workflows",
            t.id
        );
        assert!(all.iter().any(|w| w.id == t.workflow), "{}", t.id);
    }
}

#[test]
fn find_workflow_returns_a_catalog_entry_by_id_only() {
    assert_eq!(
        find_workflow("status-note").unwrap().map(|w| w.track),
        Some("project-management".to_string())
    );
    assert!(find_workflow("nope").unwrap().is_none());
    assert!(find_workflow("").unwrap().is_none());
}

#[test]
fn required_tools_are_the_tools_a_pass_needs_and_never_a_guarded_tool() {
    let req = |id: &str| -> BTreeSet<String> {
        find_workflow(id)
            .unwrap()
            .unwrap_or_else(|| panic!("{id}"))
            .required_tools()
    };
    assert!(
        req("creative-project").is_empty(),
        "answer shape needs no tool"
    );
    assert_eq!(
        req("status-note"),
        BTreeSet::from(["journal_read".to_string()])
    );
    let contract = req("contract-build");
    for t in [
        FORGE_TEST_TOOL,
        SLITHER_SCAN_TOOL,
        ADERYN_SCAN_TOOL,
        MEDUSA_FUZZ_TOOL,
    ] {
        assert!(contract.contains(t), "{t}");
    }
    for w in bundled_workflows().unwrap() {
        assert!(
            !w.required_tools().contains("contract_deploy"),
            "{}: contract_deploy is only ever guarded",
            w.id
        );
    }
}

#[test]
fn workflow_views_carry_the_tools_a_pass_needs() {
    let views = workflow_views().unwrap();
    let hello = views.iter().find(|v| v.id == "hello-mint").unwrap();
    assert!(hello.needs_tools.contains(&FORGE_TEST_TOOL.to_string()));
    assert!(!hello.needs_tools.contains(&"contract_deploy".to_string()));
    let creative = views.iter().find(|v| v.id == "creative-project").unwrap();
    assert!(creative.needs_tools.is_empty());
}

/// L-23: the fragment a session gets is rendered from the checked persona, never sent by the app.
#[test]
fn the_session_fragment_is_rendered_from_the_checked_persona() {
    assert_eq!(session_persona_fragment(None, None), Ok(None));
    for p in bundled_personas().expect("personas") {
        assert_eq!(
            session_persona_fragment(Some(&p.id), None),
            Ok(Some(p.prompt_fragment())),
            "{}",
            p.id
        );
    }
    let c = custom(vec![], vec![]);
    let view = c.check().expect("the fixture passes the persona checks");
    assert_eq!(
        session_persona_fragment(None, Some(&c)),
        Ok(Some(view.prompt_fragment))
    );
}

#[test]
fn a_session_fragment_is_refused_for_an_unknown_bad_or_doubled_persona() {
    assert!(session_persona_fragment(Some("no-such-persona"), None).is_err());
    let c = custom(vec![], vec![]);
    let id = bundled_personas().expect("personas")[0].id.clone();
    assert!(session_persona_fragment(Some(&id), Some(&c)).is_err());
    let mut bad = custom(vec![], vec![]);
    bad.style_rules.clear();
    assert!(session_persona_fragment(None, Some(&bad)).is_err());
}
