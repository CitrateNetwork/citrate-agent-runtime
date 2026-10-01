//! HUP-S1.4 — interviewer + brief (US-1.2, D-10). Tracks are bundled `track.toml` data; the brief
//! is what Hermes shows (and the member edits) before it builds anything.

use citrate_agent_loop::interview::{bundled_tracks, suggest_track, Brief, Track};
use std::collections::BTreeMap;

fn track(id: &str) -> Track {
    bundled_tracks()
        .expect("bundled tracks parse")
        .into_iter()
        .find(|t| t.id == id)
        .unwrap_or_else(|| panic!("no bundled track {id}"))
}

#[test]
fn the_five_launch_tracks_are_bundled_and_each_asks_3_to_7_questions_with_defaults() {
    let tracks = bundled_tracks().expect("parse");
    let ids: Vec<&str> = tracks.iter().map(|t| t.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "creative",
            "code",
            "smart-contract",
            "project-management",
            "full-project"
        ],
        "D-10 launch tracks, in order"
    );
    for t in &tracks {
        t.validate().unwrap_or_else(|e| panic!("{}: {e}", t.id));
        assert!((3..=7).contains(&t.questions.len()), "{}: US-1.2 AC1", t.id);
        assert!(
            t.questions.iter().all(|q| !q.default.trim().is_empty()),
            "{}: every question has a default",
            t.id
        );
        assert!(!t.workflow.is_empty() && !t.persona.is_empty(), "{}", t.id);
    }
}

#[test]
fn validation_refuses_a_track_that_breaks_the_interview_contract() {
    let mut t = track("code");
    t.questions.truncate(2);
    assert!(t.validate().is_err(), "fewer than 3 questions");
    let mut t = track("code");
    let q = t.questions[0].clone();
    t.questions.push(q);
    assert!(t.validate().is_err(), "duplicate question id");
    let mut t = track("code");
    t.questions[1].default = " ".into();
    assert!(t.validate().is_err(), "blank default");
    let mut t = track("code");
    t.questions[0].choices = vec!["a".into(), "b".into()];
    assert!(t.validate().is_err(), "default not among its choices");
}

#[test]
fn just_use_defaults_goes_straight_to_a_complete_brief() {
    let t = track("full-project");
    let b = Brief::from_answers(&t, "an NFT project called Lemon Drops", &BTreeMap::new())
        .expect("brief");
    assert_eq!(b.track, "full-project");
    assert_eq!(b.workflow, "hello-mint");
    assert_eq!(
        b.constraints.len(),
        t.questions.len(),
        "every question answered by its default"
    );
    assert!(b.constraints.iter().all(|c| c.from_default));
    // US-6.1: the hello-mint brief names the D-4 gates
    for g in [
        "forge test",
        "Slither",
        "Aderyn",
        "Medusa",
        "anvil fork",
        "SignatureCeremony",
    ] {
        assert!(
            b.gates.iter().any(|x| x.contains(g)),
            "missing gate {g}: {:?}",
            b.gates
        );
    }
}

#[test]
fn answers_override_defaults_and_unknown_or_invalid_answers_are_refused() {
    let t = track("smart-contract");
    let first = t.questions[0].id.clone();
    let mut a = BTreeMap::new();
    a.insert(first.clone(), "ERC-1155".to_string());
    let b = Brief::from_answers(&t, "a game items contract", &a).expect("brief");
    let c = b
        .constraints
        .iter()
        .find(|c| c.id == first)
        .expect("answered");
    assert_eq!(c.answer, "ERC-1155");
    assert!(!c.from_default);

    let mut bad = BTreeMap::new();
    bad.insert("not-a-question".to_string(), "x".to_string());
    assert!(
        Brief::from_answers(&t, "g", &bad).is_err(),
        "unknown question id"
    );
    let mut bad = BTreeMap::new();
    bad.insert(first, "ERC-9999".to_string());
    assert!(
        Brief::from_answers(&t, "g", &bad).is_err(),
        "answer outside the question's choices"
    );
    assert!(
        Brief::from_answers(&t, "   ", &BTreeMap::new()).is_err(),
        "a brief needs a goal"
    );
}

#[test]
fn the_brief_is_editable_json_and_renders_to_markdown_with_every_section() {
    let t = track("full-project");
    let b = Brief::from_answers(&t, "Lemon Drops", &BTreeMap::new()).expect("brief");
    let mut edited: Brief =
        serde_json::from_value(serde_json::to_value(&b).expect("ser")).expect("de");
    edited.goal = "Lemon Drops, 500 supply".into();
    edited.validate_edit(&t).expect("an edited goal is fine");
    let md = edited.to_markdown();
    for section in [
        "# Brief",
        "Lemon Drops, 500 supply",
        "## Constraints",
        "## Persona",
        "## Skills",
        "## Workflow",
        "## Gates",
    ] {
        assert!(md.contains(section), "missing {section}:\n{md}");
    }
    // the member can edit wording, never drop a gate the track requires
    let mut weakened = b.clone();
    weakened.gates.retain(|g| !g.contains("Slither"));
    assert!(
        weakened.validate_edit(&t).is_err(),
        "gates are not editable away"
    );
    let mut retracked = b;
    retracked.workflow = "something-else".into();
    assert!(
        retracked.validate_edit(&t).is_err(),
        "workflow is fixed by the track"
    );
}

#[test]
fn the_brief_says_honestly_when_its_workflow_has_not_shipped_yet() {
    let t = track("full-project");
    let b = Brief::from_answers(&t, "Lemon Drops", &BTreeMap::new()).expect("brief");
    if !t.workflow_available {
        assert!(
            b.to_markdown().contains("not available yet"),
            "Rule 1: no pretending"
        );
    }
}

#[test]
fn suggest_track_routes_common_asks() {
    assert_eq!(
        suggest_track("help me make an NFT project called Lemon Drops"),
        Some("full-project")
    );
    assert_eq!(
        suggest_track("write an ERC-20 token contract with a cap"),
        Some("smart-contract")
    );
    assert_eq!(
        suggest_track("fix the failing test in my rust crate"),
        Some("code")
    );
    assert_eq!(
        suggest_track("plan next sprint and track the milestones"),
        Some("project-management")
    );
    assert_eq!(
        suggest_track("design a poster and a landing page hero image"),
        Some("creative")
    );
    assert_eq!(suggest_track("what's the weather"), None);
}
