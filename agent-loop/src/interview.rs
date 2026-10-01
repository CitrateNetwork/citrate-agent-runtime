//! HUP-S1.4 — interviewer + brief (US-1.2, planset D-10).
//!
//! A **track** is a user goal that selects a workflow family (`tracks/*.toml`, bundled). Each track
//! carries a short interview: 3–7 questions, every one with a default, so "just use defaults" is
//! always one step. The answers become a **brief**: goal, constraints, persona, skills, workflow
//! and the gates that will apply. Hermes shows the brief and the member edits it before anything
//! is built. Edits may change wording, answers, persona and skills; they can never drop a gate the
//! track requires or swap the workflow (a different workflow is a different track).
//!
//! Pure data + validation: no I/O. The sidecar serves it; app, CLI and MCP all read the same tracks.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Bundled launch tracks, in display order (D-10).
const BUNDLED: [(&str, &str); 5] = [
    ("creative", include_str!("../tracks/creative.toml")),
    ("code", include_str!("../tracks/code.toml")),
    (
        "smart-contract",
        include_str!("../tracks/smart-contract.toml"),
    ),
    (
        "project-management",
        include_str!("../tracks/project-management.toml"),
    ),
    ("full-project", include_str!("../tracks/full-project.toml")),
];

const MIN_QUESTIONS: usize = 3;
const MAX_QUESTIONS: usize = 7;
const MAX_GOAL_CHARS: usize = 2000;
const MAX_ANSWER_CHARS: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Question {
    pub id: String,
    pub ask: String,
    /// When non-empty, the answer must be one of these.
    #[serde(default)]
    pub choices: Vec<String>,
    pub default: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Track {
    pub id: String,
    pub title: String,
    pub summary: String,
    /// Persona role (Builder, Maker, …); the owner picks the shipped names (S3.7).
    pub persona: String,
    pub skills: Vec<String>,
    pub workflow: String,
    /// False until the workflow ships; the brief says so instead of pretending (Rule 1).
    pub workflow_available: bool,
    #[serde(default)]
    pub ships_in: Option<String>,
    pub gates: Vec<String>,
    pub questions: Vec<Question>,
}

impl Track {
    /// The interview contract: 3–7 questions, unique ids, a non-blank default that is one of the
    /// question's choices (when it has choices), and at least one gate.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() || self.workflow.is_empty() || self.persona.is_empty() {
            return Err("id, workflow and persona are required".into());
        }
        if !(MIN_QUESTIONS..=MAX_QUESTIONS).contains(&self.questions.len()) {
            return Err(format!(
                "{} questions; a track asks {MIN_QUESTIONS} to {MAX_QUESTIONS}",
                self.questions.len()
            ));
        }
        if self.gates.is_empty() {
            return Err("a track names at least one gate".into());
        }
        let mut seen = BTreeSet::new();
        for q in &self.questions {
            if q.id.is_empty() || !seen.insert(q.id.as_str()) {
                return Err(format!("question id {:?} is empty or repeated", q.id));
            }
            if q.default.trim().is_empty() {
                return Err(format!("question {:?} has no default", q.id));
            }
            if !q.choices.is_empty() && !q.choices.contains(&q.default) {
                return Err(format!(
                    "question {:?}: default is not one of its choices",
                    q.id
                ));
            }
        }
        Ok(())
    }

    fn question(&self, id: &str) -> Option<&Question> {
        self.questions.iter().find(|q| q.id == id)
    }
}

/// Parse and validate every bundled track.
pub fn bundled_tracks() -> Result<Vec<Track>, String> {
    BUNDLED
        .iter()
        .map(|(name, src)| {
            let t: Track = toml::from_str(src).map_err(|e| format!("track {name}: {e}"))?;
            if t.id != *name {
                return Err(format!("track file {name} declares id {:?}", t.id));
            }
            t.validate().map_err(|e| format!("track {name}: {e}"))?;
            Ok(t)
        })
        .collect()
}

/// A cheap, deterministic first guess at the track for an ask (the member can always pick another).
pub fn suggest_track(text: &str) -> Option<&'static str> {
    let lower = text.to_lowercase();
    let words: BTreeSet<&str> = lower
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .filter(|w| !w.is_empty())
        .collect();
    let any = |ks: &[&str]| ks.iter().any(|k| words.contains(k));
    if any(&["nft", "dapp", "mint", "minting"]) || lower.contains("full project") {
        Some("full-project")
    } else if any(&[
        "contract",
        "contracts",
        "solidity",
        "erc-20",
        "erc20",
        "erc-721",
        "erc721",
        "erc-1155",
        "token",
        "governor",
    ]) {
        Some("smart-contract")
    } else if any(&[
        "plan",
        "sprint",
        "milestone",
        "milestones",
        "roadmap",
        "backlog",
        "checklist",
    ]) {
        Some("project-management")
    } else if any(&[
        "code", "bug", "test", "tests", "crate", "refactor", "function", "compile", "repo",
    ]) {
        Some("code")
    } else if any(&[
        "design", "poster", "image", "copy", "landing", "post", "logo", "banner",
    ]) {
        Some("creative")
    } else {
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Constraint {
    pub id: String,
    pub ask: String,
    pub answer: String,
    pub from_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Brief {
    pub track: String,
    pub goal: String,
    pub constraints: Vec<Constraint>,
    pub persona: String,
    pub skills: Vec<String>,
    pub workflow: String,
    pub workflow_available: bool,
    #[serde(default)]
    pub ships_in: Option<String>,
    pub gates: Vec<String>,
}

fn check_answer(q: &Question, answer: &str) -> Result<(), String> {
    if answer.trim().is_empty() || answer.chars().count() > MAX_ANSWER_CHARS {
        return Err(format!(
            "answer to {:?} must be 1..={MAX_ANSWER_CHARS} characters",
            q.id
        ));
    }
    if !q.choices.is_empty() && !q.choices.iter().any(|c| c == answer) {
        return Err(format!(
            "answer to {:?} must be one of: {}",
            q.id,
            q.choices.join(", ")
        ));
    }
    Ok(())
}

fn check_goal(goal: &str) -> Result<(), String> {
    if goal.trim().is_empty() || goal.chars().count() > MAX_GOAL_CHARS {
        return Err(format!(
            "a brief needs a goal of 1..={MAX_GOAL_CHARS} characters"
        ));
    }
    Ok(())
}

impl Brief {
    /// Build the brief from the member's answers; any question left unanswered takes its default
    /// (so an empty map is "just use defaults"). Unknown ids and out-of-choice answers are refused.
    pub fn from_answers(
        track: &Track,
        goal: &str,
        answers: &BTreeMap<String, String>,
    ) -> Result<Brief, String> {
        check_goal(goal)?;
        for id in answers.keys() {
            if track.question(id).is_none() {
                return Err(format!("track {} has no question {id:?}", track.id));
            }
        }
        let mut constraints = Vec::with_capacity(track.questions.len());
        for q in &track.questions {
            let (answer, from_default) = match answers.get(&q.id) {
                Some(a) => (a.trim().to_string(), false),
                None => (q.default.clone(), true),
            };
            check_answer(q, &answer)?;
            constraints.push(Constraint {
                id: q.id.clone(),
                ask: q.ask.clone(),
                answer,
                from_default,
            });
        }
        Ok(Brief {
            track: track.id.clone(),
            goal: goal.trim().to_string(),
            constraints,
            persona: track.persona.clone(),
            skills: track.skills.clone(),
            workflow: track.workflow.clone(),
            workflow_available: track.workflow_available,
            ships_in: track.ships_in.clone(),
            gates: track.gates.clone(),
        })
    }

    /// Check a member-edited brief against its track: same track and workflow, every required gate
    /// still present (extra gates are welcome), answers valid, goal and persona non-empty.
    pub fn validate_edit(&self, track: &Track) -> Result<(), String> {
        if self.track != track.id {
            return Err(format!(
                "brief is for track {:?}, not {:?}",
                self.track, track.id
            ));
        }
        if self.workflow != track.workflow {
            return Err("the workflow is fixed by the track; pick another track instead".into());
        }
        if self.workflow_available != track.workflow_available || self.ships_in != track.ships_in {
            return Err("workflow availability comes from the track, not the brief".into());
        }
        check_goal(&self.goal)?;
        if self.persona.trim().is_empty() {
            return Err("a brief names a persona".into());
        }
        for g in &track.gates {
            if !self.gates.contains(g) {
                return Err(format!("required gate removed: {g}"));
            }
        }
        let mut seen = BTreeSet::new();
        for c in &self.constraints {
            let q = track
                .question(&c.id)
                .ok_or_else(|| format!("track {} has no question {:?}", track.id, c.id))?;
            if !seen.insert(c.id.as_str()) {
                return Err(format!("question {:?} answered twice", c.id));
            }
            check_answer(q, &c.answer)?;
        }
        Ok(())
    }

    /// The brief as the member reads it (chat card, CLI, journal).
    pub fn to_markdown(&self) -> String {
        let mut s = format!("# Brief\n\n**Goal:** {}\n\n## Constraints\n\n", self.goal);
        for c in &self.constraints {
            s.push_str(&format!(
                "- {} **{}**{}\n",
                c.ask,
                c.answer,
                if c.from_default { " (default)" } else { "" }
            ));
        }
        s.push_str(&format!(
            "\n## Persona\n\n{}\n\n## Skills\n\n",
            self.persona
        ));
        if self.skills.is_empty() {
            s.push_str("- none\n");
        }
        for k in &self.skills {
            s.push_str(&format!("- {k}\n"));
        }
        s.push_str(&format!("\n## Workflow\n\n`{}`", self.workflow));
        if !self.workflow_available {
            s.push_str(&format!(
                ": not available yet{}. Nothing is built from this brief until the workflow ships.",
                self.ships_in
                    .as_deref()
                    .map(|v| format!(" (ships in {v})"))
                    .unwrap_or_default()
            ));
        }
        s.push_str("\n\n## Gates\n\n");
        for g in &self.gates {
            s.push_str(&format!("- [ ] {g}\n"));
        }
        s
    }
}
