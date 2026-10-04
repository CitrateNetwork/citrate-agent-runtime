//! HUP-S5.3 in the browser: the `decide()` System-1 slot picks the next step over snapshot refs.
//!
//! Each step, the page's ref-indexed snapshot becomes a fixed set of moves: `click:e3`,
//! `type:e5` (only into an editable field), `enter:e5` (only in an editable field that already
//! holds a value), and two outcomes that are always offered, `done` (the page shows the goal met)
//! and `blocked` (nothing offered moves the goal forward). `decide()` returns one of them or an
//! error, never a guess. When the move is `type` and the task has more than one value, a second
//! decision picks which value goes into the field.
//!
//! Two callers:
//! - the `browser_pick` tool ([`crate::tools`]): Hermes asks for a suggestion and then acts with
//!   `browser_act` itself, so every effect still goes through the member's approvals;
//! - [`run_task`], the multi-step runner the web subset is scored with (`web-subset-v2`). It acts
//!   directly and is a measuring harness, not a member-facing path.
//!
//! Patterns adapted (ideas, not code) from two openly licensed projects, with thanks:
//! - `ThinkFlowLab/system1-agents` (Apache-2.0), `s1a/browser/action_space.py`: one candidate per
//!   (operation, element); typing only into editable fields; Enter only in a field that holds a
//!   value; explicit DONE and BLOCKED outcomes; a control whose last two clicks changed nothing is
//!   no longer offered for clicking.
//! - `typesafe-ai/skills` (MIT), `skills/typesafe-ai/SKILL.md`: select instead of generate (the
//!   model picks among values the code found), always include a no-match outcome, keep observed
//!   facts apart from inferred ones, and check freshness before applying a result to a page that
//!   may have changed (the tool path binds an approved action to the page version).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use citrate_agent_loop::decide::{
    BackendPref, DecideError, DecideOption, DecideRequest, Decider, Decision, DecisionOrigin,
    DecisionPurpose, MAX_CONTEXT_CHARS, MAX_OPTIONS,
};
use serde::{Deserialize, Serialize};

use crate::service::{Action, BrowserService};
use crate::snapshot::{clean, Snapshot};

pub const DONE: &str = "done";
pub const BLOCKED: &str = "blocked";
/// A control is withheld from clicking after this many clicks in a row on it changed nothing.
pub const DEAD_CLICK_REPEATS: usize = 2;
/// Default step budget for one task.
pub const DEFAULT_MAX_STEPS: usize = 10;
/// Longest history shown to the model (most recent steps).
const HISTORY_SHOWN: usize = 8;

/// Roles a value can be typed into.
pub const EDITABLE_ROLES: &[&str] = &["textbox", "searchbox", "combobox", "spinbutton"];

/// One move over the current snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Move {
    Click(String),
    Type(String),
    Enter(String),
    Done,
    Blocked,
}

impl Move {
    /// The option id `decide()` sees.
    pub fn id(&self) -> String {
        match self {
            Move::Click(r) => format!("click:{r}"),
            Move::Type(r) => format!("type:{r}"),
            Move::Enter(r) => format!("enter:{r}"),
            Move::Done => DONE.to_string(),
            Move::Blocked => BLOCKED.to_string(),
        }
    }

    /// Parse an option id back into a move.
    pub fn parse(id: &str) -> Option<Move> {
        match id {
            DONE => return Some(Move::Done),
            BLOCKED => return Some(Move::Blocked),
            _ => {}
        }
        let (op, r) = id.split_once(':')?;
        let valid_ref =
            r.len() >= 2 && r.starts_with('e') && r[1..].chars().all(|c| c.is_ascii_digit());
        if !valid_ref {
            return None;
        }
        match op {
            "click" => Some(Move::Click(r.to_string())),
            "type" => Some(Move::Type(r.to_string())),
            "enter" => Some(Move::Enter(r.to_string())),
            _ => None,
        }
    }

    pub fn target(&self) -> Option<&str> {
        match self {
            Move::Click(r) | Move::Type(r) | Move::Enter(r) => Some(r),
            Move::Done | Move::Blocked => None,
        }
    }
}

/// One step a run took.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StepRecord {
    pub step: usize,
    /// The move id (`click:e3`, `done`, ...).
    pub chosen: String,
    /// `role "name"` of the target in that step's snapshot (page text: untrusted).
    pub target: String,
    /// The value typed, for a `type` move.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Whether the page (address or snapshot) changed after the move.
    pub page_changed: bool,
    pub latency_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Targets whose last [`DEAD_CLICK_REPEATS`] clicks in a row changed nothing.
pub fn dead_targets(history: &[StepRecord]) -> HashSet<String> {
    let clicks: Vec<&StepRecord> = history
        .iter()
        .filter(|s| s.chosen.starts_with("click:"))
        .collect();
    let mut dead = HashSet::new();
    let labels: HashSet<&str> = clicks.iter().map(|s| s.target.as_str()).collect();
    for label in labels {
        let recent: Vec<&&StepRecord> = clicks
            .iter()
            .filter(|s| s.target == label)
            .rev()
            .take(DEAD_CLICK_REPEATS)
            .collect();
        if recent.len() == DEAD_CLICK_REPEATS && recent.iter().all(|s| !s.page_changed) {
            dead.insert(label.to_string());
        }
    }
    dead
}

fn describe(role: &str, name: &str, value: &str) -> String {
    let mut s = format!("{role} \"{}\"", clean(name, 80));
    if !value.is_empty() && value != name {
        s.push_str(&format!(" holding \"{}\"", clean(value, 60)));
    }
    s
}

/// The moves offered over `snap`, as decide options: `done` and `blocked` first, then per
/// element (document order) its click, type and enter moves. Disabled elements get none; typing is
/// offered only when `can_type`. At most [`MAX_OPTIONS`] options.
pub fn moves(snap: &Snapshot, history: &[StepRecord], can_type: bool) -> Vec<DecideOption> {
    let dead = dead_targets(history);
    let mut out = vec![
        DecideOption {
            id: DONE.to_string(),
            label: "Done: the page already shows the goal met".to_string(),
        },
        DecideOption {
            id: BLOCKED.to_string(),
            label: "Blocked: none of the moves below gets closer to the goal".to_string(),
        },
    ];
    for e in &snap.refs {
        if e.disabled {
            continue;
        }
        let what = describe(&e.role, &e.name, &e.value);
        let editable = EDITABLE_ROLES.contains(&e.role.as_str());
        let mut push = |m: Move, label: String| {
            if out.len() < MAX_OPTIONS {
                out.push(DecideOption { id: m.id(), label });
            }
        };
        if editable {
            if can_type {
                push(
                    Move::Type(e.r#ref.clone()),
                    format!("Type into {what} [{}]", e.r#ref),
                );
            }
            if !e.value.trim().is_empty() {
                push(
                    Move::Enter(e.r#ref.clone()),
                    format!("Press Enter in {what} to submit it [{}]", e.r#ref),
                );
            }
        } else {
            let label = format!("{} \"{}\"", e.role, e.name);
            if !dead.contains(&label) {
                push(
                    Move::Click(e.r#ref.clone()),
                    format!("Click {what} [{}]", e.r#ref),
                );
            }
        }
    }
    out
}

fn history_text(history: &[StepRecord]) -> String {
    if history.is_empty() {
        return "No steps taken yet.".to_string();
    }
    let start = history.len().saturating_sub(HISTORY_SHOWN);
    history[start..]
        .iter()
        .map(|s| {
            let mut l = format!("step {}: {} {}", s.step, s.chosen, s.target);
            if let Some(v) = &s.value {
                l.push_str(&format!(" with \"{}\"", clean(v, 60)));
            }
            l.push_str(if s.page_changed {
                " (the page changed)"
            } else {
                " (nothing changed)"
            });
            if let Some(e) = &s.error {
                l.push_str(&format!(" failed: {}", clean(e, 80)));
            }
            l
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The decision request for the next move toward `goal` on this page.
pub fn next_move_request(
    goal: &str,
    snap: &Snapshot,
    url: &str,
    history: &[StepRecord],
    can_type: bool,
    origin: Option<DecisionOrigin>,
) -> DecideRequest {
    let question = format!(
        "Goal: {}\nWhich single move gets closer to the goal on this page? Choose done only if the page already shows the goal met.",
        clean(goal, 1500)
    );
    let mut context = format!(
        "Steps so far:\n{}\n\nCurrent page {}\n{}",
        history_text(history),
        clean(url, 300),
        snap.text
    );
    if context.chars().count() > MAX_CONTEXT_CHARS {
        context = context.chars().take(MAX_CONTEXT_CHARS).collect();
    }
    DecideRequest {
        purpose: DecisionPurpose::PickElement,
        question,
        options: moves(snap, history, can_type),
        context,
        origin,
    }
}

/// The decision request for which of `values` goes into the field `target`.
pub fn value_request(goal: &str, target: &str, values: &[String]) -> DecideRequest {
    DecideRequest {
        purpose: DecisionPurpose::Choose,
        question: format!(
            "Goal: {}\nWhich value should be typed into the field {}?",
            clean(goal, 1500),
            clean(target, 200)
        ),
        options: values
            .iter()
            .enumerate()
            .map(|(i, v)| DecideOption {
                id: format!("v{}", i + 1),
                label: format!("\"{}\"", clean(v, 400)),
            })
            .collect(),
        context: String::new(),
        origin: None,
    }
}

/// Something that answers decision requests: the sidecar's metered `decide()` service, or a
/// [`Decider`] directly.
pub trait Picker: Send + Sync {
    fn decide(&self, req: &DecideRequest) -> Result<Decision, DecideError>;
}

/// A [`Decider`] with a fixed backend preference.
pub struct DeciderPicker {
    pub decider: Arc<Decider>,
    pub pref: BackendPref,
}

impl Picker for DeciderPicker {
    fn decide(&self, req: &DecideRequest) -> Result<Decision, DecideError> {
        self.decider.decide(req, self.pref)
    }
}

/// What a page must show for a task to count as done. Both checks must hold when given.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessCheck {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_contains: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_contains: Option<String>,
}

impl SuccessCheck {
    pub fn holds(&self, url: &str, text: &str) -> bool {
        self.url_contains.as_deref().is_none_or(|u| url.contains(u))
            && self
                .text_contains
                .as_deref()
                .is_none_or(|t| text.contains(t))
    }
}

/// One multi-step task over a local fixture site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepTask {
    pub id: String,
    /// Path on the fixture server where the task starts (`/shop`).
    pub start: String,
    pub goal: String,
    /// Values the goal asks to enter, in the goal's words.
    #[serde(default)]
    pub values: Vec<String>,
    pub success: SuccessCheck,
    #[serde(default)]
    pub max_steps: Option<usize>,
}

/// A multi-step web subset: tasks plus the fixture pages they run on (path -> HTML).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSubset {
    pub suite: String,
    pub note: String,
    pub tasks: Vec<StepTask>,
    pub pages: std::collections::BTreeMap<String, String>,
}

impl WebSubset {
    pub fn parse(json: &str) -> Result<WebSubset, String> {
        serde_json::from_str(json).map_err(|e| format!("web subset: {e}"))
    }

    /// The page for a request path (the query string is ignored; pages read it themselves).
    pub fn page(&self, path: &str) -> Option<&str> {
        let p = path.split(['?', '#']).next().unwrap_or(path);
        self.pages.get(p).map(String::as_str)
    }
}

/// The result of one task run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskRun {
    pub task_id: String,
    /// The model said `done` and the page met the check at that moment.
    pub success: bool,
    pub declared_done: bool,
    /// The page met the check at some point (even if the model did not stop there).
    pub reached: bool,
    pub steps: Vec<StepRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The snapshots the model saw, one per step, as captured from the live browser.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub snapshots: Vec<String>,
}

/// Run `task` from `base` (a loopback fixture server) with `picker` choosing each move.
/// Every move acts directly on the page: this is the scoring harness, not a member-facing path.
pub fn run_task(
    svc: &BrowserService,
    picker: &dyn Picker,
    base: &str,
    task: &StepTask,
    capture: bool,
) -> TaskRun {
    let mut run = TaskRun {
        task_id: task.id.clone(),
        success: false,
        declared_done: false,
        reached: false,
        steps: Vec::new(),
        error: None,
        snapshots: Vec::new(),
    };
    let start = format!("{}{}", base.trim_end_matches('/'), task.start);
    if let Err(e) = svc.navigate(&start) {
        run.error = Some(format!("could not open the start page: {e}"));
        return run;
    }
    let max = task.max_steps.unwrap_or(DEFAULT_MAX_STEPS).max(1);
    let mut last_view: Option<(String, String)> = None;
    for step in 1..=max {
        let (page, snap) = match svc.snapshot() {
            Ok(x) => x,
            Err(e) => {
                run.error = Some(format!("snapshot failed: {e}"));
                break;
            }
        };
        let text = svc.page_text().unwrap_or_default();
        let view = (page.url.clone(), snap.text.clone());
        if let Some(prev) = run.steps.last_mut() {
            prev.page_changed = last_view.as_ref() != Some(&view);
        }
        last_view = Some(view);
        let met = task.success.holds(&page.url, &text);
        run.reached |= met;
        if capture {
            run.snapshots.push(snap.text.clone());
        }
        let origin = svc.decision_origin();
        let req = next_move_request(
            &task.goal,
            &snap,
            &page.url,
            &run.steps,
            !task.values.is_empty(),
            origin,
        );
        let started = Instant::now();
        let decision = picker.decide(&req);
        let mut latency_ms = started.elapsed().as_millis() as u64;
        let d = match decision {
            Ok(d) => d,
            Err(e) => {
                run.error = Some(format!("decide failed at step {step}: {}", e.kind()));
                break;
            }
        };
        let Some(mv) = Move::parse(&d.choice) else {
            run.error = Some(format!("decide chose an unknown move {}", d.choice));
            break;
        };
        let target = mv
            .target()
            .and_then(|r| snap.find(r))
            .map(|e| format!("{} \"{}\"", e.role, e.name))
            .unwrap_or_default();
        let mut rec = StepRecord {
            step,
            chosen: d.choice.clone(),
            target: target.clone(),
            value: None,
            page_changed: false,
            latency_ms,
            confidence: d.confidence,
            error: None,
        };
        let action = match &mv {
            Move::Done => {
                run.declared_done = true;
                run.success = met;
                run.steps.push(rec);
                return run;
            }
            Move::Blocked => {
                run.steps.push(rec);
                run.error = Some("the picker said it is blocked".to_string());
                return run;
            }
            Move::Click(_) => Action::Click,
            Move::Enter(_) => Action::Type {
                text: String::new(),
                clear: false,
                submit: true,
            },
            Move::Type(_) => {
                let value = if task.values.len() == 1 {
                    Ok(task.values[0].clone())
                } else {
                    let vr = value_request(&task.goal, &target, &task.values);
                    let t = Instant::now();
                    let out = picker.decide(&vr);
                    latency_ms += t.elapsed().as_millis() as u64;
                    out.map_err(|e| e.kind().to_string()).and_then(|vd| {
                        vd.choice
                            .strip_prefix('v')
                            .and_then(|n| n.parse::<usize>().ok())
                            .and_then(|n| task.values.get(n.wrapping_sub(1)))
                            .cloned()
                            .ok_or_else(|| "bad_answer".to_string())
                    })
                };
                match value {
                    Ok(v) => {
                        rec.value = Some(v.clone());
                        Action::Type {
                            text: v,
                            clear: true,
                            submit: false,
                        }
                    }
                    Err(kind) => {
                        run.error = Some(format!("value decision failed at step {step}: {kind}"));
                        rec.latency_ms = latency_ms;
                        run.steps.push(rec);
                        return run;
                    }
                }
            }
        };
        rec.latency_ms = latency_ms;
        let r = mv.target().unwrap_or_default().to_string();
        if let Err(e) = svc.act(&r, &action) {
            rec.error = Some(e.to_string());
        }
        run.steps.push(rec);
    }
    if let Ok((page, snap)) = svc.snapshot() {
        if let Some(prev) = run.steps.last_mut() {
            prev.page_changed = last_view.as_ref() != Some(&(page.url.clone(), snap.text.clone()));
        }
        let text = svc.page_text().unwrap_or_default();
        run.reached |= task.success.holds(&page.url, &text);
    }
    if run.error.is_none() && !run.declared_done {
        run.error = Some(format!("no done within {max} steps"));
    }
    run
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::RefEntry;

    fn entry(r: &str, role: &str, name: &str, value: &str, disabled: bool) -> RefEntry {
        RefEntry {
            r#ref: r.to_string(),
            role: role.to_string(),
            name: name.to_string(),
            backend_node_id: 1,
            disabled,
            value: value.to_string(),
        }
    }

    fn snap() -> Snapshot {
        Snapshot {
            text: "page".to_string(),
            refs: vec![
                entry("e1", "link", "Home", "", false),
                entry("e2", "searchbox", "Search", "", false),
                entry("e3", "textbox", "Email", "ada@example.org", false),
                entry("e4", "button", "Continue", "", false),
                entry("e5", "button", "Later", "", true),
            ],
            truncated: false,
        }
    }

    fn ids(o: &[DecideOption]) -> Vec<&str> {
        o.iter().map(|o| o.id.as_str()).collect()
    }

    #[test]
    fn moves_follow_the_element_kinds() {
        let o = moves(&snap(), &[], true);
        assert_eq!(
            ids(&o),
            vec![
                "done",
                "blocked",
                "click:e1",
                "type:e2",
                "type:e3",
                "enter:e3",
                "click:e4"
            ],
            "editable fields are typed into, Enter only where a value is held, disabled elements get nothing"
        );
        let no_values = moves(&snap(), &[], false);
        assert_eq!(
            ids(&no_values),
            vec!["done", "blocked", "click:e1", "enter:e3", "click:e4"]
        );
        assert!(o[5].label.contains("holding \"ada@example.org\""));
    }

    #[test]
    fn a_control_whose_clicks_changed_nothing_is_withheld() {
        let rec = |step, changed| StepRecord {
            step,
            chosen: "click:e4".into(),
            target: "button \"Continue\"".into(),
            value: None,
            page_changed: changed,
            latency_ms: 1,
            confidence: None,
            error: None,
        };
        assert!(
            dead_targets(&[rec(1, false)]).is_empty(),
            "one miss is not enough"
        );
        let dead = dead_targets(&[rec(1, false), rec(2, false)]);
        assert!(dead.contains("button \"Continue\""));
        assert!(!ids(&moves(&snap(), &[rec(1, false), rec(2, false)], true)).contains(&"click:e4"));
        assert!(
            dead_targets(&[rec(1, false), rec(2, true)]).is_empty(),
            "a click that moved the page keeps the control"
        );
        assert!(dead_targets(&[rec(1, false), rec(2, false), rec(3, true)]).is_empty());
    }

    #[test]
    fn move_ids_round_trip_and_garbage_is_refused() {
        for m in [
            Move::Click("e1".into()),
            Move::Type("e22".into()),
            Move::Enter("e3".into()),
            Move::Done,
            Move::Blocked,
        ] {
            assert_eq!(Move::parse(&m.id()), Some(m));
        }
        for bad in ["click:", "click:x1", "drag:e1", "e1", "click:e1x", "type:e"] {
            assert_eq!(Move::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_request_is_valid_bounded_and_fences_nothing_as_instructions() {
        let mut big = snap();
        big.text = "x".repeat(MAX_CONTEXT_CHARS * 2);
        for i in 0..200 {
            big.refs
                .push(entry(&format!("e{}", i + 10), "link", "More", "", false));
        }
        let req = next_move_request(
            "Open the docs",
            &big,
            "http://127.0.0.1:1/",
            &[],
            true,
            None,
        );
        assert!(citrate_agent_loop::decide::validate_request(&req).is_ok());
        assert_eq!(req.options.len(), MAX_OPTIONS);
        assert!(req.context.chars().count() <= MAX_CONTEXT_CHARS);
        assert_eq!(req.purpose, DecisionPurpose::PickElement);
        assert_eq!(
            req.options[0].id, DONE,
            "the no-match outcomes are always offered"
        );
    }

    #[test]
    fn values_are_picked_not_generated() {
        let vals = vec!["Ada".to_string(), "ada@example.org".to_string()];
        let req = value_request("Send a note", "textbox \"Email\"", &vals);
        assert_eq!(ids(&req.options), vec!["v1", "v2"]);
        assert!(citrate_agent_loop::decide::validate_request(&req).is_ok());
    }

    #[test]
    fn the_success_check_needs_every_given_part() {
        let c = SuccessCheck {
            url_contains: Some("/cart".into()),
            text_contains: Some("Size 10".into()),
        };
        assert!(c.holds("http://x/cart?a=1", "Your cart: Size 10"));
        assert!(!c.holds("http://x/cart", "Your cart"));
        assert!(!c.holds("http://x/shop", "Size 10"));
        assert!(SuccessCheck::default().holds("", ""));
    }
}
