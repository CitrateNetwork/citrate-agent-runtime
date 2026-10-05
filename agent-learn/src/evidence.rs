//! Evidence: the only way to obtain a [`VerifiedRun`] is to run a workflow through
//! [`run_verified_workflow`] and have every verifier of every step pass.
//!
//! The recorder sits between the workflow and the caller's event sink, keeps the verifier
//! verdicts as they are emitted, and forwards every event unchanged. When the workflow reports
//! success, the recorded verdicts are cross-checked against the workflow definition (each step's
//! final judged attempt must carry one passing verdict per verifier, in order). The model's
//! answers are kept for display only and are never evidence.

use std::sync::Mutex;

use citrate_agent_loop::{
    run_workflow_reviewed, Event, EventSink, LlmClient, LoopConfig, Message, Role, SelfReviewer,
    StopFlag, ToolRegistry, TurnOptions, Workflow, WorkflowOutcome,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One verifier verdict, as emitted by the workflow runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierVerdict {
    pub step: String,
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Where the run happened and a digest of what the workflow appended to the transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrajectoryRef {
    pub session_id: String,
    pub workflow_id: String,
    /// How many messages the workflow appended.
    pub messages: usize,
    /// [`trajectory_digest`] of those messages (hex SHA-256).
    pub sha256: String,
}

/// Why a run is learnable: the verdicts that passed and the trajectory they judged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub workflow_id: String,
    /// Step ids, in order.
    pub steps: Vec<String>,
    /// The verdicts of each step's final (passing) attempt, in step order.
    pub verdicts: Vec<VerifierVerdict>,
    /// How many attempts were judged by verifiers across all steps (failed ones included).
    pub attempts: u32,
    pub trajectory: TrajectoryRef,
}

/// A workflow run whose verifiers all passed. It has no public constructor and does not
/// deserialize: [`run_verified_workflow`] is the only way to get one.
#[derive(Debug, Clone)]
pub struct VerifiedRun {
    evidence: Evidence,
    answers: Vec<String>,
}

impl VerifiedRun {
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }
    /// The model's final answers per step. Shown to the member; never used as evidence.
    pub fn answers(&self) -> &[String] {
        &self.answers
    }
}

/// Why a run is not learnable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unverified {
    /// A step ran out of attempts without passing its verifiers.
    Failed { step: String, reason: String },
    /// The run was stopped.
    Stopped,
    /// The runner reported success but the recorded verdicts do not show it.
    EvidenceMismatch(String),
}

impl std::fmt::Display for Unverified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unverified::Failed { step, reason } => {
                write!(f, "step {step} did not pass its verifiers: {reason}")
            }
            Unverified::Stopped => write!(f, "the workflow was stopped"),
            Unverified::EvidenceMismatch(m) => write!(f, "evidence mismatch: {m}"),
        }
    }
}

impl std::error::Error for Unverified {}

/// Hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

const TRAJECTORY_DOMAIN: &[u8] = b"citrate.learn.trajectory.v1\n";

fn frame(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

/// A digest of a transcript slice: every field of every message, length-framed, so no two
/// different slices share an encoding.
pub fn trajectory_digest(messages: &[Message]) -> String {
    let mut h = Sha256::new();
    h.update(TRAJECTORY_DOMAIN);
    h.update((messages.len() as u64).to_be_bytes());
    for m in messages {
        let role: &[u8] = match m.role {
            Role::System => b"system",
            Role::User => b"user",
            Role::Assistant => b"assistant",
            Role::Tool => b"tool",
        };
        frame(&mut h, role);
        frame(&mut h, m.content.as_bytes());
        h.update((m.tool_calls.len() as u64).to_be_bytes());
        for c in &m.tool_calls {
            frame(&mut h, c.id.as_bytes());
            frame(&mut h, c.name.as_bytes());
            frame(&mut h, c.arguments.as_bytes());
        }
        match &m.tool_call_id {
            Some(id) => {
                h.update([1u8]);
                frame(&mut h, id.as_bytes());
            }
            None => h.update([0u8]),
        }
    }
    hex::encode(h.finalize())
}

/// Forwards every event to the caller's sink and keeps the verifier verdicts.
struct Recorder<'a> {
    inner: &'a dyn EventSink,
    verdicts: Mutex<Vec<VerifierVerdict>>,
}

impl EventSink for Recorder<'_> {
    fn emit(&self, ev: Event) {
        if let Event::Verifier {
            step,
            name,
            passed,
            detail,
        } = &ev
        {
            // A poisoned lock means another thread panicked mid-push; keep what is there.
            let mut v = match self.verdicts.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            v.push(VerifierVerdict {
                step: step.clone(),
                name: name.clone(),
                passed: *passed,
                detail: detail.clone(),
            });
        }
        self.inner.emit(ev);
    }
}

/// Check the recorded verdicts against the workflow: per step, the verdicts come in judged
/// attempts of exactly `verifiers.len()`, and the last attempt passed every verifier, in order.
fn check(wf: &Workflow, all: &[VerifierVerdict]) -> Result<(Vec<VerifierVerdict>, u32), String> {
    let mut finals = Vec::new();
    let mut attempts = 0u32;
    for st in &wf.steps {
        let names: Vec<String> = st.verifiers.iter().map(|v| v.name()).collect();
        let mine: Vec<&VerifierVerdict> = all.iter().filter(|v| v.step == st.id).collect();
        let n = names.len();
        if n == 0 || mine.is_empty() || !mine.len().is_multiple_of(n) {
            return Err(format!(
                "step {} has {} verdicts for {} verifiers",
                st.id,
                mine.len(),
                n
            ));
        }
        attempts = attempts.saturating_add(u32::try_from(mine.len() / n).unwrap_or(u32::MAX));
        let last = &mine[mine.len() - n..];
        for (v, want) in last.iter().zip(names.iter()) {
            if &v.name != want {
                return Err(format!(
                    "step {}: expected a verdict from {want:?}, found {:?}",
                    st.id, v.name
                ));
            }
            if !v.passed {
                return Err(format!("step {}: {} did not pass", st.id, v.name));
            }
        }
        finals.extend(last.iter().map(|v| (*v).clone()));
    }
    if all.iter().any(|v| !wf.steps.iter().any(|s| s.id == v.step)) {
        return Err("a verdict names a step that is not in the workflow".into());
    }
    Ok((finals, attempts))
}

/// Run `wf` exactly like [`citrate_agent_loop::run_workflow`] and, only if every verifier of
/// every step passed, return the run with its evidence.
#[allow(clippy::too_many_arguments)]
pub fn run_verified_workflow(
    session_id: &str,
    cfg: &LoopConfig,
    opts: &TurnOptions,
    llm: &dyn LlmClient,
    tools: &ToolRegistry,
    sink: &dyn EventSink,
    stop: &StopFlag,
    history: &mut Vec<Message>,
    wf: &Workflow,
) -> Result<VerifiedRun, Unverified> {
    run_verified_workflow_reviewed(
        session_id, cfg, opts, llm, tools, sink, stop, history, wf, None,
    )
}

/// [`run_verified_workflow`] with the model's self-review of every attempt recorded as an
/// opinion (US-1.3 AC2; [`citrate_agent_loop::run_workflow_reviewed`]). The opinions reach
/// `sink` and never the evidence: a run is verified only by its verdicts.
#[allow(clippy::too_many_arguments)]
pub fn run_verified_workflow_reviewed(
    session_id: &str,
    cfg: &LoopConfig,
    opts: &TurnOptions,
    llm: &dyn LlmClient,
    tools: &ToolRegistry,
    sink: &dyn EventSink,
    stop: &StopFlag,
    history: &mut Vec<Message>,
    wf: &Workflow,
    reviewer: Option<&dyn SelfReviewer>,
) -> Result<VerifiedRun, Unverified> {
    let start = history.len();
    let rec = Recorder {
        inner: sink,
        verdicts: Mutex::new(Vec::new()),
    };
    let outcome = run_workflow_reviewed(cfg, opts, llm, tools, &rec, stop, history, wf, reviewer);
    let answers = match outcome {
        WorkflowOutcome::Succeeded { answers } => answers,
        WorkflowOutcome::Failed { step, reason } => {
            return Err(Unverified::Failed { step, reason })
        }
        WorkflowOutcome::Stopped => return Err(Unverified::Stopped),
    };
    let all = match rec.verdicts.into_inner() {
        Ok(v) => v,
        Err(p) => p.into_inner(),
    };
    let (verdicts, attempts) = check(wf, &all).map_err(Unverified::EvidenceMismatch)?;
    let appended = history.get(start..).unwrap_or(&[]);
    Ok(VerifiedRun {
        evidence: Evidence {
            workflow_id: wf.id.clone(),
            steps: wf.steps.iter().map(|s| s.id.clone()).collect(),
            verdicts,
            attempts,
            trajectory: TrajectoryRef {
                session_id: session_id.to_string(),
                workflow_id: wf.id.clone(),
                messages: appended.len(),
                sha256: trajectory_digest(appended),
            },
        },
        answers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_agent_loop::{AnswerContains, Step, Verifier};
    use std::sync::Arc;

    fn v(step: &str, name: &str, passed: bool) -> VerifierVerdict {
        VerifierVerdict {
            step: step.into(),
            name: name.into(),
            passed,
            detail: String::new(),
        }
    }

    fn wf() -> Workflow {
        let a: Arc<dyn Verifier> = Arc::new(AnswerContains("x".into()));
        let b: Arc<dyn Verifier> = Arc::new(AnswerContains("y".into()));
        let (na, nb) = (a.name(), b.name());
        assert_ne!(na, nb);
        Workflow::new(
            "w",
            vec![Step {
                id: "s".into(),
                instruction: "i".into(),
                verifiers: vec![a, b],
                max_attempts: 3,
            }],
        )
        .unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn success_without_verdicts_is_a_mismatch() {
        assert!(check(&wf(), &[]).is_err());
    }

    #[test]
    fn a_failed_final_attempt_is_a_mismatch_even_if_an_earlier_one_passed() {
        let w = wf();
        let na = w.steps[0].verifiers[0].name();
        let nb = w.steps[0].verifiers[1].name();
        let all = vec![
            v("s", &na, true),
            v("s", &nb, true),
            v("s", &na, true),
            v("s", &nb, false),
        ];
        assert!(check(&w, &all).is_err());
        let ok = vec![
            v("s", &na, false),
            v("s", &nb, true),
            v("s", &na, true),
            v("s", &nb, true),
        ];
        let (finals, attempts) = check(&w, &ok).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(attempts, 2);
        assert_eq!(finals.len(), 2);
    }

    #[test]
    fn partial_attempts_wrong_names_and_foreign_steps_are_mismatches() {
        let w = wf();
        let na = w.steps[0].verifiers[0].name();
        let nb = w.steps[0].verifiers[1].name();
        assert!(check(&w, &[v("s", &na, true)]).is_err());
        assert!(check(&w, &[v("s", &nb, true), v("s", &na, true)]).is_err());
        assert!(check(
            &w,
            &[v("s", &na, true), v("s", &nb, true), v("other", &na, true)]
        )
        .is_err());
    }
}
