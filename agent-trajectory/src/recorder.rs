//! Turning a session's history plus its event stream into per-turn trajectories.

use crate::TrajectoryError;
use citrate_agent_loop::{Event, EventSink, Message, Role, TaintState};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, MutexGuard};

/// One verifier's verdict on a turn (the failure detail is not kept).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierVerdict {
    pub name: String,
    pub passed: bool,
}

/// Whether a turn may enter a training set on verification grounds alone (taint is a separate,
/// policy-level check in the exporter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Eligibility {
    /// Answered, judged by at least one verifier, every verifier passed.
    Verified,
    /// No verifier judged the turn.
    Unverified,
    /// At least one verifier failed.
    VerifierFailed,
    /// The turn did not end in an answer (stopped, step limit, failed).
    NotAnswered,
}

/// One loop turn: the messages it added to the history (its user prompt first) and how it was
/// judged. The system prompt is not part of a trajectory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnTrajectory {
    pub session_id: String,
    pub model: String,
    pub workflow: Option<String>,
    /// The workflow step the verifiers judged, when there was one.
    pub step: Option<String>,
    /// The loop's `done` label (`answered`, `stopped`, `step_limit`, `failed`).
    pub outcome: String,
    pub messages: Vec<Message>,
    pub verifiers: Vec<VerifierVerdict>,
    /// The session read untrusted content at some point (before, during or after this turn).
    pub session_tainted: bool,
}

impl TurnTrajectory {
    pub fn eligibility(&self) -> Eligibility {
        if self.outcome != "answered" {
            Eligibility::NotAnswered
        } else if self.verifiers.is_empty() {
            Eligibility::Unverified
        } else if self.verifiers.iter().all(|v| v.passed) {
            Eligibility::Verified
        } else {
            Eligibility::VerifierFailed
        }
    }
}

#[derive(Debug, Clone, Default)]
struct TurnMeta {
    outcome: String,
    step: Option<String>,
    verifiers: Vec<VerifierVerdict>,
}

#[derive(Default)]
struct State {
    open: Option<TurnMeta>,
    done: Vec<TurnMeta>,
    tainted: bool,
}

/// An [`EventSink`] adapter that remembers, per loop turn, how it ended and what the verifiers
/// said, and whether the session was ever tainted. It forwards every event unchanged.
///
/// Attach it before the first turn you want to export and pass the history *from that point* to
/// [`TrajectoryRecorder::trajectories`]: each loop turn appends exactly one user message and
/// emits exactly one `done`, which is how messages and verdicts are lined up.
pub struct TrajectoryRecorder {
    session_id: String,
    model: String,
    workflow: Option<String>,
    taint: TaintState,
    inner: Option<Arc<dyn EventSink>>,
    state: Mutex<State>,
}

impl TrajectoryRecorder {
    /// `taint` is the session's shared taint state. A session already tainted when the recorder
    /// is attached stays tainted for export purposes even if a member clears it later.
    pub fn new(session_id: impl Into<String>, model: impl Into<String>, taint: TaintState) -> Self {
        let tainted = taint.is_tainted();
        TrajectoryRecorder {
            session_id: session_id.into(),
            model: model.into(),
            workflow: None,
            taint,
            inner: None,
            state: Mutex::new(State {
                tainted,
                ..State::default()
            }),
        }
    }

    /// Name the workflow these turns belong to (builder).
    pub fn with_workflow(mut self, id: impl Into<String>) -> Self {
        self.workflow = Some(id.into());
        self
    }

    /// Forward every event to `inner` (builder).
    pub fn forwarding_to(mut self, inner: Arc<dyn EventSink>) -> Self {
        self.inner = Some(inner);
        self
    }

    // A poisoned lock keeps its data; the taint flag only ever moves to true.
    fn lock(&self) -> MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Pair `history` (the messages appended since this recorder was attached) with the recorded
    /// turns. Refuses rather than guesses when they do not line up.
    pub fn trajectories(
        &self,
        history: &[Message],
    ) -> Result<Vec<TurnTrajectory>, TrajectoryError> {
        let st = self.lock();
        let mut segments: Vec<Vec<Message>> = Vec::new();
        for m in history {
            if m.role == Role::User {
                segments.push(vec![m.clone()]);
            } else if let Some(seg) = segments.last_mut() {
                seg.push(m.clone());
            } else {
                return Err(TrajectoryError::Misaligned {
                    turns: st.done.len(),
                    segments: 0,
                });
            }
        }
        if segments.len() != st.done.len() {
            return Err(TrajectoryError::Misaligned {
                turns: st.done.len(),
                segments: segments.len(),
            });
        }
        let tainted = st.tainted || self.taint.is_tainted();
        Ok(segments
            .into_iter()
            .zip(st.done.iter())
            .map(|(messages, meta)| TurnTrajectory {
                session_id: self.session_id.clone(),
                model: self.model.clone(),
                workflow: self.workflow.clone(),
                step: meta.step.clone(),
                outcome: meta.outcome.clone(),
                messages,
                verifiers: meta.verifiers.clone(),
                session_tainted: tainted,
            })
            .collect())
    }

    fn observe(&self, ev: &Event) {
        let mut st = self.lock();
        match ev {
            Event::Verifier {
                step, name, passed, ..
            } => {
                let v = VerifierVerdict {
                    name: name.clone(),
                    passed: *passed,
                };
                // Verdicts follow the attempt's `done`, so they belong to the turn just closed.
                let target = match st.open.as_mut() {
                    Some(o) => Some(o),
                    None => st.done.last_mut(),
                };
                if let Some(t) = target {
                    if t.step.is_none() {
                        t.step = Some(step.clone());
                    }
                    t.verifiers.push(v);
                }
            }
            Event::Tainted { .. } => {
                st.tainted = true;
                st.open.get_or_insert_with(TurnMeta::default);
            }
            Event::Done { outcome } => {
                let mut meta = st.open.take().unwrap_or_default();
                meta.outcome = outcome.clone();
                st.done.push(meta);
            }
            _ => {
                st.open.get_or_insert_with(TurnMeta::default);
            }
        }
    }
}

impl EventSink for TrajectoryRecorder {
    fn emit(&self, ev: Event) {
        self.observe(&ev);
        if let Some(inner) = &self.inner {
            inner.emit(ev);
        }
    }
}
