//! HUP-S1.3: the model-driven planner, next to [`crate::StaticPlanner`].
//!
//! Planner and executor stay separate. [`ModelPlanner::propose`] asks the model for a plan as
//! JSON, with no tools offered, and turns it into a [`Workflow`] only when every proposed step
//! carries at least one verifier from the closed set in [`VerifierSpec`]. The plan is then run by
//! the same executor as every other workflow ([`crate::run_workflow`]), so a model-written plan
//! still succeeds only when its verifiers pass. There is no "the model says it is done" kind.
//!
//! What a proposed verifier may name is bounded by the session: tool checks name only the tools
//! the session offers ([`ModelPlanner::with_tools`]), and HTTP or hash checks build only when the
//! session supplied its scoped probes ([`ModelPlanner::with_env`]). Anything else is refused,
//! never guessed or repaired.

use std::collections::BTreeSet;
use std::sync::Arc;

use serde::Deserialize;

use crate::workflows::{VerifierEnv, VerifierSpec};
use crate::{CompletionRequest, LlmClient, LlmError, Message, Step, Workflow};

/// Most steps in one proposed plan.
pub const MAX_PLANNED_STEPS: usize = 8;
/// Most verifiers on one proposed step.
pub const MAX_PLANNED_VERIFIERS: usize = 6;
/// Longest proposed step instruction, in characters.
pub const MAX_PLANNED_INSTRUCTION_CHARS: usize = 1000;
/// Attempts per step when the plan does not say.
pub const DEFAULT_PLANNED_ATTEMPTS: u32 = 2;
/// Most tokens the planning call may produce.
pub const PLANNER_MAX_TOKENS: u32 = 1024;

/// Why no workflow came out of a goal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// The model call failed.
    Model(LlmError),
    /// The reply held no plan in the expected JSON shape.
    NotJson(String),
    /// The plan parsed but cannot be judged or is out of bounds (e.g. a step with no verifier).
    Refused(String),
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanError::Model(e) => write!(f, "{e}"),
            PlanError::NotJson(m) => write!(f, "the model's plan is not usable JSON: {m}"),
            PlanError::Refused(m) => write!(f, "the model's plan was refused: {m}"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannedStep {
    id: String,
    instruction: String,
    #[serde(default)]
    max_attempts: Option<u32>,
    verifiers: Vec<VerifierSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannedWorkflow {
    id: String,
    steps: Vec<PlannedStep>,
}

/// Proposes a workflow for a goal with the session's model.
pub struct ModelPlanner {
    llm: Arc<dyn LlmClient>,
    model: String,
    tools: BTreeSet<String>,
    env: VerifierEnv,
}

impl ModelPlanner {
    pub fn new(llm: Arc<dyn LlmClient>, model: impl Into<String>) -> Self {
        ModelPlanner {
            llm,
            model: model.into(),
            tools: BTreeSet::new(),
            env: VerifierEnv::default(),
        }
    }

    /// The tools the session offers; a proposed tool check may name only these.
    pub fn with_tools(mut self, tools: Vec<String>) -> Self {
        self.tools = tools.into_iter().collect();
        self
    }

    /// The session's scoped probes for HTTP and hash checks.
    pub fn with_env(mut self, env: VerifierEnv) -> Self {
        self.env = env;
        self
    }

    fn prompt(&self, goal: &str) -> Vec<Message> {
        let tools = if self.tools.is_empty() {
            "(none)".to_string()
        } else {
            self.tools.iter().cloned().collect::<Vec<_>>().join(", ")
        };
        let system = format!(
            "You plan work for an agent. Reply with one JSON object and nothing else:\n\
             {{\"id\": \"slug\", \"steps\": [{{\"id\": \"slug\", \"instruction\": \"...\", \
             \"max_attempts\": 1-5, \"verifiers\": [...]}}]}}\n\
             At most {MAX_PLANNED_STEPS} steps. Every step needs at least one verifier, chosen from:\n\
             {{\"kind\": \"tool_succeeded\", \"tool\": T}}, {{\"kind\": \"tool_not_called\", \"tool\": T}}, \
             {{\"kind\": \"answer_contains\", \"text\": \"...\"}}, \
             {{\"kind\": \"json_field_equals\", \"tool\": T, \"pointer\": \"/field\", \"value\": V}}, \
             {{\"kind\": \"http_status_is\", \"url\": \"http://127.0.0.1:PORT/path\", \"status\": 200}}, \
             {{\"kind\": \"sha256_equals\", \"path\": \"/abs/path\", \"hex\": \"64 hex\"}}.\n\
             T must be one of these tools: {tools}.\n\
             A step is done only when its verifiers pass, so choose checks that prove the work."
        );
        vec![
            Message::system(system),
            Message::user(format!("Goal: {goal}")),
        ]
    }

    /// Ask the model for a plan and return it as a runnable workflow, or say why not.
    pub fn propose(&self, goal: &str) -> Result<Workflow, PlanError> {
        let turn = self
            .llm
            .complete(&CompletionRequest {
                model: self.model.clone(),
                messages: self.prompt(goal),
                tools: vec![],
                max_tokens: PLANNER_MAX_TOKENS,
            })
            .map_err(PlanError::Model)?;
        let json = extract_object(&turn.content)
            .ok_or_else(|| PlanError::NotJson("the reply holds no JSON object".into()))?;
        let plan: PlannedWorkflow =
            serde_json::from_str(json).map_err(|e| PlanError::NotJson(e.to_string()))?;
        self.build(plan)
    }

    fn build(&self, plan: PlannedWorkflow) -> Result<Workflow, PlanError> {
        let refuse = |m: String| PlanError::Refused(m);
        if plan.steps.len() > MAX_PLANNED_STEPS {
            return Err(refuse(format!("at most {MAX_PLANNED_STEPS} steps")));
        }
        let known = |t: &str| self.tools.contains(t);
        let mut ids = BTreeSet::new();
        let mut steps = Vec::with_capacity(plan.steps.len());
        for s in plan.steps {
            if s.id.trim().is_empty() || s.id.len() > 64 || !ids.insert(s.id.clone()) {
                return Err(refuse(format!(
                    "step id {:?} is empty, long or repeated",
                    s.id
                )));
            }
            if s.instruction.trim().is_empty()
                || s.instruction.chars().count() > MAX_PLANNED_INSTRUCTION_CHARS
            {
                return Err(refuse(format!(
                    "step {} needs an instruction of 1 to {MAX_PLANNED_INSTRUCTION_CHARS} characters",
                    s.id
                )));
            }
            if s.verifiers.len() > MAX_PLANNED_VERIFIERS {
                return Err(refuse(format!(
                    "step {} has more than {MAX_PLANNED_VERIFIERS} verifiers",
                    s.id
                )));
            }
            let verifiers = s
                .verifiers
                .iter()
                .map(|v| v.build_with(&self.env, &known))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| refuse(format!("step {}: {e}", s.id)))?;
            steps.push(Step {
                id: s.id,
                instruction: s.instruction,
                verifiers,
                max_attempts: s.max_attempts.unwrap_or(DEFAULT_PLANNED_ATTEMPTS),
            });
        }
        if plan.id.trim().is_empty() || plan.id.len() > 64 {
            return Err(refuse("the plan needs a short id".into()));
        }
        // The same gate as every workflow: no steps, a step with no verifier, or an attempt budget
        // outside 1-5 is refused.
        Workflow::new(plan.id, steps).map_err(refuse)
    }
}

/// The outermost `{ ... }` span of a reply (models often wrap JSON in prose or a code fence).
fn extract_object(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    (end > start).then(|| &text[start..=end])
}
