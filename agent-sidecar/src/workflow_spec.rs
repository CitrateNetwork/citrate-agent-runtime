//! HUP-S3.4 wiring: the declarative workflow a client asks a session to run
//! (`POST /sessions/:id/workflows`).
//!
//! A workflow is a list of steps, each judged by verifiers from a closed set. The set is the
//! deterministic checks agent-loop already has (a tool succeeded or was not called, the answer
//! mentions a text, a JSON field of a tool result equals a value) plus the toolchain verifiers
//! (forge test report, SARIF threshold, medusa summary). There is no "the model says it is done"
//! verifier: a run is verified only when every verifier of every step passed
//! (`citrate_agent_learn::run_verified_workflow`).

use std::sync::Arc;

use citrate_agent_loop::verifiers_tooling::{
    ForgeTestsPass, MedusaNoFailures, SarifBelowThreshold, Severity, FORGE_TEST_TOOL,
    MEDUSA_FUZZ_TOOL,
};
use citrate_agent_loop::{
    AnswerContains, JsonFieldEquals, Step, ToolNotCalled, ToolSucceeded, Verifier, Workflow,
};
use serde::Deserialize;

/// Most steps in one workflow.
pub const MAX_STEPS: usize = 16;
/// Most verifiers on one step.
pub const MAX_VERIFIERS: usize = 8;
/// Longest step instruction, in bytes.
pub const MAX_INSTRUCTION: usize = 8 * 1024;
/// Longest id, tool name, text or pointer, in bytes.
const MAX_FIELD: usize = 256;

/// One verifier, by kind.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerifierSpec {
    ToolSucceeded {
        tool: String,
    },
    ToolNotCalled {
        tool: String,
    },
    AnswerContains {
        text: String,
    },
    JsonFieldEquals {
        tool: String,
        pointer: String,
        value: serde_json::Value,
    },
    ForgeTestsPass {
        #[serde(default)]
        tool: Option<String>,
    },
    SarifBelow {
        tool: String,
        threshold: String,
    },
    MedusaNoFailures {
        #[serde(default)]
        tool: Option<String>,
    },
}

fn default_attempts() -> u32 {
    1
}

/// One step.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepSpec {
    pub id: String,
    pub instruction: String,
    #[serde(default = "default_attempts")]
    pub max_attempts: u32,
    pub verifiers: Vec<VerifierSpec>,
}

/// The `POST /sessions/:id/workflows` body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSpec {
    pub id: String,
    pub steps: Vec<StepSpec>,
}

fn short(what: &str, s: &str) -> Result<(), String> {
    if s.trim().is_empty() {
        return Err(format!("{what} is empty"));
    }
    if s.len() > MAX_FIELD {
        return Err(format!("{what} is longer than {MAX_FIELD} bytes"));
    }
    if s.chars().any(char::is_control) {
        return Err(format!("{what} has control characters"));
    }
    Ok(())
}

fn verifier(v: &VerifierSpec) -> Result<Arc<dyn Verifier>, String> {
    Ok(match v {
        VerifierSpec::ToolSucceeded { tool } => {
            short("tool", tool)?;
            Arc::new(ToolSucceeded(tool.clone()))
        }
        VerifierSpec::ToolNotCalled { tool } => {
            short("tool", tool)?;
            Arc::new(ToolNotCalled(tool.clone()))
        }
        VerifierSpec::AnswerContains { text } => {
            short("text", text)?;
            Arc::new(AnswerContains(text.clone()))
        }
        VerifierSpec::JsonFieldEquals {
            tool,
            pointer,
            value,
        } => {
            short("tool", tool)?;
            if !pointer.is_empty() && !pointer.starts_with('/') {
                return Err("pointer must be an RFC 6901 JSON pointer".into());
            }
            if pointer.len() > MAX_FIELD {
                return Err("pointer is too long".into());
            }
            Arc::new(JsonFieldEquals {
                tool: tool.clone(),
                pointer: pointer.clone(),
                value: value.clone(),
            })
        }
        VerifierSpec::ForgeTestsPass { tool } => {
            let tool = tool.clone().unwrap_or_else(|| FORGE_TEST_TOOL.into());
            short("tool", &tool)?;
            Arc::new(ForgeTestsPass { tool })
        }
        VerifierSpec::SarifBelow { tool, threshold } => {
            short("tool", tool)?;
            let t = Severity::parse(threshold)
                .ok_or_else(|| format!("unknown severity {threshold:?}"))?;
            Arc::new(SarifBelowThreshold::new(tool, t))
        }
        VerifierSpec::MedusaNoFailures { tool } => {
            let tool = tool.clone().unwrap_or_else(|| MEDUSA_FUZZ_TOOL.into());
            short("tool", &tool)?;
            Arc::new(MedusaNoFailures { tool })
        }
    })
}

impl WorkflowSpec {
    /// Build the runnable workflow, or say why it cannot be judged.
    pub fn build(&self) -> Result<Workflow, String> {
        short("workflow id", &self.id)?;
        if self.steps.len() > MAX_STEPS {
            return Err(format!("at most {MAX_STEPS} steps"));
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut steps = Vec::with_capacity(self.steps.len());
        for st in &self.steps {
            short("step id", &st.id)?;
            if !seen.insert(st.id.as_str()) {
                return Err(format!("step id {:?} is used twice", st.id));
            }
            if st.instruction.trim().is_empty() || st.instruction.len() > MAX_INSTRUCTION {
                return Err(format!(
                    "step {} needs an instruction of 1 to {MAX_INSTRUCTION} bytes",
                    st.id
                ));
            }
            if st.verifiers.len() > MAX_VERIFIERS {
                return Err(format!(
                    "step {} has more than {MAX_VERIFIERS} verifiers",
                    st.id
                ));
            }
            let verifiers = st
                .verifiers
                .iter()
                .map(verifier)
                .collect::<Result<Vec<_>, _>>()?;
            // Two verifiers with the same name would make the recorded verdicts ambiguous.
            let mut names = std::collections::BTreeSet::new();
            for v in &verifiers {
                if !names.insert(v.name()) {
                    return Err(format!(
                        "step {} has the verifier {:?} twice",
                        st.id,
                        v.name()
                    ));
                }
            }
            steps.push(Step {
                id: st.id.clone(),
                instruction: st.instruction.clone(),
                verifiers,
                max_attempts: st.max_attempts,
            });
        }
        Workflow::new(self.id.clone(), steps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(v: serde_json::Value) -> Result<Workflow, String> {
        serde_json::from_value::<WorkflowSpec>(v)
            .map_err(|e| e.to_string())?
            .build()
    }

    #[test]
    fn every_verifier_kind_builds() {
        let w = spec(serde_json::json!({
            "id": "w",
            "steps": [{
                "id": "a", "instruction": "do it", "max_attempts": 3,
                "verifiers": [
                    {"kind": "tool_succeeded", "tool": "t"},
                    {"kind": "tool_not_called", "tool": "deploy"},
                    {"kind": "answer_contains", "text": "ok"},
                    {"kind": "json_field_equals", "tool": "t", "pointer": "/failed", "value": 0},
                    {"kind": "forge_tests_pass"},
                    {"kind": "sarif_below", "tool": "slither_scan", "threshold": "high"},
                    {"kind": "medusa_no_failures"}
                ]
            }]
        }))
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(w.steps[0].verifiers.len(), 7);
        assert_eq!(w.steps[0].max_attempts, 3);
    }

    #[test]
    fn duplicate_steps_or_verifiers_and_bad_fields_are_refused() {
        let one = |v: serde_json::Value| {
            spec(
                serde_json::json!({"id": "w", "steps": [{"id": "a", "instruction": "x", "verifiers": [v]}]}),
            )
        };
        assert!(one(serde_json::json!({"kind": "tool_succeeded", "tool": ""})).is_err());
        assert!(one(serde_json::json!({"kind": "answer_contains", "text": "a\u{0}b"})).is_err());
        assert!(one(serde_json::json!({"kind": "json_field_equals", "tool": "t", "pointer": "failed", "value": 0})).is_err());
        assert!(
            one(serde_json::json!({"kind": "tool_succeeded", "tool": "t", "extra": 1})).is_err()
        );
        assert!(spec(serde_json::json!({"id": "w", "steps": [
            {"id": "a", "instruction": "x", "verifiers": [{"kind": "answer_contains", "text": "y"}]},
            {"id": "a", "instruction": "x", "verifiers": [{"kind": "answer_contains", "text": "y"}]}
        ]}))
        .is_err());
        assert!(spec(
            serde_json::json!({"id": "w", "steps": [{"id": "a", "instruction": "x", "verifiers": [
                {"kind": "answer_contains", "text": "y"}, {"kind": "answer_contains", "text": "y"}
            ]}]})
        )
        .is_err());
        assert!(spec(serde_json::json!({"id": "w", "steps": [{"id": "a", "instruction": " ", "verifiers": [{"kind": "answer_contains", "text": "y"}]}]})).is_err());
    }
}
