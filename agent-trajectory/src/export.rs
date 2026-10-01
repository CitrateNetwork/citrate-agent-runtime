//! The JSONL training-set export and its redaction report.

use crate::policy::ExportPolicy;
use crate::recorder::{Eligibility, TurnTrajectory};
use crate::redact::{RedactionCounts, Redactor};
use crate::TrajectoryError;
use citrate_agent_loop::Role;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

/// A tool call in OpenAI chat fine-tuning shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExampleFunction {
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExampleToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub function: ExampleFunction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExampleMessage {
    pub role: String,
    pub content: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ExampleToolCall>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExampleMeta {
    pub model: String,
    pub workflow: Option<String>,
    pub step: Option<String>,
    /// The verifiers that passed this turn.
    pub verifiers: Vec<String>,
}

/// One JSONL line: `{"messages": [...], "metadata": {...}}`. No session id is exported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingExample {
    pub messages: Vec<ExampleMessage>,
    pub metadata: ExampleMeta,
}

/// Why turns were left out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExclusionCounts {
    pub tainted_session: u32,
    pub unverified: u32,
    pub verifier_failed: u32,
    pub not_answered: u32,
}

/// What the export did. Counts only: no redacted value appears here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionReport {
    pub considered: u32,
    pub exported: u32,
    pub excluded: ExclusionCounts,
    pub totals: RedactionCounts,
    /// Per exported example, in output order.
    pub per_example: Vec<RedactionCounts>,
    /// The member's reason, when tainted sessions were allowed.
    pub tainted_sessions_allowed: Option<String>,
    pub granted_roots: u32,
    pub allowed_addresses: u32,
    pub note: String,
}

/// The export: examples ready for JSONL plus the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrainingExport {
    pub examples: Vec<TrainingExample>,
    pub report: RedactionReport,
}

fn role(r: Role) -> &'static str {
    match r {
        Role::System => "system",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
    }
}

fn bump(x: &mut u32) {
    *x = x.saturating_add(1);
}

/// Export the verified turns under `policy`. Excluded: turns from tainted sessions (unless the
/// policy allows them), turns no verifier judged, turns with a failing verifier, turns that did
/// not end in an answer. Everything exported is redacted.
pub fn export_verified(
    trajectories: &[TurnTrajectory],
    policy: &ExportPolicy,
) -> Result<TrainingExport, TrajectoryError> {
    let redactor = Redactor::new(policy)?;
    let mut report = RedactionReport {
        considered: 0,
        exported: 0,
        excluded: ExclusionCounts::default(),
        totals: RedactionCounts::default(),
        per_example: Vec::new(),
        tainted_sessions_allowed: policy.tainted_allowed().map(str::to_string),
        granted_roots: u32::try_from(policy.granted_roots().len()).unwrap_or(u32::MAX),
        allowed_addresses: u32::try_from(policy.allowed_addresses().len()).unwrap_or(u32::MAX),
        note: "Redaction is pattern-based and errs toward removing too much. Review the file \
               before sharing it; sharing for a training round needs the member's consent for \
               that round."
            .to_string(),
    };
    let mut examples = Vec::new();
    for t in trajectories {
        bump(&mut report.considered);
        if t.session_tainted && policy.tainted_allowed().is_none() {
            bump(&mut report.excluded.tainted_session);
            continue;
        }
        match t.eligibility() {
            Eligibility::Verified => {}
            Eligibility::Unverified => {
                bump(&mut report.excluded.unverified);
                continue;
            }
            Eligibility::VerifierFailed => {
                bump(&mut report.excluded.verifier_failed);
                continue;
            }
            Eligibility::NotAnswered => {
                bump(&mut report.excluded.not_answered);
                continue;
            }
        }
        let mut counts = RedactionCounts::default();
        let mut r = |s: &str| {
            let (out, c) = redactor.redact(s);
            counts.add(&c);
            out
        };
        let messages = t
            .messages
            .iter()
            .map(|m| ExampleMessage {
                role: role(m.role).to_string(),
                content: r(&m.content),
                tool_calls: m
                    .tool_calls
                    .iter()
                    .map(|c| ExampleToolCall {
                        id: r(&c.id),
                        kind: "function".to_string(),
                        function: ExampleFunction {
                            name: r(&c.name),
                            arguments: r(&c.arguments),
                        },
                    })
                    .collect(),
                tool_call_id: m.tool_call_id.as_deref().map(&mut r),
            })
            .collect();
        let metadata = ExampleMeta {
            model: r(&t.model),
            workflow: t.workflow.as_deref().map(&mut r),
            step: t.step.as_deref().map(&mut r),
            verifiers: t.verifiers.iter().map(|v| r(&v.name)).collect(),
        };
        examples.push(TrainingExample { messages, metadata });
        report.totals.add(&counts);
        report.per_example.push(counts);
        bump(&mut report.exported);
    }
    Ok(TrainingExport { examples, report })
}

impl TrainingExport {
    /// One JSON object per line (empty when nothing was exported).
    pub fn to_jsonl(&self) -> Result<String, TrajectoryError> {
        let mut out = String::new();
        for e in &self.examples {
            out.push_str(
                &serde_json::to_string(e).map_err(|e| TrajectoryError::Serialize(e.to_string()))?,
            );
            out.push('\n');
        }
        Ok(out)
    }

    /// Write the JSONL to a new file, readable only by its owner on Unix. Never overwrites an
    /// existing one.
    pub fn write_jsonl(&self, path: &Path) -> Result<(), TrajectoryError> {
        let body = self.to_jsonl()?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(path)
            .map_err(|e| TrajectoryError::Io(e.to_string()))?;
        f.write_all(body.as_bytes())
            .map_err(|e| TrajectoryError::Io(e.to_string()))
    }
}
