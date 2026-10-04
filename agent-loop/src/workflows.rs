//! HUP-S3.3 (US-3.3 AC2): the workflow family of each track.
//!
//! `tracks/workflows.toml` (bundled) defines every track's workflows as data: ordered steps, each
//! with an instruction, a retry budget and the verifiers that judge it. [`WorkflowSpec::build`]
//! turns a definition into a real [`crate::Workflow`] whose verifiers are the loop's own
//! ([`crate::ToolSucceeded`], [`crate::AnswerContains`], ...) and the toolchain's
//! ([`crate::verifiers_tooling::ForgeTestsPass`], ...). Only verifiers say done.
//!
//! The first workflow listed for a track is its default and must be the track's `workflow`.
//! Definitions name only tools in [`KNOWN_TOOLS`], so a typo fails the bundled-data test instead
//! of producing a workflow that can never pass.
//!
//! Pure data + validation: no I/O. The sidecar runs a catalog workflow in a session with
//! `POST /sessions/:id/track_workflows` (it refuses one whose [`WorkflowSpec::required_tools`] the
//! session does not offer), so every track says `workflow_available = true`.

use crate::interview::bundled_tracks;
use crate::verifiers_tooling::{
    ForgeTestsPass, MedusaNoFailures, SarifBelowThreshold, ScanReportRead, Severity,
    ADERYN_SCAN_TOOL, FORGE_TEST_TOOL, MEDUSA_FUZZ_TOOL, SLITHER_SCAN_TOOL,
};
use crate::{
    AnswerContains, FileDigest, HttpProbe, HttpStatusIs, JsonFieldEquals, Sha256Equals, Step,
    ToolNotCalled, ToolSucceeded, Verifier, Workflow,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Arc;

/// The bundled workflow catalog, verbatim.
pub const WORKFLOWS_SOURCE: &str = include_str!("../tracks/workflows.toml");

/// Tools a workflow (or a shipped persona's tool emphasis) may name: the sidecar's toolchain and
/// skill tools, and the tools citrate-core offers every session (`src/agent/harness.ts`).
pub const KNOWN_TOOLS: &[&str] = &[
    // sidecar: toolchain (HUP-S6.3) and skills (HUP-S3.2)
    FORGE_TEST_TOOL,
    SLITHER_SCAN_TOOL,
    ADERYN_SCAN_TOOL,
    MEDUSA_FUZZ_TOOL,
    "skill_load",
    // core-hosted
    "memory_search",
    "memory_recall",
    "memory_assert",
    "app_navigate",
    "journal_append",
    "journal_read",
    "node_status",
    "staking_status",
    "groups_list",
    "group_roster",
    "group_create",
    "group_invite",
    "directory_find",
    "skills_list",
    "skill_write",
    "skill_run",
    "models_list",
    "contract_deploy",
];

const MAX_INSTRUCTION_CHARS: usize = 1000;
const MAX_TEXT_CHARS: usize = 200;
/// Longest URL or path an HTTP or hash verifier may name, in bytes.
pub const MAX_LOCATION_BYTES: usize = 2048;

/// HUP-S1.3: the hosts the I/O verifiers need. The bundled catalog builds with none, so it can
/// never name an HTTP or hash check; a sidecar session supplies its own scoped probes.
#[derive(Clone, Default)]
pub struct VerifierEnv {
    /// For `http_status_is` (loopback or member-consented origins only, in the sidecar).
    pub http: Option<Arc<dyn HttpProbe>>,
    /// For `sha256_equals` (inside the session's folder grants only, in the sidecar).
    pub files: Option<Arc<dyn FileDigest>>,
}

/// One verifier, as data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    ForgeTestsPass {},
    SarifBelowThreshold {
        tool: String,
        threshold: String,
    },
    MedusaNoFailures {},
    /// The latest scan of a SARIF scanner produced a report that was read (any findings).
    ScanReportRead {
        tool: String,
    },
    /// HUP-S1.3: `GET url` answers exactly `status`.
    HttpStatusIs {
        url: String,
        status: u16,
    },
    /// HUP-S1.3: the file at `path` has this SHA-256 (64 hex characters).
    Sha256Equals {
        path: String,
        hex: String,
    },
}

impl VerifierSpec {
    /// The tool this verifier reads or guards, if any.
    pub fn tool(&self) -> Option<&str> {
        match self {
            VerifierSpec::ToolSucceeded { tool }
            | VerifierSpec::ToolNotCalled { tool }
            | VerifierSpec::JsonFieldEquals { tool, .. }
            | VerifierSpec::SarifBelowThreshold { tool, .. }
            | VerifierSpec::ScanReportRead { tool } => Some(tool),
            VerifierSpec::ForgeTestsPass {} => Some(FORGE_TEST_TOOL),
            VerifierSpec::MedusaNoFailures {} => Some(MEDUSA_FUZZ_TOOL),
            VerifierSpec::AnswerContains { .. }
            | VerifierSpec::HttpStatusIs { .. }
            | VerifierSpec::Sha256Equals { .. } => None,
        }
    }

    /// True when passing needs the tool to have run (every tool verifier except a guard).
    pub fn requires_call(&self) -> bool {
        !matches!(
            self,
            VerifierSpec::ToolNotCalled { .. }
                | VerifierSpec::AnswerContains { .. }
                | VerifierSpec::HttpStatusIs { .. }
                | VerifierSpec::Sha256Equals { .. }
        )
    }

    /// True when the verdict comes from evidence outside the answer: a tool's result, or (HTTP
    /// and hash checks) the state of the world the step was meant to change.
    pub fn reads_a_tool_report(&self) -> bool {
        self.requires_call()
            || matches!(
                self,
                VerifierSpec::HttpStatusIs { .. } | VerifierSpec::Sha256Equals { .. }
            )
    }

    fn validate(&self) -> Result<(), String> {
        self.validate_with(&|t| KNOWN_TOOLS.contains(&t))
    }

    /// Shape checks, with `known` deciding which tool names may appear.
    pub fn validate_with(&self, known: &dyn Fn(&str) -> bool) -> Result<(), String> {
        if let Some(t) = self.tool() {
            if !known(t) {
                return Err(format!("unknown tool {t:?}"));
            }
        }
        match self {
            VerifierSpec::AnswerContains { text } => {
                if text.trim().is_empty() || text.chars().count() > MAX_TEXT_CHARS {
                    return Err("answer_contains needs 1..=200 characters of text".into());
                }
            }
            VerifierSpec::JsonFieldEquals { pointer, .. } => {
                if !pointer.starts_with('/') {
                    return Err(format!("json pointer {pointer:?} must start with /"));
                }
            }
            VerifierSpec::SarifBelowThreshold { tool, threshold } => {
                if tool != SLITHER_SCAN_TOOL && tool != ADERYN_SCAN_TOOL {
                    return Err(format!("{tool:?} is not a SARIF scanner"));
                }
                if Severity::parse(threshold).is_none() {
                    return Err(format!("unknown severity {threshold:?}"));
                }
            }
            VerifierSpec::ScanReportRead { tool }
                if tool != SLITHER_SCAN_TOOL && tool != ADERYN_SCAN_TOOL =>
            {
                return Err(format!("{tool:?} is not a SARIF scanner"));
            }
            VerifierSpec::HttpStatusIs { url, status } => {
                let lower = url.to_ascii_lowercase();
                if url.len() > MAX_LOCATION_BYTES
                    || url.chars().any(char::is_control)
                    || !(lower.starts_with("http://") || lower.starts_with("https://"))
                    || lower.len() <= "https://".len()
                {
                    return Err(format!("{url:?} is not an http(s) URL"));
                }
                if !(100..=599).contains(status) {
                    return Err(format!("{status} is not an HTTP status"));
                }
            }
            VerifierSpec::Sha256Equals { path, hex } => {
                if path.trim().is_empty()
                    || path.len() > MAX_LOCATION_BYTES
                    || path.chars().any(char::is_control)
                {
                    return Err("sha256_equals needs a file path".into());
                }
                if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err("sha256_equals needs 64 hex characters".into());
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// The real verifier. The bundled catalog has no I/O hosts, so an HTTP or hash check is
    /// refused here; see [`VerifierSpec::build_in`].
    pub fn build(&self) -> Result<Arc<dyn Verifier>, String> {
        self.build_in(&VerifierEnv::default())
    }

    /// The real verifier, with `env`'s hosts for the I/O checks.
    pub fn build_in(&self, env: &VerifierEnv) -> Result<Arc<dyn Verifier>, String> {
        self.validate()?;
        self.build_checked(env)
    }

    /// The real verifier, with `known` deciding which tool names may appear (a model-proposed
    /// plan names the session's own tools, not the catalog's).
    pub fn build_with(
        &self,
        env: &VerifierEnv,
        known: &dyn Fn(&str) -> bool,
    ) -> Result<Arc<dyn Verifier>, String> {
        self.validate_with(known)?;
        self.build_checked(env)
    }

    fn build_checked(&self, env: &VerifierEnv) -> Result<Arc<dyn Verifier>, String> {
        Ok(match self {
            VerifierSpec::ToolSucceeded { tool } => Arc::new(ToolSucceeded(tool.clone())),
            VerifierSpec::ToolNotCalled { tool } => Arc::new(ToolNotCalled(tool.clone())),
            VerifierSpec::AnswerContains { text } => Arc::new(AnswerContains(text.clone())),
            VerifierSpec::JsonFieldEquals {
                tool,
                pointer,
                value,
            } => Arc::new(JsonFieldEquals {
                tool: tool.clone(),
                pointer: pointer.clone(),
                value: value.clone(),
            }),
            VerifierSpec::ForgeTestsPass {} => Arc::new(ForgeTestsPass::default()),
            VerifierSpec::SarifBelowThreshold { tool, threshold } => {
                let t = Severity::parse(threshold)
                    .ok_or_else(|| format!("unknown severity {threshold:?}"))?;
                Arc::new(SarifBelowThreshold::new(tool, t))
            }
            VerifierSpec::MedusaNoFailures {} => Arc::new(MedusaNoFailures::default()),
            VerifierSpec::ScanReportRead { tool } => Arc::new(ScanReportRead::new(tool)),
            VerifierSpec::HttpStatusIs { url, status } => {
                let probe = env.http.clone().ok_or_else(|| {
                    "http_status_is needs the sidecar session's HTTP probe".to_string()
                })?;
                Arc::new(HttpStatusIs::new(url.clone(), *status, probe))
            }
            VerifierSpec::Sha256Equals { path, hex } => {
                let files = env.files.clone().ok_or_else(|| {
                    "sha256_equals needs the sidecar session's folder grants".to_string()
                })?;
                Arc::new(Sha256Equals::new(path.clone(), hex, files))
            }
        })
    }
}

/// One step, as data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepSpec {
    pub id: String,
    pub instruction: String,
    pub max_attempts: u32,
    pub verifiers: Vec<VerifierSpec>,
}

/// How strong a workflow's evidence is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Evidence {
    /// At least one verifier re-judges a tool's own result.
    ToolReport,
    /// Only the answer's shape and tool guards are checked.
    AnswerShape,
}

/// One workflow of a track's family, as data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSpec {
    pub id: String,
    pub track: String,
    pub title: String,
    pub summary: String,
    pub steps: Vec<StepSpec>,
}

fn slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

impl WorkflowSpec {
    /// Every tool the workflow reads or guards.
    pub fn tools(&self) -> BTreeSet<String> {
        self.steps
            .iter()
            .flat_map(|s| s.verifiers.iter())
            .filter_map(|v| v.tool().map(str::to_string))
            .collect()
    }

    /// The tools a passing run must have called: every tool a verifier reads a result of. A tool
    /// that is only guarded (`tool_not_called`) is never required.
    pub fn required_tools(&self) -> BTreeSet<String> {
        self.steps
            .iter()
            .flat_map(|s| s.verifiers.iter())
            .filter(|v| v.requires_call())
            .filter_map(|v| v.tool().map(str::to_string))
            .collect()
    }

    pub fn evidence(&self) -> Evidence {
        if self
            .steps
            .iter()
            .flat_map(|s| s.verifiers.iter())
            .any(VerifierSpec::reads_a_tool_report)
        {
            Evidence::ToolReport
        } else {
            Evidence::AnswerShape
        }
    }

    /// Shape checks that do not need the track list.
    pub fn validate(&self) -> Result<(), String> {
        if !slug(&self.id) || !slug(&self.track) {
            return Err(format!("workflow {:?}: id and track are slugs", self.id));
        }
        if self.title.trim().is_empty() || self.summary.trim().is_empty() {
            return Err(format!(
                "workflow {}: title and summary are required",
                self.id
            ));
        }
        if self.steps.is_empty() {
            return Err(format!("workflow {} has no steps", self.id));
        }
        let mut seen = BTreeSet::new();
        for s in &self.steps {
            if !slug(&s.id) || !seen.insert(s.id.as_str()) {
                return Err(format!(
                    "workflow {}: step id {:?} is not a slug or repeats",
                    self.id, s.id
                ));
            }
            if s.instruction.trim().is_empty()
                || s.instruction.chars().count() > MAX_INSTRUCTION_CHARS
            {
                return Err(format!(
                    "workflow {} step {}: instruction must be 1..={MAX_INSTRUCTION_CHARS} characters",
                    self.id, s.id
                ));
            }
            for v in &s.verifiers {
                v.validate()
                    .map_err(|e| format!("workflow {} step {}: {e}", self.id, s.id))?;
            }
        }
        Ok(())
    }

    /// The runnable workflow: the loop's verifiers judge every step.
    pub fn build(&self) -> Result<Workflow, String> {
        self.validate()?;
        let mut steps = Vec::with_capacity(self.steps.len());
        for s in &self.steps {
            let verifiers = s
                .verifiers
                .iter()
                .map(VerifierSpec::build)
                .collect::<Result<Vec<_>, _>>()?;
            steps.push(Step {
                id: s.id.clone(),
                instruction: s.instruction.clone(),
                verifiers,
                max_attempts: s.max_attempts,
            });
        }
        Workflow::new(self.id.clone(), steps)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowFile {
    workflows: Vec<WorkflowSpec>,
}

/// Parse and validate a catalog against the bundled tracks: unique ids, known tracks, every
/// workflow buildable, and each track's default workflow listed first in its family.
pub fn parse_workflows(src: &str) -> Result<Vec<WorkflowSpec>, String> {
    let file: WorkflowFile = toml::from_str(src).map_err(|e| format!("workflows: {e}"))?;
    let tracks = bundled_tracks()?;
    let mut ids = BTreeSet::new();
    for w in &file.workflows {
        if !ids.insert(w.id.as_str()) {
            return Err(format!("workflow id {:?} repeats", w.id));
        }
        if !tracks.iter().any(|t| t.id == w.track) {
            return Err(format!("workflow {}: no track {:?}", w.id, w.track));
        }
        w.build()?;
    }
    for t in &tracks {
        match file.workflows.iter().find(|w| w.track == t.id) {
            Some(first) if first.id == t.workflow => {}
            Some(first) => {
                return Err(format!(
                    "track {}: its default workflow {} must be listed first (found {})",
                    t.id, t.workflow, first.id
                ))
            }
            None => return Err(format!("track {} has no workflows", t.id)),
        }
    }
    Ok(file.workflows)
}

/// The bundled catalog.
pub fn bundled_workflows() -> Result<Vec<WorkflowSpec>, String> {
    parse_workflows(WORKFLOWS_SOURCE)
}

/// The catalog workflow with this id, if any.
pub fn find_workflow(id: &str) -> Result<Option<WorkflowSpec>, String> {
    Ok(bundled_workflows()?.into_iter().find(|w| w.id == id))
}

/// A track's family, default first.
pub fn workflows_for_track(track: &str) -> Result<Vec<WorkflowSpec>, String> {
    Ok(bundled_workflows()?
        .into_iter()
        .filter(|w| w.track == track)
        .collect())
}

/// A step as a client shows it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StepView {
    pub id: String,
    pub instruction: String,
    pub max_attempts: u32,
    /// The verifiers' own names (what the activity view prints when they judge).
    pub verifier_names: Vec<String>,
}

/// A workflow as a client shows it (`GET /workflows`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowView {
    pub id: String,
    pub track: String,
    pub title: String,
    pub summary: String,
    pub is_default: bool,
    pub evidence: Evidence,
    pub tools: Vec<String>,
    /// The tools a passing run must call ([`WorkflowSpec::required_tools`]). A session that does
    /// not offer one of them cannot run the workflow; the sidecar says which.
    pub needs_tools: Vec<String>,
    pub verifier_names: Vec<String>,
    pub steps: Vec<StepView>,
}

/// Every bundled workflow, in catalog order, with its verifiers named.
pub fn workflow_views() -> Result<Vec<WorkflowView>, String> {
    let tracks = bundled_tracks()?;
    let all = bundled_workflows()?;
    let mut out = Vec::with_capacity(all.len());
    for w in all {
        let built = w.build()?;
        let steps: Vec<StepView> = w
            .steps
            .iter()
            .zip(built.steps.iter())
            .map(|(s, b)| StepView {
                id: s.id.clone(),
                instruction: s.instruction.clone(),
                max_attempts: s.max_attempts,
                verifier_names: b.verifiers.iter().map(|v| v.name()).collect(),
            })
            .collect();
        let is_default = tracks.iter().any(|t| t.id == w.track && t.workflow == w.id);
        out.push(WorkflowView {
            evidence: w.evidence(),
            tools: w.tools().into_iter().collect(),
            needs_tools: w.required_tools().into_iter().collect(),
            verifier_names: steps
                .iter()
                .flat_map(|s| s.verifier_names.iter().cloned())
                .collect(),
            id: w.id,
            track: w.track,
            title: w.title,
            summary: w.summary,
            is_default,
            steps,
        });
    }
    Ok(out)
}
