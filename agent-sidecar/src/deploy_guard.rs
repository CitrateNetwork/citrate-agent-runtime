//! HUP-S6 US-6.1 AC2 + US-6.2 — the session's **deploy guard**.
//!
//! A session with the toolchain keeps the latest raw report of every forge_test, slither_scan,
//! aderyn_scan and medusa_fuzz run ([`crate::toolchain_reports`]). This module reads them with the
//! loop crate's guard ([`citrate_agent_loop::deploy_guard`]) and applies it twice:
//!
//! - **A deploy request while the gate blocks** ("deploy it", "deploy anyway") is answered by
//!   [`DeployGuard::refusal`] without a model call: Hermes declines, names each finding (test
//!   name, or rule id with its severity and location), and proposes the fix, with a patch where
//!   the cause is mechanical. Nothing is dispatched, so no SignatureCeremony is created.
//! - **A `contract_deploy` call the model makes anyway** is declined by the loop's call policy
//!   before it is announced: its `tool_call` event names no host, so core never acts on it.
//!
//! "Blocks" is evidence only: the most recently worked-on project (the one with the newest
//! report) has at least one finding in the latest report of a gate tool. A project no tool ran
//! on is not blocked here; core's deploy gate, the one source of truth for a deploy verdict,
//! still refuses any deploy without a READY record. The guard only ever takes a deploy away.
//!
//! Proposed patches read the project's own `src/*.sol` files: a plain relative path, no symlink,
//! inside the canonical project folder, at most [`MAX_SOURCE_BYTES`]. Nothing is written.
//! Rule 3: nothing here signs or holds a key.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use citrate_agent_loop::deploy_guard::{
    findings_from_report, is_deploy_request, propose_fix, refusal_text, safe_src_path, GateFinding,
    CONTRACT_DEPLOY_TOOL, GATE_TOOLS,
};
use citrate_agent_loop::{CallPolicy, ToolCall};

use crate::toolchain_reports::ToolchainReports;

/// The largest source file a fix proposal reads.
pub const MAX_SOURCE_BYTES: u64 = 256 * 1024;

/// What blocks a deploy right now: the project and its findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployBlock {
    pub project: String,
    pub findings: Vec<GateFinding>,
}

/// A session's deploy guard over its kept toolchain reports.
#[derive(Clone)]
pub struct DeployGuard {
    reports: Arc<ToolchainReports>,
}

/// `project/<rel>` when `rel` is a plain `src/*.sol` path, the file is a regular file (not a
/// symlink) inside the canonical project, and it is small enough.
pub fn read_project_source(project: &Path, rel: &str) -> Option<String> {
    if !safe_src_path(rel) {
        return None;
    }
    let root = std::fs::canonicalize(project).ok()?;
    let path: PathBuf = root.join(rel);
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > MAX_SOURCE_BYTES {
        return None;
    }
    // Every folder on the way must resolve inside the project too (no symlinked `src/`).
    let canon = std::fs::canonicalize(&path).ok()?;
    if !canon.starts_with(&root) {
        return None;
    }
    std::fs::read_to_string(canon).ok()
}

impl DeployGuard {
    pub fn new(reports: Arc<ToolchainReports>) -> Self {
        DeployGuard { reports }
    }

    /// The findings that block a deploy of the most recently worked-on project, if any.
    pub fn block(&self) -> Option<DeployBlock> {
        let all = self.reports.list(None);
        let project = all.iter().max_by_key(|r| r.seq)?.project.clone();
        let mut findings = Vec::new();
        for tool in GATE_TOOLS {
            let latest = all
                .iter()
                .filter(|r| r.project == project && r.tool == tool)
                .max_by_key(|r| r.seq);
            if let Some(r) = latest {
                findings.extend(findings_from_report(
                    tool,
                    r.status,
                    r.gate.as_ref().map(|g| g.output.as_str()),
                ));
            }
        }
        (!findings.is_empty()).then_some(DeployBlock { project, findings })
    }

    /// Hermes's refusal for the current block, with the proposed fixes; `None` when nothing
    /// blocks.
    pub fn refusal(&self) -> Option<String> {
        let b = self.block()?;
        let root = PathBuf::from(&b.project);
        let read = |rel: &str| read_project_source(&root, rel);
        let fixes: Vec<_> = b.findings.iter().map(|f| propose_fix(f, &read)).collect();
        Some(refusal_text(&b.project, &b.findings, &fixes))
    }

    /// The refusal for a member's message: `Some` only for a deploy request while a block holds.
    pub fn answer_to(&self, text: &str) -> Option<String> {
        if !is_deploy_request(text) {
            return None;
        }
        self.refusal()
    }
}

impl CallPolicy for DeployGuard {
    fn decline(&self, call: &ToolCall) -> Option<String> {
        if call.name != CONTRACT_DEPLOY_TOOL {
            return None;
        }
        self.refusal()
    }
}
