//! HUP-S6.3 → HUP-S6.4 (retro A27): the toolchain's raw reports, kept for the app's deploy gate.
//!
//! The deploy gate in citrate-core is the one source of truth for a deploy verdict. It never
//! trusts a verdict computed here: it reads the raw report of each tool run and parses it itself.
//! This module is the hand-over:
//!
//! - the toolchain host attaches a [`GateReport`] to every completed run: the raw stdout, the
//!   project folder, a digest of the project's sources taken before and after the run, the
//!   creation bytecode digests of what a forge run built, and medusa's call budget and lcov
//!   coverage report;
//! - [`CapturingToolchain`] wraps a session's toolchain host. It takes the report out of the
//!   result before the model sees it (the model gets the envelope without the raw output) and
//!   keeps the latest report per (project, tool) in the session's [`ToolchainReports`];
//! - core reads them with `GET /sessions/:id/toolchain/reports` over its bearer channel and
//!   submits them to `deploy_gate_submit`.
//!
//! Nothing here judges, signs or holds a key (Rule 3).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use citrate_agent_loop::verifiers_tooling::{GateReport, RunStatus, ToolchainEnvelope};
use citrate_agent_loop::{ToolCall, ToolHost, ToolOutcome};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::toolchain::ToolchainHost;

/// Folders that hold build output, caches or dependencies' own history, never sources.
const SKIP_DIRS: [&str; 8] = [
    "out",
    "cache",
    "node_modules",
    "medusa-corpus",
    "crytic-export",
    "broadcast",
    ".git",
    "dist",
];
/// Report files the tools write into the project; they are output, not sources.
const SKIP_FILE_PREFIXES: [&str; 1] = ["aderyn-report"];
/// Bounds on the source digest walk. Past them the digest is `None` (never a partial digest).
const MAX_SOURCE_FILES: usize = 20_000;
const MAX_SOURCE_BYTES: u64 = 512 * 1024 * 1024;
/// Bounds on the forge artifact scan.
const MAX_ARTIFACTS: usize = 2048;
const MAX_ARTIFACT_BYTES: u64 = 32 * 1024 * 1024;
/// medusa's lcov report is kept up to this size; a larger one is left out. With the 4 MiB stdout
/// cap this keeps a result well inside the worker protocol's 32 MiB line.
const MAX_LCOV_BYTES: u64 = 4 * 1024 * 1024;
/// The renderer's provenance record (citrate-templates), read for medusa's default budget.
pub const TEMPLATE_LOCK_FILE: &str = "citrate-template.lock.json";
/// Reports kept per session (oldest dropped first): four tools on four projects.
pub const MAX_REPORTS: usize = 16;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn skipped(name: &str, is_dir: bool) -> bool {
    if is_dir {
        SKIP_DIRS.contains(&name)
    } else {
        SKIP_FILE_PREFIXES.iter().any(|p| name.starts_with(p))
    }
}

/// SHA-256 over the project's sources: every regular file below `project` (sorted by relative
/// path), except build output, caches, git history and the tools' own reports. Each file adds
/// `path NUL length(8 bytes, BE) content`; a symlink adds `path NUL "->" target` and is not
/// followed. `None` when the walk fails or passes its bounds.
pub fn sources_sha256(project: &Path) -> Option<String> {
    let mut files: Vec<(String, PathBuf, bool)> = Vec::new();
    let mut stack = vec![project.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).ok()? {
            let entry = entry.ok()?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let ft = entry.file_type().ok()?;
            if skipped(&name, ft.is_dir()) {
                continue;
            }
            let rel = path
                .strip_prefix(project)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            if ft.is_symlink() {
                files.push((rel, path, true));
            } else if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                files.push((rel, path, false));
            }
            if files.len() > MAX_SOURCE_FILES {
                return None;
            }
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = Sha256::new();
    let mut total = 0u64;
    for (rel, path, link) in files {
        h.update(rel.as_bytes());
        h.update([0u8]);
        if link {
            let target = std::fs::read_link(&path).ok()?;
            h.update(b"->");
            h.update(target.to_string_lossy().as_bytes());
            continue;
        }
        let bytes = std::fs::read(&path).ok()?;
        total = total.checked_add(bytes.len() as u64)?;
        if total > MAX_SOURCE_BYTES {
            return None;
        }
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(&bytes);
    }
    Some(hex(&h.finalize()))
}

/// SHA-256 of a creation bytecode as forge writes it (`0x`-hex), over the lower-case hex without
/// the prefix. `None` for an empty bytecode (interfaces, abstract contracts) or non-hex text.
pub fn bytecode_digest(object: &str) -> Option<String> {
    let t = object.trim();
    let t = t.strip_prefix("0x").unwrap_or(t);
    if t.is_empty() || !t.len().is_multiple_of(2) || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(hex(&Sha256::digest(t.to_ascii_lowercase().as_bytes())))
}

fn read_bounded(path: &Path, max: u64) -> Option<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > max {
        return None;
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    std::fs::File::open(path)
        .ok()?
        .take(max)
        .read_to_end(&mut buf)
        .ok()?;
    Some(buf)
}

/// The creation bytecode digest of every artifact under `<project>/out/` (`<File>.sol/<Name>.json`,
/// one level, `build-info` skipped). Artifacts without bytecode are left out.
pub fn forge_artifacts(project: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(dirs) = std::fs::read_dir(project.join("out")) else {
        return out;
    };
    let mut dirs: Vec<PathBuf> = dirs
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.path())
        .filter(|p| p.file_name().is_some_and(|n| n != "build-info"))
        .collect();
    dirs.sort();
    for dir in dirs {
        let Ok(files) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut files: Vec<PathBuf> = files
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        files.sort();
        for f in files {
            if out.len() >= MAX_ARTIFACTS {
                return out;
            }
            let Some(bytes) = read_bounded(&f, MAX_ARTIFACT_BYTES) else {
                continue;
            };
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                continue;
            };
            let Some(digest) = v
                .pointer("/bytecode/object")
                .and_then(|o| o.as_str())
                .and_then(bytecode_digest)
            else {
                continue;
            };
            let (Some(d), Some(n)) = (dir.file_name(), f.file_name()) else {
                continue;
            };
            out.insert(
                format!("{}/{}", d.to_string_lossy(), n.to_string_lossy()),
                digest,
            );
        }
    }
    out
}

/// A plain relative path (no `..`, no root, not empty).
fn plain_relative(s: &str) -> Option<PathBuf> {
    let p = PathBuf::from(s);
    let ok = !s.is_empty() && p.components().all(|c| matches!(c, Component::Normal(_)));
    ok.then_some(p)
}

/// medusa's lcov report for this project when the run that ended just now wrote it (modified at
/// or after `since`). The corpus folder comes from `medusa.json` (`fuzzing.corpusDirectory`,
/// a plain relative path; default `medusa-corpus`).
pub fn medusa_lcov(project: &Path, since: SystemTime) -> Option<String> {
    let corpus = read_bounded(&project.join("medusa.json"), 1024 * 1024)
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| {
            v.pointer("/fuzzing/corpusDirectory")
                .and_then(|c| c.as_str())
                .map(str::to_string)
        })
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| "medusa-corpus".to_string());
    let corpus = plain_relative(&corpus)?;
    let path = project.join(corpus).join("coverage").join("lcov.info");
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if meta.modified().ok()? < since {
        return None;
    }
    let bytes = read_bounded(&path, MAX_LCOV_BYTES)?;
    String::from_utf8(bytes).ok()
}

/// The medusa call budget the template renderer recorded for this project (its
/// `citrate-template.lock.json`, or the parent folder's for an included contract project such as
/// hello-mint's `contracts/`). Only a convenience default for `medusa_fuzz`: the deploy gate in
/// core enforces the member's tier budget on its own.
pub fn lock_test_limit(project: &Path) -> Option<u64> {
    let read = |dir: &Path| -> Option<u64> {
        let bytes = read_bounded(&dir.join(TEMPLATE_LOCK_FILE), 1024 * 1024)?;
        let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        let own = v
            .pointer("/medusa_budget/test_limit")
            .and_then(|t| t.as_u64());
        let included = || {
            v.get("includes")?.as_array()?.iter().find_map(|inc| {
                inc.pointer("/medusa_budget/test_limit")
                    .and_then(|t| t.as_u64())
            })
        };
        own.or_else(included)
    };
    read(project).or_else(|| project.parent().and_then(read))
}

/// One kept report, as core reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoredReport {
    /// Increases with every report this session keeps.
    pub seq: u64,
    pub tool: String,
    /// The canonical project folder.
    pub project: String,
    pub status: RunStatus,
    /// The one-line summary the model saw.
    pub summary: String,
    pub captured_at_ms: u64,
    /// Present when the program ran to completion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate: Option<GateReport>,
}

#[derive(Default)]
struct Inner {
    next: u64,
    /// (project, tool) → report.
    latest: BTreeMap<(String, String), StoredReport>,
}

/// One session's latest toolchain report per (project, tool).
#[derive(Default)]
pub struct ToolchainReports {
    inner: Mutex<Inner>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

impl ToolchainReports {
    /// Keep `report`, replacing the earlier one for its (project, tool). Past [`MAX_REPORTS`]
    /// the oldest is dropped.
    fn keep(&self, mut report: StoredReport) {
        let Ok(mut g) = self.inner.lock() else {
            return;
        };
        g.next += 1;
        report.seq = g.next;
        g.latest
            .insert((report.project.clone(), report.tool.clone()), report);
        while g.latest.len() > MAX_REPORTS {
            let oldest = g
                .latest
                .iter()
                .min_by_key(|(_, r)| r.seq)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    g.latest.remove(&k);
                }
                None => break,
            }
        }
    }

    /// Every kept report, oldest first; only those for `project` when given (compared as a
    /// canonical path).
    pub fn list(&self, project: Option<&str>) -> Vec<StoredReport> {
        let want = project.map(|p| {
            std::fs::canonicalize(p)
                .map(|c| c.to_string_lossy().into_owned())
                .unwrap_or_else(|_| p.to_string())
        });
        let Ok(g) = self.inner.lock() else {
            return Vec::new();
        };
        let mut out: Vec<StoredReport> = g
            .latest
            .values()
            .filter(|r| want.as_deref().is_none_or(|w| r.project == w))
            .cloned()
            .collect();
        out.sort_by_key(|r| r.seq);
        out
    }
}

/// The project folder a toolchain call named, made canonical when it exists.
fn call_project(call: &ToolCall) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(&call.arguments).ok()?;
    let p = v.get("project")?.as_str()?.trim();
    if p.is_empty() || !Path::new(p).is_absolute() {
        return None;
    }
    Some(
        std::fs::canonicalize(p)
            .map(|c| c.to_string_lossy().into_owned())
            .unwrap_or_else(|_| p.to_string()),
    )
}

/// Take the gate report out of a toolchain result: keep it in `reports`, hand the model the
/// envelope without it. A result that is not a toolchain envelope passes through unchanged.
pub fn capture(reports: &ToolchainReports, call: &ToolCall, outcome: ToolOutcome) -> ToolOutcome {
    let (content, is_err) = match &outcome {
        ToolOutcome::Ok(c) => (c.as_str(), false),
        ToolOutcome::Error(c) => (c.as_str(), true),
        ToolOutcome::Untrusted(_) | ToolOutcome::Denied(_) => return outcome,
    };
    let Ok(mut env) = ToolchainEnvelope::from_content(content) else {
        return outcome;
    };
    let gate = env.gate.take();
    let project = gate
        .as_ref()
        .map(|g| g.project.clone())
        .or_else(|| call_project(call));
    // A refused call (bad arguments, a folder outside the grants) is not a run of the project.
    if let Some(project) = project.filter(|_| env.status != RunStatus::Refused) {
        reports.keep(StoredReport {
            seq: 0,
            tool: env.tool.clone(),
            project,
            status: env.status,
            summary: env.summary.clone(),
            captured_at_ms: now_ms(),
            gate,
        });
    }
    let content = env.to_content();
    if is_err {
        ToolOutcome::Error(content)
    } else {
        ToolOutcome::Ok(content)
    }
}

/// A session's toolchain host that keeps each run's gate report (see [`capture`]).
pub struct CapturingToolchain {
    inner: std::sync::Arc<dyn ToolHost>,
    reports: std::sync::Arc<ToolchainReports>,
}

impl CapturingToolchain {
    pub fn new(
        inner: std::sync::Arc<dyn ToolHost>,
        reports: std::sync::Arc<ToolchainReports>,
    ) -> Self {
        CapturingToolchain { inner, reports }
    }
}

impl ToolHost for CapturingToolchain {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        let outcome = self.inner.execute(call);
        if !ToolchainHost::handles(&call.name) {
            return outcome;
        }
        capture(&self.reports, call, outcome)
    }
}
