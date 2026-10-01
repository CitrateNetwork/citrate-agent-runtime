//! HUP-S9.3 (sidecar wiring): verified trajectories, **off by default**.
//!
//! Only when `CITRATE_HERMES_TRAJECTORIES` names an absolute directory does a session attach a
//! [`TrajectoryRecorder`]. When the session closes, its turns go through
//! [`citrate_agent_trajectory::export_verified`]: only answered turns that every verifier passed
//! are kept, every turn of a session that read untrusted content is dropped, and what is kept is
//! redacted. Exporting at close (not per turn) is what lets a taint that arrives late still
//! exclude the session's earlier turns.
//!
//! Files: `<session>-<unix_ms>.report.json` (counts only, never content) always, and
//! `<session>-<unix_ms>.jsonl` (the redacted examples) only when at least one turn qualified. Both
//! are created new (never overwritten) and readable only by their owner on Unix. Nothing here
//! uploads anything: D-29 needs the member's consent for each training round, which is separate.

use std::path::{Path, PathBuf};

use citrate_agent_loop::Message;
use citrate_agent_trajectory::{export_verified, ExportPolicy, TrajectoryRecorder};
use serde::Serialize;

/// The opt-in: an absolute directory for exported trajectories. Unset: no recorder is attached.
pub const TRAJECTORIES_ENV: &str = "CITRATE_HERMES_TRAJECTORIES";

/// Where exports go and which folders count as granted (paths inside them are kept as
/// `[root:N]/...`; any other absolute path is redacted).
#[derive(Debug, Clone)]
pub struct TrajectoryConfig {
    dir: PathBuf,
    granted_roots: Vec<PathBuf>,
    home: Option<PathBuf>,
}

impl TrajectoryConfig {
    pub fn new(dir: PathBuf) -> Self {
        TrajectoryConfig {
            dir,
            granted_roots: Vec::new(),
            home: None,
        }
    }

    pub fn with_granted_roots(mut self, roots: Vec<PathBuf>) -> Self {
        self.granted_roots = roots;
        self
    }

    pub fn with_home(mut self, home: Option<PathBuf>) -> Self {
        self.home = home;
        self
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Only an explicit, absolute directory turns recording on.
    pub fn from_value(value: Option<&str>) -> Option<Self> {
        let v = value?.trim();
        if v.is_empty() {
            return None;
        }
        let dir = PathBuf::from(v);
        dir.is_absolute().then(|| TrajectoryConfig::new(dir))
    }

    /// [`TrajectoryConfig::from_value`] over the environment, with the toolchain's granted folders
    /// (`CITRATE_HERMES_TOOLCHAIN_ROOTS`) and `HOME` for path redaction.
    pub fn from_env() -> Option<Self> {
        let cfg = Self::from_value(std::env::var(TRAJECTORIES_ENV).ok().as_deref())?;
        let roots = std::env::var_os("CITRATE_HERMES_TOOLCHAIN_ROOTS")
            .map(|v| {
                std::env::split_paths(&v)
                    .filter(|p| p.is_absolute())
                    .collect()
            })
            .unwrap_or_default();
        Some(
            cfg.with_granted_roots(roots)
                .with_home(std::env::var_os("HOME").map(PathBuf::from)),
        )
    }

    fn policy(&self) -> ExportPolicy {
        let mut p = ExportPolicy::new();
        for r in &self.granted_roots {
            p = p.with_granted_root(r.clone());
        }
        if let Some(h) = &self.home {
            p = p.with_home(h.clone());
        }
        p
    }
}

/// What a close-time export did. Counts only.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportSummary {
    pub considered: u32,
    pub exported: u32,
    pub unverified: u32,
    pub verifier_failed: u32,
    pub not_answered: u32,
    pub tainted_session: u32,
    pub redactions: u32,
    pub report_file: String,
    /// `None` when no turn qualified (no examples file is written).
    pub examples_file: Option<String>,
    /// Set when the export could not be completed (no content in the message).
    pub error: Option<String>,
}

fn file_name_safe(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn write_new(path: &Path, body: &str) -> Result<(), String> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("could not create {}: {}", path.display(), e.kind()))?;
    f.write_all(body.as_bytes())
        .map_err(|e| format!("could not write {}: {}", path.display(), e.kind()))
}

/// Export one closing session. `history` is the session's history since the recorder attached
/// (sessions attach it at creation, so the whole history).
pub fn export_session(
    cfg: &TrajectoryConfig,
    recorder: &TrajectoryRecorder,
    history: &[Message],
    session_id: &str,
    now_ms: u64,
) -> ExportSummary {
    let stem = format!("{}-{now_ms}", file_name_safe(session_id));
    let report_path = cfg.dir.join(format!("{stem}.report.json"));
    let examples_path = cfg.dir.join(format!("{stem}.jsonl"));
    let mut s = ExportSummary {
        considered: 0,
        exported: 0,
        unverified: 0,
        verifier_failed: 0,
        not_answered: 0,
        tainted_session: 0,
        redactions: 0,
        report_file: report_path.display().to_string(),
        examples_file: None,
        error: None,
    };
    let result = (|| -> Result<(), String> {
        std::fs::create_dir_all(&cfg.dir)
            .map_err(|e| format!("could not create the trajectory folder: {}", e.kind()))?;
        let trajectories = recorder.trajectories(history).map_err(|e| e.to_string())?;
        let export = export_verified(&trajectories, &cfg.policy()).map_err(|e| e.to_string())?;
        let r = &export.report;
        s.considered = r.considered;
        s.exported = r.exported;
        s.unverified = r.excluded.unverified;
        s.verifier_failed = r.excluded.verifier_failed;
        s.not_answered = r.excluded.not_answered;
        s.tainted_session = r.excluded.tainted_session;
        s.redactions = r.totals.total();
        let report = serde_json::to_string_pretty(r).map_err(|e| e.to_string())?;
        write_new(&report_path, &report)?;
        if r.exported > 0 {
            export
                .write_jsonl(&examples_path)
                .map_err(|e| e.to_string())?;
            s.examples_file = Some(examples_path.display().to_string());
        }
        Ok(())
    })();
    if let Err(e) = result {
        eprintln!("citrate-agent-sidecar: trajectory export failed: {e}");
        s.error = Some(e);
    }
    s
}
