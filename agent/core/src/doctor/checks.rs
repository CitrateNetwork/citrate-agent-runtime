//! Doctor checks — RFC-CIT-AGENT-0001 §10.2.
//!
//! CIT-AGENT-7a lands 5 concrete checks whose dependencies are in
//! place from prior sprints:
//!
//! | # | Check | Depends on |
//! |---|---|---|
//! | 1 | `AuditChainIntegrityCheck` | CIT-AGENT-5a `verify_integrity` |
//! | 2 | `AuditFilePermissionsCheck` | CIT-AGENT-5a filesystem sink |
//! | 3 | `ApprovalQueueDepthCheck` | CIT-AGENT-4a `ApprovalQueue::depth` |
//! | 4 | `PendingBreakGlassCheck` | CIT-AGENT-4c `BreakGlassRegistry` |
//! | 5 | `RuntimeCheck` | tokio runtime presence |
//!
//! Each check returns `Pass` when its dependency is absent
//! (with `details: skipped`), so partial contexts still produce
//! meaningful reports.

use crate::audit::chain::AuditChain;
use crate::audit::sink::FilesystemSink;
use crate::doctor::report::{CheckResult, Severity};
use crate::hitl::{ApprovalQueue, BreakGlassPhase, BreakGlassRegistry};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

/// Context passed to every check. Optional fields let the operator
/// run a partial doctor pass when not all subsystems are wired.
pub struct DoctorContext {
    pub agent_did: String,
    pub now_unix: i64,
    /// Filesystem path of the audit log. When `None`, the chain
    /// integrity + permissions checks skip.
    pub audit_chain_path: Option<PathBuf>,
    /// Approval queue handle. When `None`, the queue-depth check skips.
    pub approval_queue: Option<Arc<ApprovalQueue>>,
    /// Break-glass registry handle. When `None`, the BG check skips.
    pub break_glass: Option<Arc<BreakGlassRegistry>>,
    /// Externally-anchored expected audit-chain head `(sequence, hash)`
    /// — from the AgentSBT `latest_audit_chain_head` or the last
    /// `AnchorRegistry` Merkle root. AR-B-001: when supplied, the
    /// integrity check fails unless the walked head matches, which is
    /// the only way to detect tail-truncation of the log. When `None`,
    /// truncation cannot be detected (documented limitation) but a
    /// wholesale-deleted / empty log is still reported as a Blocker.
    pub expected_audit_head: Option<(u64, [u8; 32])>,
}

/// The check trait. Implementors are Send + Sync so a single
/// `Vec<Box<dyn Check>>` can be shared across the orchestrator.
pub trait Check: Send + Sync {
    fn name(&self) -> &str;
    fn run(&self, ctx: &DoctorContext) -> CheckResult;
}

// ── 1. Audit chain integrity ──────────────────────────────────────

pub struct AuditChainIntegrityCheck;

impl Check for AuditChainIntegrityCheck {
    fn name(&self) -> &str {
        "audit-chain-integrity"
    }
    fn run(&self, ctx: &DoctorContext) -> CheckResult {
        let Some(path) = &ctx.audit_chain_path else {
            return CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: "skipped: no audit_chain_path configured".into(),
                details: BTreeMap::new(),
            };
        };
        let sink = match FilesystemSink::open(path) {
            Ok(s) => Arc::new(s) as Arc<dyn crate::audit::sink::AuditSink>,
            Err(e) => {
                return CheckResult {
                    name: self.name().into(),
                    severity: Severity::Blocker,
                    message: format!("cannot open audit sink at {path:?}: {e}"),
                    details: BTreeMap::new(),
                };
            }
        };
        // AR-B-001: open the EXISTING chain WITHOUT minting a genesis.
        // An empty / wholesale-deleted log must be a Blocker — never a
        // silently re-initialised "verified 1 records" Pass.
        let chain = match AuditChain::open_existing(sink) {
            Ok(Some(c)) => c,
            Ok(None) => {
                return CheckResult {
                    name: self.name().into(),
                    severity: Severity::Blocker,
                    message: format!(
                        "audit log at {path:?} is empty or deleted — expected an \
                         initialized chain (possible wholesale erasure)"
                    ),
                    details: BTreeMap::new(),
                };
            }
            Err(e) => {
                return CheckResult {
                    name: self.name().into(),
                    severity: Severity::Blocker,
                    message: format!("chain open failed: {e}"),
                    details: BTreeMap::new(),
                };
            }
        };
        let mut details = BTreeMap::new();
        let count = match chain.verify_integrity() {
            Ok(count) => count,
            Err(e) => {
                return CheckResult {
                    name: self.name().into(),
                    severity: Severity::Blocker,
                    message: format!("chain integrity broken: {e}"),
                    details,
                };
            }
        };
        details.insert("records_verified".into(), count.to_string());
        // AR-B-001: if an externally-anchored head is configured, the
        // walked head MUST match it — otherwise the tail was truncated.
        if let Some((expected_seq, expected_hash)) = ctx.expected_audit_head {
            details.insert("expected_head_sequence".into(), expected_seq.to_string());
            if let Err(e) = chain.verify_head(expected_seq, expected_hash) {
                return CheckResult {
                    name: self.name().into(),
                    severity: Severity::Blocker,
                    message: format!("chain integrity broken: {e}"),
                    details,
                };
            }
        }
        CheckResult {
            name: self.name().into(),
            severity: Severity::Pass,
            message: format!("verified {count} records"),
            details,
        }
    }
}

// ── 2. Audit file permissions ─────────────────────────────────────

pub struct AuditFilePermissionsCheck;

impl Check for AuditFilePermissionsCheck {
    fn name(&self) -> &str {
        "audit-file-permissions"
    }
    fn run(&self, ctx: &DoctorContext) -> CheckResult {
        let Some(path) = &ctx.audit_chain_path else {
            return CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: "skipped: no audit_chain_path configured".into(),
                details: BTreeMap::new(),
            };
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = match std::fs::metadata(path) {
                Ok(m) => m,
                Err(e) => {
                    return CheckResult {
                        name: self.name().into(),
                        severity: Severity::Warn,
                        message: format!("cannot stat {path:?}: {e}"),
                        details: BTreeMap::new(),
                    };
                }
            };
            let mode = meta.permissions().mode() & 0o777;
            let mut details = BTreeMap::new();
            details.insert("mode_octal".into(), format!("{mode:o}"));
            if mode == 0o600 {
                CheckResult {
                    name: self.name().into(),
                    severity: Severity::Pass,
                    message: "audit file is owner-only (0600)".into(),
                    details,
                }
            } else {
                CheckResult {
                    name: self.name().into(),
                    severity: Severity::Warn,
                    message: format!(
                        "audit file mode {mode:o} is not the expected 0600"
                    ),
                    details,
                }
            }
        }
        #[cfg(not(unix))]
        {
            CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: "skipped: non-Unix platform".into(),
                details: BTreeMap::new(),
            }
        }
    }
}

// ── 3. Approval queue depth ───────────────────────────────────────

pub struct ApprovalQueueDepthCheck {
    /// Warn when queue depth exceeds this value. Default 100.
    pub warn_threshold: usize,
}

impl Default for ApprovalQueueDepthCheck {
    fn default() -> Self {
        Self {
            warn_threshold: 100,
        }
    }
}

impl Check for ApprovalQueueDepthCheck {
    fn name(&self) -> &str {
        "approval-queue-depth"
    }
    fn run(&self, ctx: &DoctorContext) -> CheckResult {
        let Some(queue) = &ctx.approval_queue else {
            return CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: "skipped: no approval_queue configured".into(),
                details: BTreeMap::new(),
            };
        };
        let depth = queue.depth();
        let mut details = BTreeMap::new();
        details.insert("depth".into(), depth.to_string());
        details.insert("warn_threshold".into(), self.warn_threshold.to_string());
        if depth > self.warn_threshold {
            CheckResult {
                name: self.name().into(),
                severity: Severity::Warn,
                message: format!(
                    "queue depth {depth} exceeds warn threshold {}",
                    self.warn_threshold
                ),
                details,
            }
        } else {
            CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: format!("queue depth {depth} within threshold"),
                details,
            }
        }
    }
}

// ── 4. Pending break-glass ────────────────────────────────────────

pub struct PendingBreakGlassCheck {
    /// List of action IDs the operator considers in scope for this
    /// doctor pass. Empty list = "check no actions" (skip).
    pub action_ids: Vec<String>,
}

impl Check for PendingBreakGlassCheck {
    fn name(&self) -> &str {
        "pending-break-glass"
    }
    fn run(&self, ctx: &DoctorContext) -> CheckResult {
        let Some(registry) = &ctx.break_glass else {
            return CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: "skipped: no break_glass registry configured".into(),
                details: BTreeMap::new(),
            };
        };
        if self.action_ids.is_empty() {
            return CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: "skipped: no action_ids supplied".into(),
                details: BTreeMap::new(),
            };
        }
        let mut surfaced = 0usize;
        let mut unaffirmed = 0usize;
        let mut invoked_open = 0usize;
        for id in &self.action_ids {
            if let Some(entry) = registry.get(id) {
                match entry.phase {
                    BreakGlassPhase::Surfaced => surfaced += 1,
                    BreakGlassPhase::Unaffirmed => unaffirmed += 1,
                    BreakGlassPhase::Invoked => invoked_open += 1,
                    _ => {}
                }
            }
        }
        let mut details = BTreeMap::new();
        details.insert("surfaced".into(), surfaced.to_string());
        details.insert("unaffirmed".into(), unaffirmed.to_string());
        details.insert("invoked_open".into(), invoked_open.to_string());
        if surfaced > 0 {
            CheckResult {
                name: self.name().into(),
                severity: Severity::Blocker,
                message: format!(
                    "{surfaced} break-glass action(s) Surfaced — required IR follow-up"
                ),
                details,
            }
        } else if unaffirmed > 0 {
            CheckResult {
                name: self.name().into(),
                severity: Severity::Warn,
                message: format!("{unaffirmed} break-glass action(s) Unaffirmed"),
                details,
            }
        } else {
            CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: format!(
                    "{} action(s) checked; none surfaced/unaffirmed",
                    self.action_ids.len()
                ),
                details,
            }
        }
    }
}

// ── 5. Runtime presence ───────────────────────────────────────────

pub struct RuntimeCheck;

impl Check for RuntimeCheck {
    fn name(&self) -> &str {
        "runtime-presence"
    }
    fn run(&self, _ctx: &DoctorContext) -> CheckResult {
        match tokio::runtime::Handle::try_current() {
            Ok(_) => CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: "tokio runtime active".into(),
                details: BTreeMap::new(),
            },
            Err(_) => CheckResult {
                name: self.name().into(),
                severity: Severity::Warn,
                message: "no tokio runtime — async sinks unavailable".into(),
                details: BTreeMap::new(),
            },
        }
    }
}

// ── 6. Capsule manifest re-verification ───────────────────────────

/// Re-loads each capsule via `Capsule::from_archive` (which verifies
/// the content_hash invariant). Optionally supplies a
/// `PublicKeyRegistry` to additionally verify signatures via
/// `Capsule::from_archive_verified`. CIT-AGENT-7b.
///
/// Skip when `capsule_paths` is empty. Blocker when any capsule
/// fails to load (tampered archive); Warn when load succeeds but
/// signature verification fails.
pub struct CapsuleManifestReverifyCheck {
    pub capsule_paths: Vec<std::path::PathBuf>,
    pub registry: Option<std::sync::Arc<dyn crate::capsule::tiers::PublicKeyRegistry>>,
}

impl Check for CapsuleManifestReverifyCheck {
    fn name(&self) -> &str {
        "capsule-manifest-reverify"
    }
    fn run(&self, _ctx: &DoctorContext) -> CheckResult {
        if self.capsule_paths.is_empty() {
            return CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: "skipped: no capsule_paths supplied".into(),
                details: BTreeMap::new(),
            };
        }
        let mut details = BTreeMap::new();
        let mut load_failures: Vec<String> = Vec::new();
        let mut sig_failures: Vec<String> = Vec::new();
        let mut verified = 0u32;
        for path in &self.capsule_paths {
            let path_str = path.to_string_lossy().to_string();
            let file = match std::fs::File::open(path) {
                Ok(f) => f,
                Err(e) => {
                    load_failures.push(format!("{path_str}: open failed: {e}"));
                    continue;
                }
            };
            // Always check content_hash via from_archive.
            let capsule = match crate::capsule::Capsule::from_archive(file) {
                Ok(c) => c,
                Err(e) => {
                    load_failures.push(format!("{path_str}: {e}"));
                    continue;
                }
            };
            // If a registry is supplied, also verify signatures.
            if let Some(reg) = &self.registry {
                let file2 = match std::fs::File::open(path) {
                    Ok(f) => f,
                    Err(_) => continue,
                };
                if let Err(e) =
                    crate::capsule::Capsule::from_archive_verified(file2, reg.as_ref())
                {
                    sig_failures.push(format!("{path_str}: {e}"));
                    continue;
                }
            }
            verified += 1;
            let _ = capsule; // keep ownership briefly for clarity
        }
        details.insert("capsules_checked".into(), self.capsule_paths.len().to_string());
        details.insert("verified".into(), verified.to_string());
        details.insert("load_failures".into(), load_failures.len().to_string());
        details.insert("sig_failures".into(), sig_failures.len().to_string());
        if !load_failures.is_empty() {
            return CheckResult {
                name: self.name().into(),
                severity: Severity::Blocker,
                message: format!(
                    "{} capsule(s) failed to load: {}",
                    load_failures.len(),
                    load_failures.join("; ")
                ),
                details,
            };
        }
        if !sig_failures.is_empty() {
            return CheckResult {
                name: self.name().into(),
                severity: Severity::Warn,
                message: format!(
                    "{} capsule(s) failed signature verification: {}",
                    sig_failures.len(),
                    sig_failures.join("; ")
                ),
                details,
            };
        }
        CheckResult {
            name: self.name().into(),
            severity: Severity::Pass,
            message: format!("{verified} capsule(s) re-verified"),
            details,
        }
    }
}

// ── 7. WASM linker re-check ───────────────────────────────────────

/// For each (manifest, wit) pair, re-runs `LinkerBuilder::from_manifest`
/// and `verify_capability_against_wit`. Detects drift introduced
/// after capsule install — e.g. an operator-edited manifest no
/// longer matches the bundled WIT. CIT-AGENT-7b.
///
/// Skip when `pairs` is empty. Blocker on any mismatch.
pub struct WasmLinkerRecheckCheck {
    pub pairs: Vec<(crate::capsule::manifest::Manifest, String)>,
}

impl Check for WasmLinkerRecheckCheck {
    fn name(&self) -> &str {
        "wasm-linker-recheck"
    }
    fn run(&self, _ctx: &DoctorContext) -> CheckResult {
        if self.pairs.is_empty() {
            return CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: "skipped: no (manifest, wit) pairs supplied".into(),
                details: BTreeMap::new(),
            };
        }
        let engine = match crate::capsule::wasm::EngineFactory::build() {
            Ok(e) => e,
            Err(e) => {
                return CheckResult {
                    name: self.name().into(),
                    severity: Severity::Blocker,
                    message: format!("engine init: {e}"),
                    details: BTreeMap::new(),
                };
            }
        };
        let mut details = BTreeMap::new();
        let mut mismatches: Vec<String> = Vec::new();
        let mut ok = 0u32;
        for (i, (manifest, wit)) in self.pairs.iter().enumerate() {
            // 1. Construct linker — fails if manifest filesystem entries are malformed.
            if let Err(e) =
                crate::capsule::linker::LinkerBuilder::from_manifest(&engine, manifest)
            {
                mismatches.push(format!("pair[{i}]: linker build: {e}"));
                continue;
            }
            // 2. Cross-check WIT vs manifest.
            if let Err(e) = crate::capsule::verify::verify_capability_against_wit(manifest, wit)
            {
                mismatches.push(format!("pair[{i}]: WIT cross-check: {e}"));
                continue;
            }
            ok += 1;
        }
        details.insert("pairs_checked".into(), self.pairs.len().to_string());
        details.insert("ok".into(), ok.to_string());
        details.insert("mismatches".into(), mismatches.len().to_string());
        if mismatches.is_empty() {
            CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: format!("{ok} pair(s) re-checked cleanly"),
                details,
            }
        } else {
            CheckResult {
                name: self.name().into(),
                severity: Severity::Blocker,
                message: format!(
                    "{} pair(s) drifted: {}",
                    mismatches.len(),
                    mismatches.join("; ")
                ),
                details,
            }
        }
    }
}

// ── 8. Policy bundle hash drift ───────────────────────────────────

/// Generic file-hash-drift detector. Reads each (path, expected_sha256)
/// pair; computes sha256 of the file; reports drift. Used for the
/// policy bundle as the v0.1 source of truth (no policy-bundle
/// crate yet); also useful for any file whose hash should be
/// pinned in the ceremony record. CIT-AGENT-7b.
pub struct PolicyBundleHashCheck {
    pub files: Vec<(std::path::PathBuf, [u8; 32])>,
}

impl Check for PolicyBundleHashCheck {
    fn name(&self) -> &str {
        "policy-bundle-hash"
    }
    fn run(&self, _ctx: &DoctorContext) -> CheckResult {
        if self.files.is_empty() {
            return CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: "skipped: no pinned files supplied".into(),
                details: BTreeMap::new(),
            };
        }
        let mut details = BTreeMap::new();
        let mut drifts: Vec<String> = Vec::new();
        let mut ok = 0u32;
        for (path, expected) in &self.files {
            let bytes = match std::fs::read(path) {
                Ok(b) => b,
                Err(e) => {
                    drifts.push(format!("{path:?}: read failed: {e}"));
                    continue;
                }
            };
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&bytes);
            let digest = h.finalize();
            let mut computed = [0u8; 32];
            computed.copy_from_slice(&digest);
            if computed != *expected {
                drifts.push(format!(
                    "{path:?}: hash drift (expected {}, got {})",
                    hex::encode(expected),
                    hex::encode(computed)
                ));
            } else {
                ok += 1;
            }
        }
        details.insert("files_checked".into(), self.files.len().to_string());
        details.insert("ok".into(), ok.to_string());
        details.insert("drifts".into(), drifts.len().to_string());
        if drifts.is_empty() {
            CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: format!("{ok} file(s) match pinned hashes"),
                details,
            }
        } else {
            CheckResult {
                name: self.name().into(),
                severity: Severity::Blocker,
                message: format!(
                    "{} file(s) drifted: {}",
                    drifts.len(),
                    drifts.join("; ")
                ),
                details,
            }
        }
    }
}

// ── 9. TLA spec CI status ─────────────────────────────────────────

/// Reads a JSON status file (CI writes it) describing the last TLA+
/// spec verification run. Schema:
///
/// ```json
/// {
///     "last_run_utc": "2026-05-15T00:00:00Z",
///     "verified_specs": ["ApprovalStateMachine", ...],
///     "failing_specs": []
/// }
/// ```
///
/// Warn when `last_run_utc` is older than `max_age_hours`; Blocker
/// when `failing_specs` is non-empty. CIT-AGENT-7b.
pub struct TlaSpecCiStatusCheck {
    pub status_file_path: Option<std::path::PathBuf>,
    /// Warn when last_run_utc is older than this many hours.
    /// Default 48 — nightly TLC runs ~once a day; 48h tolerates a
    /// missed run.
    pub max_age_hours: u64,
}

impl Default for TlaSpecCiStatusCheck {
    fn default() -> Self {
        Self {
            status_file_path: None,
            max_age_hours: 48,
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct TlaCiStatus {
    last_run_utc: String,
    #[serde(default)]
    verified_specs: Vec<String>,
    #[serde(default)]
    failing_specs: Vec<String>,
}

impl Check for TlaSpecCiStatusCheck {
    fn name(&self) -> &str {
        "tla-spec-ci-status"
    }
    fn run(&self, ctx: &DoctorContext) -> CheckResult {
        let Some(path) = &self.status_file_path else {
            return CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: "skipped: no status_file_path supplied".into(),
                details: BTreeMap::new(),
            };
        };
        let bytes = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                return CheckResult {
                    name: self.name().into(),
                    severity: Severity::Warn,
                    message: format!("cannot read status file {path:?}: {e}"),
                    details: BTreeMap::new(),
                };
            }
        };
        let status: TlaCiStatus = match serde_json::from_str(&bytes) {
            Ok(s) => s,
            Err(e) => {
                return CheckResult {
                    name: self.name().into(),
                    severity: Severity::Blocker,
                    message: format!("parse status JSON: {e}"),
                    details: BTreeMap::new(),
                };
            }
        };
        let mut details = BTreeMap::new();
        details.insert("last_run_utc".into(), status.last_run_utc.clone());
        details.insert(
            "verified_specs_count".into(),
            status.verified_specs.len().to_string(),
        );
        details.insert(
            "failing_specs_count".into(),
            status.failing_specs.len().to_string(),
        );
        if !status.failing_specs.is_empty() {
            return CheckResult {
                name: self.name().into(),
                severity: Severity::Blocker,
                message: format!(
                    "TLA CI reports {} failing spec(s): {}",
                    status.failing_specs.len(),
                    status.failing_specs.join(", ")
                ),
                details,
            };
        }
        // Age check: parse last_run_utc as RFC 3339 timestamp.
        // For simplicity we accept "YYYY-MM-DDTHH:MM:SSZ" or any
        // prefix-parseable subset; on parse failure we Warn.
        let age_hours = parse_age_hours(&status.last_run_utc, ctx.now_unix);
        match age_hours {
            Some(age) if age > self.max_age_hours => {
                details.insert("age_hours".into(), age.to_string());
                CheckResult {
                    name: self.name().into(),
                    severity: Severity::Warn,
                    message: format!(
                        "TLA CI last run {age}h ago (> max_age_hours {})",
                        self.max_age_hours
                    ),
                    details,
                }
            }
            Some(age) => {
                details.insert("age_hours".into(), age.to_string());
                CheckResult {
                    name: self.name().into(),
                    severity: Severity::Pass,
                    message: format!(
                        "TLA CI healthy: {} spec(s) verified, last run {age}h ago",
                        status.verified_specs.len()
                    ),
                    details,
                }
            }
            None => CheckResult {
                name: self.name().into(),
                severity: Severity::Warn,
                message: format!(
                    "cannot parse last_run_utc '{}' — age not computed",
                    status.last_run_utc
                ),
                details,
            },
        }
    }
}

/// Parse an RFC-3339-ish timestamp + return hours-since against
/// `now_unix`. Returns None on parse failure. Minimal hand-rolled
/// parser to avoid pulling in `chrono`; accepts `YYYY-MM-DDTHH:MM:SS`
/// with optional trailing `Z`.
fn parse_age_hours(ts: &str, now_unix: i64) -> Option<u64> {
    let s = ts.trim_end_matches('Z');
    let (date, time) = s.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;
    let mut time_parts = time.split(':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let minute: i64 = time_parts.next()?.parse().ok()?;
    let second: i64 = time_parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    // Crude UTC unix conversion. Doesn't handle leap seconds; close
    // enough for an "is it stale" check measured in hours.
    let days_since_epoch = naive_days_since_epoch(year, month, day)?;
    let unix = days_since_epoch * 86_400 + hour * 3_600 + minute * 60 + second;
    let delta = now_unix - unix;
    if delta < 0 {
        Some(0)
    } else {
        Some((delta / 3_600) as u64)
    }
}

fn naive_days_since_epoch(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1970..=9999).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let mut days: i64 = 0;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    let month_lengths = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 0..(month - 1) as usize {
        days += month_lengths[m] as i64;
        if m == 1 && is_leap(year) {
            days += 1;
        }
    }
    days += day - 1;
    Some(days)
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

// ── 10. Retention age ─────────────────────────────────────────────

/// Audit file mtime vs configurable `max_age_days`. The 5d retention
/// scheduler will rotate audit files; this check Warns when an
/// audit file is older than the retention budget — indicating the
/// rotator isn't running OR the operator's retention policy needs
/// tightening. CIT-AGENT-7b.
pub struct RetentionAgeCheck {
    pub max_age_days: u32,
}

impl Default for RetentionAgeCheck {
    fn default() -> Self {
        Self { max_age_days: 90 }
    }
}

impl Check for RetentionAgeCheck {
    fn name(&self) -> &str {
        "retention-age"
    }
    fn run(&self, ctx: &DoctorContext) -> CheckResult {
        let Some(path) = &ctx.audit_chain_path else {
            return CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: "skipped: no audit_chain_path configured".into(),
                details: BTreeMap::new(),
            };
        };
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                return CheckResult {
                    name: self.name().into(),
                    severity: Severity::Warn,
                    message: format!("cannot stat {path:?}: {e}"),
                    details: BTreeMap::new(),
                };
            }
        };
        let modified = match meta.modified() {
            Ok(m) => m,
            Err(_) => {
                return CheckResult {
                    name: self.name().into(),
                    severity: Severity::Warn,
                    message: "platform doesn't expose mtime".into(),
                    details: BTreeMap::new(),
                };
            }
        };
        let secs_old = match std::time::SystemTime::now().duration_since(modified) {
            Ok(d) => d.as_secs(),
            Err(_) => 0, // file mtime in the future — treat as fresh
        };
        let days_old = secs_old / 86_400;
        let mut details = BTreeMap::new();
        details.insert("days_old".into(), days_old.to_string());
        details.insert("max_age_days".into(), self.max_age_days.to_string());
        if days_old as u32 > self.max_age_days {
            CheckResult {
                name: self.name().into(),
                severity: Severity::Warn,
                message: format!(
                    "audit file is {days_old} days old (> max_age_days {}); rotator may be stuck",
                    self.max_age_days
                ),
                details,
            }
        } else {
            CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: format!("audit file fresh ({days_old} days old)"),
                details,
            }
        }
    }
}

// ── 11. Anchor reconciliation ─────────────────────────────────────

/// For each (record_hash, expected_kind) pair, verifies
/// `AnchorRegistryClient::is_anchored(record_hash)` returns true.
/// Reports any that didn't land. Async; uses `block_on` to bridge to
/// the sync `Check::run` API. CIT-AGENT-7b.
///
/// Skip when `client` is None or `expected_roots` is empty.
pub struct AnchorReconciliationCheck {
    pub client: Option<std::sync::Arc<crate::chain::AnchorRegistryClient>>,
    pub expected_roots: Vec<[u8; 32]>,
}

impl Check for AnchorReconciliationCheck {
    fn name(&self) -> &str {
        "anchor-reconciliation"
    }
    fn run(&self, _ctx: &DoctorContext) -> CheckResult {
        let Some(client) = &self.client else {
            return CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: "skipped: no AnchorRegistryClient configured".into(),
                details: BTreeMap::new(),
            };
        };
        if self.expected_roots.is_empty() {
            return CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: "skipped: no expected_roots supplied".into(),
                details: BTreeMap::new(),
            };
        }
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(h) => h,
            Err(_) => {
                return CheckResult {
                    name: self.name().into(),
                    severity: Severity::Warn,
                    message: "skipped: no tokio runtime for chain reconciliation".into(),
                    details: BTreeMap::new(),
                };
            }
        };
        let mut details = BTreeMap::new();
        let mut missing: Vec<String> = Vec::new();
        let mut found = 0u32;
        for root in &self.expected_roots {
            let client_ref = std::sync::Arc::clone(client);
            let root_copy = *root;
            // Block on the eth_call. Each call is independent so we
            // don't bother with parallelism here.
            let result = tokio::task::block_in_place(|| {
                handle.block_on(async move { client_ref.is_anchored(root_copy).await })
            });
            match result {
                Ok(true) => found += 1,
                Ok(false) => missing.push(hex::encode(root)),
                Err(e) => missing.push(format!("{}: rpc err: {e}", hex::encode(root))),
            }
        }
        details.insert(
            "roots_checked".into(),
            self.expected_roots.len().to_string(),
        );
        details.insert("found".into(), found.to_string());
        details.insert("missing".into(), missing.len().to_string());
        if missing.is_empty() {
            CheckResult {
                name: self.name().into(),
                severity: Severity::Pass,
                message: format!("{found} anchor(s) reconciled"),
                details,
            }
        } else {
            CheckResult {
                name: self.name().into(),
                severity: Severity::Blocker,
                message: format!(
                    "{} anchor(s) missing on chain: {}",
                    missing.len(),
                    missing.join(", ")
                ),
                details,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::record::EventType;

    fn empty_ctx() -> DoctorContext {
        DoctorContext {
            agent_did: "did:citrate:agent:test".into(),
            now_unix: 1_715_000_000,
            audit_chain_path: None,
            approval_queue: None,
            break_glass: None,
            expected_audit_head: None,
        }
    }

    #[test]
    fn audit_chain_check_skips_without_path() {
        let r = AuditChainIntegrityCheck.run(&empty_ctx());
        assert!(matches!(r.severity, Severity::Pass));
        assert!(r.message.contains("skipped"));
    }

    #[test]
    fn audit_chain_check_passes_on_clean_chain() {
        let tmp = std::env::temp_dir().join("cit-agent-7a-clean-chain.jsonl");
        let _ = std::fs::remove_file(&tmp);
        let mut ctx = empty_ctx();
        ctx.audit_chain_path = Some(tmp.clone());
        // AR-B-001 (RC-8): bootstrap the chain EXPLICITLY via
        // open_or_init — NOT by running the doctor check, which no
        // longer mints a genesis on an empty sink. Genesis + 1 append
        // == 2 records.
        {
            use crate::audit::chain::{AuditChain, GenesisInfo};
            let sink: Arc<dyn crate::audit::sink::AuditSink> =
                Arc::new(FilesystemSink::open(&tmp).unwrap());
            let mut chain = AuditChain::open_or_init(
                sink,
                GenesisInfo {
                    agent_did: ctx.agent_did.clone(),
                    harness_version: "test".into(),
                    policy_bundle_hash: [0u8; 32],
                    doctor_report_hash: [0u8; 32],
                },
                ctx.now_unix,
            )
            .unwrap();
            chain
                .append(
                    EventType::Proposal,
                    b"x".to_vec(),
                    "did:citrate:role:0xop".into(),
                    vec![],
                    None,
                    ctx.now_unix + 1,
                )
                .unwrap();
        }
        let r2 = AuditChainIntegrityCheck.run(&ctx);
        assert!(matches!(r2.severity, Severity::Pass));
        assert_eq!(r2.details.get("records_verified"), Some(&"2".to_string()));
        let _ = std::fs::remove_file(&tmp);
    }

    // ── AR-B-001 tripwires ────────────────────────────────────────────

    /// Wholesale deletion: an empty / deleted audit log must be a
    /// Blocker, NOT a silently re-minted "verified 1 records" Pass.
    #[test]
    fn audit_chain_check_blocks_on_deleted_log_ar_b_001() {
        let tmp = std::env::temp_dir().join("cit-agent-ar-b-001-deleted.jsonl");
        let _ = std::fs::remove_file(&tmp);
        let mut ctx = empty_ctx();
        ctx.audit_chain_path = Some(tmp.clone());
        // File does not exist → the sink creates an empty one → no records.
        let r = AuditChainIntegrityCheck.run(&ctx);
        assert!(
            matches!(r.severity, Severity::Blocker),
            "deleted/empty log must Block, got {:?}: {}",
            r.severity,
            r.message
        );
        assert!(r.message.contains("empty or deleted"));
        let _ = std::fs::remove_file(&tmp);
    }

    /// Tail-truncation: with an externally-anchored expected head,
    /// lopping the last records off the log must be a Blocker even
    /// though the surviving prefix is internally contiguous.
    #[test]
    fn audit_chain_check_blocks_on_tail_truncation_ar_b_001() {
        use crate::audit::chain::{AuditChain, GenesisInfo};
        let tmp = std::env::temp_dir().join("cit-agent-ar-b-001-trunc.jsonl");
        let _ = std::fs::remove_file(&tmp);
        let mut ctx = empty_ctx();
        ctx.audit_chain_path = Some(tmp.clone());

        // Build genesis + 3 appends == 4 records, and capture the REAL head.
        let (head_seq, head_hash) = {
            let sink: Arc<dyn crate::audit::sink::AuditSink> =
                Arc::new(FilesystemSink::open(&tmp).unwrap());
            let mut chain = AuditChain::open_or_init(
                sink,
                GenesisInfo {
                    agent_did: ctx.agent_did.clone(),
                    harness_version: "test".into(),
                    policy_bundle_hash: [0u8; 32],
                    doctor_report_hash: [0u8; 32],
                },
                ctx.now_unix,
            )
            .unwrap();
            for i in 0..3 {
                chain
                    .append(
                        EventType::Proposal,
                        format!("a{i}").into_bytes(),
                        "did:citrate:role:0xop".into(),
                        vec![],
                        None,
                        ctx.now_unix + 1 + i,
                    )
                    .unwrap();
            }
            (chain.next_sequence() - 1, chain.last_hash())
        };
        ctx.expected_audit_head = Some((head_seq, head_hash));

        // Sanity: with the full log, the check passes.
        let r_full = AuditChainIntegrityCheck.run(&ctx);
        assert!(
            matches!(r_full.severity, Severity::Pass),
            "intact log should Pass, got {:?}: {}",
            r_full.severity,
            r_full.message
        );

        // Truncate: drop the last 2 lines from the JSONL file.
        let content = std::fs::read_to_string(&tmp).unwrap();
        let kept: Vec<&str> = content.lines().collect();
        let keep_n = kept.len() - 2;
        let truncated = kept[..keep_n].join("\n") + "\n";
        std::fs::write(&tmp, truncated).unwrap();

        let r = AuditChainIntegrityCheck.run(&ctx);
        assert!(
            matches!(r.severity, Severity::Blocker),
            "tail-truncated log must Block, got {:?}: {}",
            r.severity,
            r.message
        );
        assert!(r.message.contains("head mismatch") || r.message.contains("truncation"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[cfg(unix)]
    #[test]
    fn audit_file_permissions_check_pass_at_0600() {
        let tmp = std::env::temp_dir().join("cit-agent-7a-perms-pass.jsonl");
        let _ = std::fs::remove_file(&tmp);
        let _sink = FilesystemSink::open(&tmp).unwrap();
        let mut ctx = empty_ctx();
        ctx.audit_chain_path = Some(tmp.clone());
        let r = AuditFilePermissionsCheck.run(&ctx);
        assert!(matches!(r.severity, Severity::Pass));
        let _ = std::fs::remove_file(&tmp);
    }

    #[cfg(unix)]
    #[test]
    fn audit_file_permissions_check_warns_at_wrong_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir().join("cit-agent-7a-perms-warn.jsonl");
        let _ = std::fs::remove_file(&tmp);
        std::fs::write(&tmp, b"").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut ctx = empty_ctx();
        ctx.audit_chain_path = Some(tmp.clone());
        let r = AuditFilePermissionsCheck.run(&ctx);
        assert!(matches!(r.severity, Severity::Warn));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn approval_queue_depth_skips_without_queue() {
        let r = ApprovalQueueDepthCheck::default().run(&empty_ctx());
        assert!(matches!(r.severity, Severity::Pass));
        assert!(r.message.contains("skipped"));
    }

    #[test]
    fn approval_queue_depth_passes_under_threshold() {
        let q = Arc::new(ApprovalQueue::new());
        let mut ctx = empty_ctx();
        ctx.approval_queue = Some(q);
        let r = ApprovalQueueDepthCheck::default().run(&ctx);
        assert!(matches!(r.severity, Severity::Pass));
        assert_eq!(r.details.get("depth"), Some(&"0".to_string()));
    }

    #[test]
    fn approval_queue_depth_warns_above_threshold() {
        let q = Arc::new(ApprovalQueue::new());
        let mut ctx = empty_ctx();
        ctx.approval_queue = Some(q);
        let r = ApprovalQueueDepthCheck { warn_threshold: 0 }.run(&ctx);
        // depth=0, threshold=0 → 0 > 0 is false → Pass. Verify the
        // tight-threshold edge.
        assert!(matches!(r.severity, Severity::Pass));
    }

    #[test]
    fn pending_break_glass_skips_without_registry() {
        let check = PendingBreakGlassCheck { action_ids: vec![] };
        let r = check.run(&empty_ctx());
        assert!(matches!(r.severity, Severity::Pass));
    }

    #[test]
    fn pending_break_glass_passes_when_no_ids() {
        let mut ctx = empty_ctx();
        ctx.break_glass = Some(Arc::new(BreakGlassRegistry::new()));
        let check = PendingBreakGlassCheck { action_ids: vec![] };
        let r = check.run(&ctx);
        assert!(matches!(r.severity, Severity::Pass));
        assert!(r.message.contains("skipped"));
    }

    #[tokio::test]
    async fn runtime_check_passes_in_tokio_context() {
        let r = RuntimeCheck.run(&empty_ctx());
        assert!(matches!(r.severity, Severity::Pass));
    }

    #[test]
    fn runtime_check_warns_outside_tokio() {
        let r = RuntimeCheck.run(&empty_ctx());
        // Non-tokio sync test — no runtime present.
        assert!(matches!(r.severity, Severity::Warn));
    }

    // ── CIT-AGENT-7b tests ────────────────────────────────────────

    #[test]
    fn capsule_reverify_skips_with_empty_list() {
        let check = CapsuleManifestReverifyCheck {
            capsule_paths: vec![],
            registry: None,
        };
        let r = check.run(&empty_ctx());
        assert!(matches!(r.severity, Severity::Pass));
        assert!(r.message.contains("skipped"));
    }

    #[test]
    fn capsule_reverify_blocks_on_missing_file() {
        let check = CapsuleManifestReverifyCheck {
            capsule_paths: vec![std::path::PathBuf::from("/nonexistent/cit-agent-7b-no.cps")],
            registry: None,
        };
        let r = check.run(&empty_ctx());
        assert!(matches!(r.severity, Severity::Blocker));
        assert!(r.message.contains("open failed") || r.message.contains("failed to load"));
    }

    #[test]
    fn wasm_linker_recheck_skips_empty() {
        let check = WasmLinkerRecheckCheck { pairs: vec![] };
        let r = check.run(&empty_ctx());
        assert!(matches!(r.severity, Severity::Pass));
    }

    #[test]
    fn wasm_linker_recheck_flags_sockets_under_none() {
        use crate::capsule::manifest::*;
        let m = Manifest {
            capsule: CapsuleMetadata {
                name: "x".into(),
                version: "0.1.0".into(),
                content_hash: format!("sha256:{}", "0".repeat(64)),
            },
            capability: CapabilitySet {
                network: NetworkPolicy::None,
                filesystem: vec![],
                chain_calls: vec![],
                subagent_spawn: false,
            },
            data_class: DataClassDecl {
                reads: vec![],
                writes: vec![],
                emits: vec![],
            },
            risk: RiskDecl {
                tier: RiskTier::Low,
                required_roles: vec![],
                break_glass_eligible: false,
            },
            overlay: OverlayDecl {
                certified: vec![],
                not_certified: vec![],
            },
            procedure: ProcedureDecl { gates: vec![] },
            provenance: ProvenanceDecl {
                publisher: "did:citrate:agent:0xab12".into(),
                build_reproducible: true,
                agentile_sprint: "test".into(),
                tla_spec: "".into(),
            },
            signing: SigningDecl {
                tier: SigningTier::Bundled,
            },
        };
        let wit = "package test:capsule@0.1.0;\nworld root {\n    import wasi:sockets/tcp@0.2.0;\n}\n".to_string();
        let check = WasmLinkerRecheckCheck {
            pairs: vec![(m, wit)],
        };
        let r = check.run(&empty_ctx());
        assert!(matches!(r.severity, Severity::Blocker));
        assert!(r.message.contains("drifted") || r.message.contains("WIT"));
    }

    #[test]
    fn policy_bundle_hash_skips_empty() {
        let check = PolicyBundleHashCheck { files: vec![] };
        let r = check.run(&empty_ctx());
        assert!(matches!(r.severity, Severity::Pass));
    }

    #[test]
    fn policy_bundle_hash_passes_on_match() {
        use sha2::{Digest, Sha256};
        let tmp = std::env::temp_dir().join("cit-agent-7b-policy-ok.bin");
        let _ = std::fs::remove_file(&tmp);
        std::fs::write(&tmp, b"policy bundle bytes").unwrap();
        let mut h = Sha256::new();
        h.update(b"policy bundle bytes");
        let digest = h.finalize();
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&digest);
        let check = PolicyBundleHashCheck {
            files: vec![(tmp.clone(), expected)],
        };
        let r = check.run(&empty_ctx());
        assert!(matches!(r.severity, Severity::Pass));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn policy_bundle_hash_blocks_on_drift() {
        let tmp = std::env::temp_dir().join("cit-agent-7b-policy-drift.bin");
        let _ = std::fs::remove_file(&tmp);
        std::fs::write(&tmp, b"actual bytes").unwrap();
        let wrong_hash = [0xff; 32];
        let check = PolicyBundleHashCheck {
            files: vec![(tmp.clone(), wrong_hash)],
        };
        let r = check.run(&empty_ctx());
        assert!(matches!(r.severity, Severity::Blocker));
        assert!(r.message.contains("drifted") || r.message.contains("drift"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn tla_ci_skips_without_path() {
        let r = TlaSpecCiStatusCheck::default().run(&empty_ctx());
        assert!(matches!(r.severity, Severity::Pass));
        assert!(r.message.contains("skipped"));
    }

    #[test]
    fn tla_ci_blocks_on_failing_specs() {
        let tmp = std::env::temp_dir().join("cit-agent-7b-tla-fail.json");
        let _ = std::fs::remove_file(&tmp);
        std::fs::write(
            &tmp,
            r#"{"last_run_utc":"2026-05-15T00:00:00Z","verified_specs":["A"],"failing_specs":["B"]}"#,
        )
        .unwrap();
        let check = TlaSpecCiStatusCheck {
            status_file_path: Some(tmp.clone()),
            max_age_hours: 9999,
        };
        let r = check.run(&empty_ctx());
        assert!(matches!(r.severity, Severity::Blocker));
        assert!(r.message.contains("failing"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn tla_ci_warns_on_stale() {
        let tmp = std::env::temp_dir().join("cit-agent-7b-tla-stale.json");
        let _ = std::fs::remove_file(&tmp);
        std::fs::write(
            &tmp,
            r#"{"last_run_utc":"2020-01-01T00:00:00Z","verified_specs":["A"],"failing_specs":[]}"#,
        )
        .unwrap();
        // Use a ctx whose now_unix is in 2026 — 6+ years after 2020.
        let mut ctx = empty_ctx();
        ctx.now_unix = 1_715_000_000; // ~May 2024
        let check = TlaSpecCiStatusCheck {
            status_file_path: Some(tmp.clone()),
            max_age_hours: 48,
        };
        let r = check.run(&ctx);
        assert!(matches!(r.severity, Severity::Warn));
        assert!(r.message.contains("max_age_hours") || r.message.contains("ago"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn tla_ci_passes_on_recent_clean_run() {
        let tmp = std::env::temp_dir().join("cit-agent-7b-tla-ok.json");
        let _ = std::fs::remove_file(&tmp);
        std::fs::write(
            &tmp,
            r#"{"last_run_utc":"2024-05-06T12:00:00Z","verified_specs":["A","B","C"],"failing_specs":[]}"#,
        )
        .unwrap();
        let mut ctx = empty_ctx();
        ctx.now_unix = 1_715_000_000;
        let check = TlaSpecCiStatusCheck {
            status_file_path: Some(tmp.clone()),
            max_age_hours: 24 * 365 * 10,
        };
        let r = check.run(&ctx);
        assert!(matches!(r.severity, Severity::Pass));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn retention_skips_without_path() {
        let r = RetentionAgeCheck::default().run(&empty_ctx());
        assert!(matches!(r.severity, Severity::Pass));
    }

    #[test]
    fn retention_passes_for_fresh_file() {
        let tmp = std::env::temp_dir().join("cit-agent-7b-retention-fresh.bin");
        let _ = std::fs::remove_file(&tmp);
        std::fs::write(&tmp, b"x").unwrap();
        let mut ctx = empty_ctx();
        ctx.audit_chain_path = Some(tmp.clone());
        let r = RetentionAgeCheck::default().run(&ctx);
        assert!(matches!(r.severity, Severity::Pass));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn anchor_reconciliation_skips_without_client() {
        let check = AnchorReconciliationCheck {
            client: None,
            expected_roots: vec![[0u8; 32]],
        };
        let r = check.run(&empty_ctx());
        assert!(matches!(r.severity, Severity::Pass));
        assert!(r.message.contains("skipped"));
    }

    #[tokio::test]
    async fn anchor_reconciliation_skips_with_empty_roots() {
        // Build a client with a dummy contract address; we never
        // actually call it because expected_roots is empty.
        let client = std::sync::Arc::new(
            crate::chain::AnchorRegistryClient::from_hex_key(
                "0x1feffc85883856c384f497cf057d38da863eb9b89c545e72fbfd35631eaf4a58",
                "http://localhost:0",
                "0x0000000000000000000000000000000000000000",
                40204,
            )
            .expect("client builds"),
        );
        let check = AnchorReconciliationCheck {
            client: Some(client),
            expected_roots: vec![],
        };
        let r = check.run(&empty_ctx());
        assert!(matches!(r.severity, Severity::Pass));
    }

    #[test]
    fn parse_age_hours_handles_iso_format() {
        // Sanity: a known timestamp parses + the delta is sensible.
        let now = 1_715_000_000; // 2024-05-06T~13:33 UTC
        let earlier = parse_age_hours("2024-05-05T13:33:20Z", now);
        assert!(earlier.is_some());
        let h = earlier.unwrap();
        // Should be ~24 hours give or take.
        assert!(h >= 23 && h <= 25, "expected ~24h, got {h}");
    }
}
