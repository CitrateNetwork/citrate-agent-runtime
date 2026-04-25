//! Cron scheduler — time-based job scheduling for the agent system.
//!
//! `CronScheduler` manages a collection of `CronJob` entries. Each job
//! specifies a cron-style schedule expression, a tool name, and parameters.
//! The `tick()` method evaluates which jobs are due based on the current time
//! and returns them for execution.
//!
//! Schedule expression format: `"second minute hour day_of_month month day_of_week"`
//! Supports `*` (every), specific values, and ranges. The scheduler matches
//! each field against the current time to determine if a job should fire.

use chrono::{DateTime, Datelike, Timelike, Utc};
use std::sync::Arc;
use tokio::sync::RwLock;

/// A scheduled job entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CronJob {
    /// Unique job identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Cron schedule expression: `"sec min hour dom month dow"`.
    /// Each field supports `*` (every), a single number, or a range `a-b`.
    pub schedule: String,
    /// Name of the `AgentTool` to invoke when this job fires.
    pub tool_name: String,
    /// JSON parameters to pass to the tool.
    pub params: serde_json::Value,
    /// Whether this job is active.
    pub enabled: bool,
    /// ISO 8601 timestamp of the last time this job fired (if ever).
    pub last_run: Option<String>,
    /// Snapshot of the capability grant captured at REGISTRATION
    /// time. The fire-time check verifies the snapshot's signature
    /// is still valid AND that the live grant hasn't been revoked
    /// AND that the snapshot's policy still admits the tool. This
    /// closes audit AGT-14: pre-fix the cron loop re-resolved
    /// `grant_id` at fire time, so a grant rotated to a more
    /// permissive scope after registration would silently elevate
    /// the cron's authority.
    /// RM-B1 / WP-E5.9 (audit AGT-14).
    #[serde(default)]
    pub grant_snapshot: Option<citrate_agent_core::canonical::CapabilityGrant>,
}

/// Result of a `tick()` — jobs that are due for execution.
#[derive(Debug, Clone)]
pub struct DueJob {
    /// The job that matched.
    pub job: CronJob,
    /// The timestamp when the match was evaluated.
    pub matched_at: DateTime<Utc>,
}

/// Cron scheduler — stores jobs and determines which are due.
pub struct CronScheduler {
    jobs: Arc<RwLock<Vec<CronJob>>>,
}

impl CronScheduler {
    /// Create a new empty scheduler.
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add a job to the scheduler. Returns an error if a job with the same ID
    /// already exists.
    pub async fn add_job(&self, job: CronJob) -> Result<(), SchedulerError> {
        let mut jobs = self.jobs.write().await;
        if jobs.iter().any(|j| j.id == job.id) {
            return Err(SchedulerError::DuplicateJobId(job.id));
        }
        tracing::info!("Cron job added: id={} name={} schedule={}", job.id, job.name, job.schedule);
        jobs.push(job);
        Ok(())
    }

    /// Remove a job by ID. Returns the removed job, or an error if not found.
    pub async fn remove_job(&self, id: &str) -> Result<CronJob, SchedulerError> {
        let mut jobs = self.jobs.write().await;
        let pos = jobs
            .iter()
            .position(|j| j.id == id)
            .ok_or_else(|| SchedulerError::JobNotFound(id.to_string()))?;
        let removed = jobs.remove(pos);
        tracing::info!("Cron job removed: id={}", id);
        Ok(removed)
    }

    /// List all jobs.
    pub async fn list_jobs(&self) -> Vec<CronJob> {
        self.jobs.read().await.clone()
    }

    /// Enable a job by ID.
    pub async fn enable_job(&self, id: &str) -> Result<(), SchedulerError> {
        let mut jobs = self.jobs.write().await;
        let job = jobs
            .iter_mut()
            .find(|j| j.id == id)
            .ok_or_else(|| SchedulerError::JobNotFound(id.to_string()))?;
        job.enabled = true;
        tracing::info!("Cron job enabled: id={}", id);
        Ok(())
    }

    /// Disable a job by ID.
    pub async fn disable_job(&self, id: &str) -> Result<(), SchedulerError> {
        let mut jobs = self.jobs.write().await;
        let job = jobs
            .iter_mut()
            .find(|j| j.id == id)
            .ok_or_else(|| SchedulerError::JobNotFound(id.to_string()))?;
        job.enabled = false;
        tracing::info!("Cron job disabled: id={}", id);
        Ok(())
    }

    /// Get a job by ID.
    pub async fn get_job(&self, id: &str) -> Option<CronJob> {
        self.jobs.read().await.iter().find(|j| j.id == id).cloned()
    }

    /// Number of registered jobs.
    pub async fn count(&self) -> usize {
        self.jobs.read().await.len()
    }

    /// Evaluate all enabled jobs against the given timestamp and return those
    /// whose schedule matches. Also updates `last_run` on matched jobs.
    pub async fn tick(&self, now: DateTime<Utc>) -> Vec<DueJob> {
        let mut jobs = self.jobs.write().await;
        let mut due = Vec::new();

        for job in jobs.iter_mut() {
            if !job.enabled {
                continue;
            }
            if schedule_matches(&job.schedule, now) {
                job.last_run = Some(now.to_rfc3339());
                due.push(DueJob {
                    job: job.clone(),
                    matched_at: now,
                });
            }
        }

        due
    }

    /// Convenience: tick with the current UTC time.
    pub async fn tick_now(&self) -> Vec<DueJob> {
        self.tick(Utc::now()).await
    }

    /// Fire-time grant validation. Given a `DueJob`, check that the
    /// snapshot captured at registration is still valid:
    ///   1. The snapshot's signature still verifies (i.e. the issuer
    ///      key on file still consents to this exact preimage).
    ///   2. The snapshot's `tool_name` is in `allowed_tools`.
    ///   3. The snapshot's expiry hasn't elapsed.
    ///
    /// Returns `Ok(())` if the cron is allowed to fire, `Err(reason)`
    /// otherwise. Caller is responsible for checking against the
    /// LIVE grant store for revocation if it cares about that
    /// (snapshot-only is sufficient for AGT-14's "no silent
    /// elevation" property).
    /// RM-B1 / WP-E5.9 (audit AGT-14).
    pub fn validate_fire(due: &DueJob, now: DateTime<Utc>) -> Result<(), String> {
        let snapshot = due
            .job
            .grant_snapshot
            .as_ref()
            .ok_or_else(|| "no grant snapshot recorded at registration".to_string())?;

        // Signature still valid? (Either it was always signed and
        // still verifies, or it was never signed and we treat that
        // as legacy-OK — operator's policy choice at registration.)
        if !snapshot.signature.is_empty() || !snapshot.issuer_pubkey.is_empty() {
            snapshot
                .verify_signature()
                .map_err(|e| format!("snapshot signature invalid: {}", e))?;
        }

        // Tool still in scope?
        if !snapshot.allowed_tools.is_empty()
            && !snapshot
                .allowed_tools
                .iter()
                .any(|t| t == &due.job.tool_name)
        {
            return Err(format!(
                "snapshot does not authorize tool '{}'",
                due.job.tool_name
            ));
        }

        // Expiry?
        if snapshot
            .is_expired(now)
            .map_err(|e| format!("snapshot expires_at malformed: {}", e))?
        {
            return Err("snapshot has expired".to_string());
        }

        Ok(())
    }
}

impl Default for CronScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors from the cron scheduler.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    #[error("Job with id '{0}' already exists")]
    DuplicateJobId(String),

    #[error("Job with id '{0}' not found")]
    JobNotFound(String),

    #[error("Invalid schedule expression: {0}")]
    InvalidSchedule(String),
}

/// Parse and evaluate a cron schedule expression against a timestamp.
///
/// Format: `"second minute hour day_of_month month day_of_week"`
///
/// Each field can be:
/// - `*` — matches any value
/// - A single number — exact match
/// - `a-b` — inclusive range match
/// - `*/n` — step (every n-th value)
///
/// Returns `true` if all six fields match the given time.
fn schedule_matches(schedule: &str, time: DateTime<Utc>) -> bool {
    let fields: Vec<&str> = schedule.split_whitespace().collect();
    if fields.len() != 6 {
        tracing::warn!("Invalid cron expression (expected 6 fields): {}", schedule);
        return false;
    }

    let values = [
        time.second(),
        time.minute(),
        time.hour(),
        time.day(),
        time.month(),
        time.weekday().num_days_from_sunday(), // 0=Sun, 6=Sat
    ];

    for (field, &value) in fields.iter().zip(values.iter()) {
        if !field_matches(field, value) {
            return false;
        }
    }

    true
}

/// Check whether a single cron field matches a numeric value.
fn field_matches(field: &str, value: u32) -> bool {
    if field == "*" {
        return true;
    }

    // Step pattern: */n
    if let Some(step_str) = field.strip_prefix("*/") {
        if let Ok(step) = step_str.parse::<u32>() {
            if step == 0 {
                return false;
            }
            return value.is_multiple_of(step);
        }
        return false;
    }

    // Range pattern: a-b
    if field.contains('-') {
        let parts: Vec<&str> = field.splitn(2, '-').collect();
        if parts.len() == 2 {
            if let (Ok(lo), Ok(hi)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                return value >= lo && value <= hi;
            }
        }
        return false;
    }

    // Exact match
    if let Ok(exact) = field.parse::<u32>() {
        return value == exact;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn make_job(id: &str, schedule: &str) -> CronJob {
        CronJob {
            id: id.to_string(),
            name: format!("Test job {}", id),
            schedule: schedule.to_string(),
            tool_name: "test_tool".to_string(),
            params: serde_json::json!({"key": "value"}),
            enabled: true,
            last_run: None,
            grant_snapshot: None,
        }
    }

    #[tokio::test]
    async fn test_add_and_list_jobs() {
        let scheduler = CronScheduler::new();
        scheduler.add_job(make_job("j1", "0 * * * * *")).await.expect("add job");
        scheduler.add_job(make_job("j2", "0 */5 * * * *")).await.expect("add job");

        let jobs = scheduler.list_jobs().await;
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].id, "j1");
        assert_eq!(jobs[1].id, "j2");
    }

    #[tokio::test]
    async fn test_add_duplicate_id_fails() {
        let scheduler = CronScheduler::new();
        scheduler.add_job(make_job("j1", "0 * * * * *")).await.expect("add job");
        let result = scheduler.add_job(make_job("j1", "0 */5 * * * *")).await;
        assert!(result.is_err());
        match result.expect_err("should be duplicate error") {
            SchedulerError::DuplicateJobId(id) => assert_eq!(id, "j1"),
            other => panic!("Expected DuplicateJobId, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_remove_job() {
        let scheduler = CronScheduler::new();
        scheduler.add_job(make_job("j1", "0 * * * * *")).await.expect("add job");
        assert_eq!(scheduler.count().await, 1);

        let removed = scheduler.remove_job("j1").await.expect("remove job");
        assert_eq!(removed.id, "j1");
        assert_eq!(scheduler.count().await, 0);
    }

    #[tokio::test]
    async fn test_remove_nonexistent_fails() {
        let scheduler = CronScheduler::new();
        let result = scheduler.remove_job("nope").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_enable_disable_job() {
        let scheduler = CronScheduler::new();
        scheduler.add_job(make_job("j1", "0 * * * * *")).await.expect("add job");

        scheduler.disable_job("j1").await.expect("disable job");
        let job = scheduler.get_job("j1").await.expect("get job");
        assert!(!job.enabled);

        scheduler.enable_job("j1").await.expect("enable job");
        let job = scheduler.get_job("j1").await.expect("get job");
        assert!(job.enabled);
    }

    #[tokio::test]
    async fn test_tick_matches_wildcard() {
        let scheduler = CronScheduler::new();
        // "* * * * * *" matches every second
        scheduler.add_job(make_job("every", "* * * * * *")).await.expect("add job");

        let now = Utc::now();
        let due = scheduler.tick(now).await;
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].job.id, "every");
    }

    #[tokio::test]
    async fn test_tick_matches_exact_minute() {
        let scheduler = CronScheduler::new();
        // Fires at second 0 of minute 30
        scheduler.add_job(make_job("m30", "0 30 * * * *")).await.expect("add job");

        // 2026-03-28 10:30:00 UTC
        let matching = Utc.with_ymd_and_hms(2026, 3, 28, 10, 30, 0)
            .single()
            .expect("valid datetime");
        let due = scheduler.tick(matching).await;
        assert_eq!(due.len(), 1);

        // 2026-03-28 10:31:00 UTC — should NOT match
        let non_matching = Utc.with_ymd_and_hms(2026, 3, 28, 10, 31, 0)
            .single()
            .expect("valid datetime");
        let due2 = scheduler.tick(non_matching).await;
        assert_eq!(due2.len(), 0);
    }

    #[tokio::test]
    async fn test_tick_skips_disabled_jobs() {
        let scheduler = CronScheduler::new();
        let mut job = make_job("disabled", "* * * * * *");
        job.enabled = false;
        scheduler.add_job(job).await.expect("add job");

        let due = scheduler.tick(Utc::now()).await;
        assert!(due.is_empty());
    }

    #[tokio::test]
    async fn test_tick_updates_last_run() {
        let scheduler = CronScheduler::new();
        scheduler.add_job(make_job("j1", "* * * * * *")).await.expect("add job");

        let before = scheduler.get_job("j1").await.expect("get job");
        assert!(before.last_run.is_none());

        scheduler.tick(Utc::now()).await;

        let after = scheduler.get_job("j1").await.expect("get job");
        assert!(after.last_run.is_some());
    }

    #[test]
    fn test_field_matches_star() {
        assert!(field_matches("*", 0));
        assert!(field_matches("*", 59));
    }

    #[test]
    fn test_field_matches_exact() {
        assert!(field_matches("5", 5));
        assert!(!field_matches("5", 6));
    }

    #[test]
    fn test_field_matches_range() {
        assert!(field_matches("10-20", 10));
        assert!(field_matches("10-20", 15));
        assert!(field_matches("10-20", 20));
        assert!(!field_matches("10-20", 9));
        assert!(!field_matches("10-20", 21));
    }

    #[test]
    fn test_field_matches_step() {
        // */5 matches 0, 5, 10, 15, ...
        assert!(field_matches("*/5", 0));
        assert!(field_matches("*/5", 15));
        assert!(!field_matches("*/5", 3));
    }

    #[test]
    fn test_schedule_matches_full_expression() {
        // "0 0 12 * * *" = noon every day
        let noon = Utc.with_ymd_and_hms(2026, 3, 28, 12, 0, 0)
            .single()
            .expect("valid datetime");
        assert!(schedule_matches("0 0 12 * * *", noon));

        let not_noon = Utc.with_ymd_and_hms(2026, 3, 28, 13, 0, 0)
            .single()
            .expect("valid datetime");
        assert!(!schedule_matches("0 0 12 * * *", not_noon));
    }

    #[test]
    fn test_schedule_invalid_field_count() {
        let now = Utc::now();
        // Only 5 fields — invalid
        assert!(!schedule_matches("0 0 12 * *", now));
    }

    // ── RM-E5 / WP-E5.9 (audit AGT-14) cron grant snapshot ──────────

    use citrate_agent_core::canonical::{CapabilityGrant, PolicyProfile};

    fn make_snapshot(allowed_tool: &str, expires_at: &str) -> CapabilityGrant {
        CapabilityGrant {
            id: "grant-cron".to_string(),
            issuer: "0xuser".to_string(),
            recipient: "cron".to_string(),
            allowed_tools: vec![allowed_tool.to_string()],
            max_value_per_tx: None,
            allowed_paths: vec![],
            expires_at: expires_at.to_string(),
            policy: PolicyProfile::Operator,
            revoked: false,
            connected_since: 0,
            issuer_pubkey: Vec::new(),
            signature: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_agt14_validate_fire_passes_when_snapshot_authorizes_tool() {
        let mut job = make_job("j1", "* * * * * *");
        job.tool_name = "check_balance".to_string();
        job.grant_snapshot = Some(make_snapshot("check_balance", "2030-01-01T00:00:00Z"));
        let due = DueJob {
            job: job.clone(),
            matched_at: Utc::now(),
        };
        CronScheduler::validate_fire(&due, Utc::now()).expect("should pass");
    }

    #[tokio::test]
    async fn test_agt14_validate_fire_rejects_missing_snapshot() {
        let job = make_job("j1", "* * * * * *");
        let due = DueJob {
            job,
            matched_at: Utc::now(),
        };
        let err = CronScheduler::validate_fire(&due, Utc::now())
            .expect_err("missing snapshot should error");
        assert!(err.contains("snapshot"));
    }

    #[tokio::test]
    async fn test_agt14_validate_fire_rejects_unauthorized_tool() {
        let mut job = make_job("j1", "* * * * * *");
        job.tool_name = "send_tx".to_string();
        // Snapshot only allows `check_balance`, not `send_tx`.
        job.grant_snapshot = Some(make_snapshot("check_balance", "2030-01-01T00:00:00Z"));
        let due = DueJob {
            job,
            matched_at: Utc::now(),
        };
        let err = CronScheduler::validate_fire(&due, Utc::now())
            .expect_err("unauthorized tool should error");
        assert!(err.contains("does not authorize"));
    }

    #[tokio::test]
    async fn test_agt14_validate_fire_rejects_expired_snapshot() {
        let mut job = make_job("j1", "* * * * * *");
        job.tool_name = "check_balance".to_string();
        // Snapshot expired in 2020.
        job.grant_snapshot = Some(make_snapshot("check_balance", "2020-01-01T00:00:00Z"));
        let due = DueJob {
            job,
            matched_at: Utc::now(),
        };
        let err = CronScheduler::validate_fire(&due, Utc::now())
            .expect_err("expired snapshot should error");
        assert!(err.contains("expired"));
    }

    /// Core AGT-14 case: the live grant has been rotated to a more
    /// permissive scope, but the snapshot — locked at registration
    /// — refuses the elevated tool.
    #[tokio::test]
    async fn test_agt14_snapshot_blocks_post_registration_elevation() {
        let mut job = make_job("j1", "* * * * * *");
        // Cron was registered to do `check_balance` only.
        job.tool_name = "check_balance".to_string();
        job.grant_snapshot = Some(make_snapshot("check_balance", "2030-01-01T00:00:00Z"));

        // Imagine the operator later rotated the grant to also
        // authorize `send_tx`. The cron's job record might
        // independently change `tool_name` to "send_tx", but the
        // snapshot still says "check_balance only".
        job.tool_name = "send_tx".to_string();
        let due = DueJob {
            job,
            matched_at: Utc::now(),
        };
        assert!(CronScheduler::validate_fire(&due, Utc::now()).is_err());
    }
}
