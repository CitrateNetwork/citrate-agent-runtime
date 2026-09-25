//! Approval flow, risk-tiered HIC (Human In Control) approval.
//!
//! Every tool execution passes through the approval flow before running.
//! The flow checks risk level and either auto-approves or blocks until
//! the user responds via the UI.

use crate::error::AgentError;
use crate::tool::RiskLevel;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// Approval decision from the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// Approved for this single execution
    Approve,
    /// Approved for this tool for the rest of the session
    ApproveSession,
    /// Denied
    Deny,
}

/// Callback for requesting approval from the UI.
#[async_trait::async_trait]
pub trait ApprovalHandler: Send + Sync {
    /// Request approval for a tool execution.
    /// Returns the user's decision.
    /// The implementation should show a UI dialog and block until responded.
    async fn request_approval(
        &self,
        tool_name: &str,
        tool_description: &str,
        params: &serde_json::Value,
        risk_level: RiskLevel,
    ) -> Result<ApprovalDecision, AgentError>;

    /// Request password re-authentication (for Critical risk).
    async fn request_reauth(&self) -> Result<bool, AgentError>;
}

/// Default lifetime of a per-session auto-approve grant.
/// One hour matches the wallet session timeout — once the wallet
/// auto-locks, any auto-approve grant expires too.
/// RM-B1 / WP-E5.2 (audit AGT-10).
pub const AUTO_APPROVE_DEFAULT_TTL_SECS: u64 = 3600;

/// Per-session auto-approve grant. Carries an expiry so a
/// long-lived process doesn't keep auto-approving forever.
/// `session_id == None` is the legacy "global" grant retained for
/// dev contexts; production callers must always pass an id.
#[derive(Debug, Clone)]
pub struct AutoApproveGrant {
    pub session_id: Option<String>,
    pub expires_at: std::time::Instant,
}

impl AutoApproveGrant {
    fn is_active_for(&self, session_id: Option<&str>) -> bool {
        if std::time::Instant::now() >= self.expires_at {
            return false;
        }
        match (&self.session_id, session_id) {
            (Some(a), Some(b)) => a == b,
            (None, _) => true, // legacy global
            _ => false,
        }
    }
}

/// Approval flow — decides whether a tool can execute.
pub struct ApprovalFlow {
    handler: Arc<dyn ApprovalHandler>,
    /// Tools that have been granted session-wide approval
    session_grants: RwLock<HashSet<String>>,
    /// Active auto-approve grant (if any). Replaces the previous
    /// boolean: each grant has an expiry and (optionally) a
    /// session id, so flipping auto-approve in one session doesn't
    /// silently apply to a sibling session of the same process.
    /// RM-B1 / WP-E5.2 (audit AGT-10).
    auto_approve: Mutex<Option<AutoApproveGrant>>,
}

impl ApprovalFlow {
    pub fn new(handler: Arc<dyn ApprovalHandler>) -> Self {
        Self {
            handler,
            session_grants: RwLock::new(HashSet::new()),
            auto_approve: Mutex::new(None),
        }
    }

    /// Internal: read the current auto-approve grant, expiring it
    /// in place if it's elapsed. When `session_id` is `None`, any
    /// active grant satisfies the check (legacy compat for callers
    /// that don't track session ids); when `Some`, the grant must
    /// match the caller's session OR be a legacy global grant.
    async fn current_auto_approve(&self, session_id: Option<&str>) -> bool {
        let mut guard = self.auto_approve.lock().await;
        let active = match guard.as_ref() {
            Some(grant) => {
                if std::time::Instant::now() >= grant.expires_at {
                    *guard = None;
                    false
                } else {
                    match session_id {
                        // Caller named a session: must match.
                        Some(s) => match &grant.session_id {
                            Some(g) => g == s,
                            None => true, // legacy global grant covers all
                        },
                        // AR-B-019: an anonymous caller is covered ONLY by a
                        // GLOBAL grant. Previously any active grant satisfied an
                        // anonymous check, so a grant created by
                        // `set_auto_approve_for_session("sess-A")` auto-approved
                        // Low/Medium tools for EVERY session (check() passes
                        // None). A session-scoped grant must not leak past its
                        // session.
                        None => grant.session_id.is_none(),
                    }
                }
            }
            None => false,
        };
        active
    }

    /// Check if a tool can execute. May block waiting for user input.
    pub async fn check(
        &self,
        tool_name: &str,
        tool_description: &str,
        params: &serde_json::Value,
        risk_level: RiskLevel,
    ) -> Result<(), AgentError> {
        // Auto-approve only bypasses low/medium risk checks.
        // High/critical flows still require explicit approval.
        // RM-B1 / WP-E5.2 (audit AGT-10): per-session, time-bounded.
        if self.current_auto_approve(None).await {
            match risk_level {
                RiskLevel::Low | RiskLevel::Medium => return Ok(()),
                RiskLevel::High | RiskLevel::Critical => {}
            }
        }

        match risk_level {
            RiskLevel::Low => {
                // Auto-approve read-only operations
                Ok(())
            }
            RiskLevel::Medium => {
                // Check session grants first
                if self.session_grants.read().await.contains(tool_name) {
                    return Ok(());
                }
                // Ask the user
                let decision = self
                    .handler
                    .request_approval(tool_name, tool_description, params, risk_level)
                    .await?;
                match decision {
                    ApprovalDecision::Approve => Ok(()),
                    ApprovalDecision::ApproveSession => {
                        self.session_grants
                            .write()
                            .await
                            .insert(tool_name.to_string());
                        Ok(())
                    }
                    ApprovalDecision::Deny => Err(AgentError::Denied),
                }
            }
            RiskLevel::High => {
                // Always ask for high-risk operations
                let decision = self
                    .handler
                    .request_approval(tool_name, tool_description, params, risk_level)
                    .await?;
                match decision {
                    ApprovalDecision::Approve | ApprovalDecision::ApproveSession => Ok(()),
                    ApprovalDecision::Deny => Err(AgentError::Denied),
                }
            }
            RiskLevel::Critical => {
                // Ask + require password re-authentication
                let decision = self
                    .handler
                    .request_approval(tool_name, tool_description, params, risk_level)
                    .await?;
                match decision {
                    ApprovalDecision::Approve | ApprovalDecision::ApproveSession => {
                        // Require password
                        if self.handler.request_reauth().await? {
                            Ok(())
                        } else {
                            Err(AgentError::Denied)
                        }
                    }
                    ApprovalDecision::Deny => Err(AgentError::Denied),
                }
            }
        }
    }

    /// Enable auto-approve mode for low/medium risk operations in trusted dev sessions.
    ///
    /// Legacy entry point — uses the default TTL and "global"
    /// session scope. Prefer `set_auto_approve_for_session` in new
    /// code, which makes the scope explicit and enables auto-expiry
    /// at session lock.
    /// RM-B1 / WP-E5.2 (audit AGT-10).
    pub async fn set_auto_approve(&self, enabled: bool) {
        if enabled {
            let when = std::time::Instant::now()
                + std::time::Duration::from_secs(AUTO_APPROVE_DEFAULT_TTL_SECS);
            *self.auto_approve.lock().await = Some(AutoApproveGrant {
                session_id: None,
                expires_at: when,
            });
        } else {
            *self.auto_approve.lock().await = None;
        }
    }

    /// Bind auto-approve to a specific session id with an explicit
    /// TTL. Flipping `enabled` to true requires a Critical re-auth
    /// in the calling code path; this method is the place that
    /// receives that confirmation and records the grant.
    /// RM-B1 / WP-E5.2 (audit AGT-10).
    pub async fn set_auto_approve_for_session(
        &self,
        session_id: impl Into<String>,
        ttl_secs: u64,
    ) {
        let when = std::time::Instant::now() + std::time::Duration::from_secs(ttl_secs);
        *self.auto_approve.lock().await = Some(AutoApproveGrant {
            session_id: Some(session_id.into()),
            expires_at: when,
        });
    }

    /// True iff an auto-approve grant for `session_id` is active.
    pub async fn auto_approve_active_for(&self, session_id: &str) -> bool {
        self.current_auto_approve(Some(session_id)).await
    }

    /// Clear all session grants.
    pub async fn clear_grants(&self) {
        self.session_grants.write().await.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysApprove;

    #[async_trait::async_trait]
    impl ApprovalHandler for AlwaysApprove {
        async fn request_approval(
            &self,
            _: &str,
            _: &str,
            _: &serde_json::Value,
            _: RiskLevel,
        ) -> Result<ApprovalDecision, AgentError> {
            Ok(ApprovalDecision::Approve)
        }
        async fn request_reauth(&self) -> Result<bool, AgentError> {
            Ok(true)
        }
    }

    struct AlwaysDeny;

    #[async_trait::async_trait]
    impl ApprovalHandler for AlwaysDeny {
        async fn request_approval(
            &self,
            _: &str,
            _: &str,
            _: &serde_json::Value,
            _: RiskLevel,
        ) -> Result<ApprovalDecision, AgentError> {
            Ok(ApprovalDecision::Deny)
        }
        async fn request_reauth(&self) -> Result<bool, AgentError> {
            Ok(false)
        }
    }

    #[tokio::test]
    async fn test_low_risk_auto_approves() {
        let flow = ApprovalFlow::new(Arc::new(AlwaysDeny)); // Even deny handler
        let result = flow
            .check(
                "read_file",
                "Read a file",
                &serde_json::json!({}),
                RiskLevel::Low,
            )
            .await;
        assert!(result.is_ok()); // Low risk always passes
    }

    #[tokio::test]
    async fn test_high_risk_denied() {
        let flow = ApprovalFlow::new(Arc::new(AlwaysDeny));
        let result = flow
            .check(
                "send_tx",
                "Send transaction",
                &serde_json::json!({}),
                RiskLevel::High,
            )
            .await;
        assert!(matches!(result, Err(AgentError::Denied)));
    }

    #[tokio::test]
    async fn test_high_risk_approved() {
        let flow = ApprovalFlow::new(Arc::new(AlwaysApprove));
        let result = flow
            .check(
                "send_tx",
                "Send transaction",
                &serde_json::json!({}),
                RiskLevel::High,
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_auto_approve_only_bypasses_low_and_medium() {
        let flow = ApprovalFlow::new(Arc::new(AlwaysDeny));
        flow.set_auto_approve(true).await;
        let low = flow
            .check(
                "read_file",
                "Read file",
                &serde_json::json!({}),
                RiskLevel::Low,
            )
            .await;
        let medium = flow
            .check(
                "write_file",
                "Write file",
                &serde_json::json!({}),
                RiskLevel::Medium,
            )
            .await;
        let high = flow
            .check(
                "send_tx",
                "Send transaction",
                &serde_json::json!({}),
                RiskLevel::High,
            )
            .await;
        let critical = flow
            .check(
                "export_key",
                "Export key",
                &serde_json::json!({}),
                RiskLevel::Critical,
            )
            .await;
        assert!(low.is_ok());
        assert!(medium.is_ok());
        assert!(matches!(high, Err(AgentError::Denied)));
        assert!(matches!(critical, Err(AgentError::Denied)));
    }

    /// RM-B1 / WP-E5.2 (audit AGT-10): expired auto-approve grants
    /// no longer auto-approve. Set TTL to 0 so the grant is born
    /// expired.
    #[tokio::test]
    async fn test_agt10_auto_approve_expires() {
        let flow = ApprovalFlow::new(Arc::new(AlwaysDeny));
        flow.set_auto_approve_for_session("sess-1", 0).await;
        // Sleep a hair so the Instant::now() comparison crosses.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let r = flow
            .check(
                "write_file",
                "Write",
                &serde_json::json!({}),
                RiskLevel::Medium,
            )
            .await;
        // Handler is AlwaysDeny → without an active auto-approve,
        // medium risk hits the handler and denies.
        assert!(matches!(r, Err(AgentError::Denied)));
    }

    /// AR-B-019 (RC-8): a SESSION-scoped grant must NOT auto-approve the
    /// anonymous `check()` path. This test previously asserted it DID (the
    /// bleed: a grant for "sess-1" auto-approved Medium tools for every caller
    /// because check() passes session_id = None). Now the anonymous check falls
    /// through to the handler (AlwaysDeny) → Denied, while the session grant is
    /// still active for a caller that names its session.
    #[tokio::test]
    async fn session_grant_does_not_auto_approve_anonymous_check() {
        let flow = ApprovalFlow::new(Arc::new(AlwaysDeny));
        flow.set_auto_approve_for_session("sess-1", 60).await;
        let r = flow
            .check(
                "write_file",
                "Write",
                &serde_json::json!({}),
                RiskLevel::Medium,
            )
            .await;
        assert!(
            matches!(r, Err(AgentError::Denied)),
            "a session-scoped grant must not leak to the anonymous check path"
        );
        // The grant is still active for the session that owns it.
        assert!(flow.auto_approve_active_for("sess-1").await);
        assert!(!flow.auto_approve_active_for("sess-2").await);
    }

    /// AR-B-019: a GLOBAL grant (set_auto_approve(true)) DOES auto-approve the
    /// anonymous check() — global is intentionally session-agnostic.
    #[tokio::test]
    async fn global_grant_auto_approves_anonymous_check() {
        let flow = ApprovalFlow::new(Arc::new(AlwaysDeny));
        flow.set_auto_approve(true).await;
        let r = flow
            .check(
                "write_file",
                "Write",
                &serde_json::json!({}),
                RiskLevel::Medium,
            )
            .await;
        assert!(r.is_ok(), "a global grant auto-approves Medium even if the handler denies");
    }

    /// AGT-10 enforcement test: a grant bound to "sess-A" does NOT
    /// auto-approve a query naming "sess-B".
    #[tokio::test]
    async fn test_agt10_session_scope_enforced_when_caller_identifies() {
        let flow = ApprovalFlow::new(Arc::new(AlwaysDeny));
        flow.set_auto_approve_for_session("sess-A", 60).await;
        assert!(flow.auto_approve_active_for("sess-A").await);
        assert!(!flow.auto_approve_active_for("sess-B").await);
    }

    #[tokio::test]
    async fn test_agt10_set_false_clears_grant() {
        let flow = ApprovalFlow::new(Arc::new(AlwaysDeny));
        flow.set_auto_approve(true).await;
        flow.set_auto_approve(false).await;
        // No grant active → medium-risk falls through to handler
        // and is denied.
        let r = flow
            .check(
                "write_file",
                "Write",
                &serde_json::json!({}),
                RiskLevel::Medium,
            )
            .await;
        assert!(matches!(r, Err(AgentError::Denied)));
    }

    #[tokio::test]
    async fn test_session_grant_persists() {
        let flow = ApprovalFlow::new(Arc::new(SessionGranter));
        // First call: granted for session
        let r1 = flow
            .check(
                "write_file",
                "Write",
                &serde_json::json!({}),
                RiskLevel::Medium,
            )
            .await;
        assert!(r1.is_ok());
        // Second call: should auto-approve from session grant
        // (even if handler would deny — but it returns ApproveSession)
        let r2 = flow
            .check(
                "write_file",
                "Write",
                &serde_json::json!({}),
                RiskLevel::Medium,
            )
            .await;
        assert!(r2.is_ok());
    }

    struct SessionGranter;

    #[async_trait::async_trait]
    impl ApprovalHandler for SessionGranter {
        async fn request_approval(
            &self,
            _: &str,
            _: &str,
            _: &serde_json::Value,
            _: RiskLevel,
        ) -> Result<ApprovalDecision, AgentError> {
            Ok(ApprovalDecision::ApproveSession)
        }
        async fn request_reauth(&self) -> Result<bool, AgentError> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn test_clear_grants() {
        let flow = ApprovalFlow::new(Arc::new(SessionGranter));
        flow.check("tool", "desc", &serde_json::json!({}), RiskLevel::Medium)
            .await
            .expect("granted");
        flow.clear_grants().await;
        // Grant cleared — would need to re-approve
        assert!(flow.session_grants.read().await.is_empty());
    }
}
