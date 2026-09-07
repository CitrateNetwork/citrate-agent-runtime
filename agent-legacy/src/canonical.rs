//! Canonical agent objects — the shared vocabulary for all agent features.
//!
//! Every agent-related feature maps to these types instead of inventing its own.
//! These are the substrate that trails, LogSeq projections, benchmarks, and
//! external runtime adapters (Hermes, OpenClaw, ZeroClaw) build on.
//!
//! Architecture: Citrate is the substrate. External agents are adapters.
//! See .agentile/audits/2026-03/2026-03-31-agent-ecosystem-strategy/ for rationale.

use serde::{Deserialize, Serialize};

/// A single event in an agent's execution trail.
/// The trail is the machine truth — everything else (LogSeq notes, benchmarks,
/// chain anchors) is a projection of this stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrailEvent {
    /// Unique event ID
    pub id: String,
    /// Session this event belongs to
    pub session_id: String,
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Event type: tool_call, tool_result, approval_request, approval_decision,
    /// user_message, assistant_message, error, session_start, session_end
    pub event_type: String,
    /// The tool or action name (if applicable)
    pub tool_name: Option<String>,
    /// Structured event data (tool params, result, error details)
    pub data: serde_json::Value,
    /// Risk level of the action (if applicable)
    pub risk_level: Option<String>,
    /// Whether this event was approved by the user
    pub approved: Option<bool>,
    /// Duration in milliseconds (for tool executions)
    pub duration_ms: Option<u64>,
}

/// An agent session — a bounded period of agent activity.
/// Sessions are the unit of budgeting, auditing, and trail collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSession {
    /// Unique session ID
    pub id: String,
    /// When the session started
    pub started_at: String,
    /// When the session ended (None if still active)
    pub ended_at: Option<String>,
    /// Wallet address of the user who owns this session
    pub wallet_address: String,
    /// Network the session is operating on
    pub network: String,
    /// Chain ID for the active network
    pub chain_id: u64,
    /// Workspace root directory (for code tools)
    pub workspace_dir: String,
    /// Tools available in this session (by name)
    pub available_tools: Vec<String>,
    /// Budget limits for this session
    pub budget: SessionBudget,
    /// Number of tool calls executed
    pub tool_calls_count: u32,
    /// Whether the session was halted by emergency stop
    pub emergency_stopped: bool,
}

/// Budget limits for an agent session.
/// Per auditor recommendation: 25 tool calls, 25K tokens, 10min wall clock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionBudget {
    pub max_tool_calls: u32,
    pub max_tokens: u32,
    pub max_wall_clock_seconds: u64,
    pub max_high_risk_calls: u32,
    /// Per-tool timeout classes (seconds)
    pub read_tool_timeout: u64,
    pub file_tool_timeout: u64,
    pub shell_tool_timeout: u64,
    pub chain_tool_timeout: u64,
}

impl Default for SessionBudget {
    fn default() -> Self {
        Self {
            max_tool_calls: 25,
            max_tokens: 25_000,
            max_wall_clock_seconds: 600, // 10 minutes
            max_high_risk_calls: 3,
            read_tool_timeout: 10,
            file_tool_timeout: 15,
            shell_tool_timeout: 30,
            chain_tool_timeout: 60,
        }
    }
}

/// A capability grant — what an external runtime is allowed to do.
/// Grants are scoped by tool, amount, recipient, workspace, and time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGrant {
    /// Unique grant ID
    pub id: String,
    /// Who issued the grant (wallet address)
    pub issuer: String,
    /// Who receives the grant (agent/runtime identifier)
    pub recipient: String,
    /// Tools this grant covers (empty = no tools)
    pub allowed_tools: Vec<String>,
    /// Maximum value per transaction (in wei, for chain tools)
    pub max_value_per_tx: Option<u128>,
    /// Workspace paths this grant covers (for file tools)
    pub allowed_paths: Vec<String>,
    /// When this grant expires (RFC 3339 / ISO 8601). Empty string
    /// means "never expires" (use sparingly).
    /// RM-B1 / WP-E5.3 (audit AGT-07): parsed via
    /// `chrono::DateTime::parse_from_rfc3339`, not string-compared.
    pub expires_at: String,
    /// Policy profile: ReadOnly, Guided, Operator, Maintainer
    pub policy: PolicyProfile,
    /// Whether this grant has been revoked
    pub revoked: bool,
    /// Unix seconds when the client connected (P960-J). Used by the
    /// Operations panel to display session-age and by the MCP host's
    /// stale-grant GC to time out inactive clients. Serde default = 0
    /// keeps backward compat with grants serialized before this field.
    #[serde(default)]
    pub connected_since: u64,
    /// Issuer's ed25519 public key (32 bytes) — the wallet whose
    /// signature authorized this grant. Empty allowed in test paths
    /// and during the legacy → signed transition.
    /// RM-B1 / WP-E5.1 (audit AGT-06).
    #[serde(default)]
    pub issuer_pubkey: Vec<u8>,
    /// Ed25519 signature (64 bytes) over the canonical pre-image:
    /// `id | issuer | recipient | allowed_tools_csv | expires_at |
    ///  policy_str | max_value_per_tx_dec | allowed_paths_csv`.
    /// RM-B1 / WP-E5.1 (audit AGT-06): pre-fix `mcp_server::check_grant`
    /// trusted any grant in its in-memory list, so a leaked
    /// `grant_id` alone authorized calls. Post-fix `verify_signature`
    /// rejects grants whose signature isn't valid under
    /// `issuer_pubkey`.
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl CapabilityGrant {
    /// Build the canonical signing pre-image for this grant.
    ///
    /// AR-B-017: the previous encoding joined `allowed_tools` and `allowed_paths`
    /// with `","` and length-prefixed nothing, so a signature over a
    /// ONE-element list `["file_read,shell_exec"]` was byte-identical to — and
    /// valid for — the SPLIT two-element list `["file_read","shell_exec"]`,
    /// silently widening tool/path scope. The `\x1f` separator was also assumed
    /// unable to appear in the (arbitrary) field strings, which nothing checked.
    ///
    /// This version is unambiguous: a fixed domain tag + version, then each
    /// scalar and each list element length-prefixed (u64-LE length || bytes),
    /// and each list count-prefixed. Two grants differing in ANY field — the
    /// split above included — produce different pre-images.
    ///
    /// `signature` and `issuer_pubkey` are excluded (the signer commits to the
    /// content; the pubkey is metadata the verifier already holds).
    pub fn signing_preimage(&self) -> Vec<u8> {
        const DOMAIN: &[u8] = b"CIT-GRANT-PREIMAGE-v1";
        fn field(buf: &mut Vec<u8>, b: &[u8]) {
            buf.extend_from_slice(&(b.len() as u64).to_le_bytes());
            buf.extend_from_slice(b);
        }
        let mut buf: Vec<u8> = Vec::with_capacity(256);
        field(&mut buf, DOMAIN);
        field(&mut buf, self.id.as_bytes());
        field(&mut buf, self.issuer.as_bytes());
        field(&mut buf, self.recipient.as_bytes());
        // Lists: count then each element length-prefixed (never joined).
        buf.extend_from_slice(&(self.allowed_tools.len() as u64).to_le_bytes());
        for t in &self.allowed_tools {
            field(&mut buf, t.as_bytes());
        }
        field(&mut buf, self.expires_at.as_bytes());
        field(&mut buf, format!("{:?}", self.policy).as_bytes());
        field(
            &mut buf,
            self.max_value_per_tx
                .map(|v| v.to_string())
                .unwrap_or_default()
                .as_bytes(),
        );
        buf.extend_from_slice(&(self.allowed_paths.len() as u64).to_le_bytes());
        for p in &self.allowed_paths {
            field(&mut buf, p.as_bytes());
        }
        // AR-B-017: bind the revocation flag so a signature cannot be presented
        // over a different revoked-state than the one the issuer signed.
        buf.push(self.revoked as u8);
        buf
    }

    /// Verify the grant's signature under `issuer_pubkey`. Returns
    /// `Ok(())` on success, `Err(reason)` otherwise. Returns
    /// `Err("unsigned grant")` when either field is empty.
    pub fn verify_signature(&self) -> Result<(), String> {
        if self.signature.is_empty() {
            return Err("unsigned grant".to_string());
        }
        if self.issuer_pubkey.is_empty() {
            return Err("unsigned grant: missing issuer_pubkey".to_string());
        }
        let pubkey_bytes: [u8; 32] = self
            .issuer_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| "issuer_pubkey is not 32 bytes".to_string())?;
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "signature is not 64 bytes".to_string())?;

        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| format!("invalid issuer_pubkey: {}", e))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let preimage = self.signing_preimage();
        verifying
            .verify_strict(&preimage, &sig)
            .map_err(|e| format!("signature verification failed: {}", e))
    }

    /// Parse `expires_at` as RFC 3339; returns `Ok(None)` for empty
    /// (no expiry) and `Err` for malformed strings.
    /// RM-B1 / WP-E5.3 (audit AGT-07): pre-fix `mcp_server::check_grant`
    /// did `now > grant.expires_at` as a string compare, which only
    /// happened to work for full ISO-8601 timestamps; truncated /
    /// timezoned forms compared lexicographically and let some
    /// expired grants through.
    pub fn parsed_expires_at(&self) -> Result<Option<chrono::DateTime<chrono::Utc>>, String> {
        if self.expires_at.is_empty() {
            return Ok(None);
        }
        chrono::DateTime::parse_from_rfc3339(&self.expires_at)
            .map(|dt| Some(dt.with_timezone(&chrono::Utc)))
            .map_err(|e| format!("expires_at not RFC3339: {}", e))
    }

    /// True iff `expires_at` parses and the grant has expired
    /// relative to `now`.
    pub fn is_expired(&self, now: chrono::DateTime<chrono::Utc>) -> Result<bool, String> {
        match self.parsed_expires_at()? {
            Some(when) => Ok(now >= when),
            None => Ok(false),
        }
    }
}

/// User-visible policy profiles for capability grants.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyProfile {
    /// Can only read data, no mutations
    ReadOnly,
    /// Can propose actions, user approves each one
    Guided,
    /// Can execute pre-approved action classes without per-action approval
    Operator,
    /// Full tool access with budget limits
    Maintainer,
}

/// An approval request — a pending action waiting for user decision.
/// Keyed by request_id, correlated to session and trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique request ID (for correlation)
    pub request_id: String,
    /// Session this request belongs to
    pub session_id: String,
    /// Tool being requested
    pub tool_name: String,
    /// Parameters for the tool call
    pub params: serde_json::Value,
    /// Risk level
    pub risk_level: String,
    /// When this request was created
    pub created_at: String,
    /// Timeout in seconds (deny by default on timeout)
    pub timeout_seconds: u64,
    /// Resolution: None (pending), Some(true) (approved), Some(false) (denied)
    pub resolved: Option<bool>,
    /// When it was resolved
    pub resolved_at: Option<String>,
}

/// A benchmark trace — a replayable record of agent performance on a task.
/// The research truth projection of the trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkTrace {
    /// Unique trace ID
    pub id: String,
    /// Session this trace was recorded from
    pub session_id: String,
    /// The task description
    pub task: String,
    /// Model used for inference
    pub model: String,
    /// Trail events in order
    pub events: Vec<TrailEvent>,
    /// Total duration in milliseconds
    pub total_duration_ms: u64,
    /// Number of tool calls
    pub tool_call_count: u32,
    /// Number of approval requests
    pub approval_count: u32,
    /// Whether the task was completed successfully
    pub success: bool,
    /// Human rating (if provided)
    pub human_rating: Option<f32>,
}

/// A LogSeq projection — the human-readable view of a trail or session.
/// LogSeq markdown pages are the human truth projection of machine events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogseqProjection {
    /// Page title (e.g., "Agent Session 2026-03-31")
    pub title: String,
    /// Page type: journal, session, task, summary
    pub page_type: String,
    /// Markdown content for the page
    pub content: String,
    /// Optional content hash for on-chain anchoring
    pub content_hash: Option<String>,
    /// Trail events this page was derived from
    pub source_event_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trail_event_serializes() {
        let event = TrailEvent {
            id: "evt-001".to_string(),
            session_id: "sess-001".to_string(),
            timestamp: "2026-03-31T10:00:00Z".to_string(),
            event_type: "tool_call".to_string(),
            tool_name: Some("check_balance".to_string()),
            data: serde_json::json!({"address": "0x1234"}),
            risk_level: Some("low".to_string()),
            approved: Some(true),
            duration_ms: Some(150),
        };
        let json = serde_json::to_string(&event).expect("serializes");
        assert!(json.contains("check_balance"));
        assert!(json.contains("evt-001"));
    }

    #[test]
    fn test_session_budget_defaults() {
        let budget = SessionBudget::default();
        assert_eq!(budget.max_tool_calls, 25);
        assert_eq!(budget.max_tokens, 25_000);
        assert_eq!(budget.max_wall_clock_seconds, 600);
        assert_eq!(budget.max_high_risk_calls, 3);
    }

    #[test]
    fn test_capability_grant_serializes() {
        let grant = CapabilityGrant {
            id: "grant-001".to_string(),
            issuer: "0xuser".to_string(),
            recipient: "hermes-sidecar".to_string(),
            allowed_tools: vec!["check_balance".to_string(), "list_models".to_string()],
            max_value_per_tx: None,
            allowed_paths: vec![],
            expires_at: "2026-04-01T00:00:00Z".to_string(),
            policy: PolicyProfile::ReadOnly,
            revoked: false,
            connected_since: 0,
            issuer_pubkey: Vec::new(),
            signature: Vec::new(),
        };
        let json = serde_json::to_string(&grant).expect("serializes");
        assert!(json.contains("hermes-sidecar"));
        assert!(json.contains("ReadOnly"));
    }

    #[test]
    fn test_approval_request_default_pending() {
        let req = ApprovalRequest {
            request_id: "req-001".to_string(),
            session_id: "sess-001".to_string(),
            tool_name: "send_tx".to_string(),
            params: serde_json::json!({"to": "0x1234", "value": "1000000000000000000"}),
            risk_level: "high".to_string(),
            created_at: "2026-03-31T10:00:00Z".to_string(),
            timeout_seconds: 30,
            resolved: None,
            resolved_at: None,
        };
        assert!(req.resolved.is_none());
    }

    // ── RM-E5 / WP-E5.1 (audit AGT-06) signed grants ─────────────────

    fn unsigned_grant_for_test() -> CapabilityGrant {
        CapabilityGrant {
            id: "grant-test".to_string(),
            issuer: "0xuser".to_string(),
            recipient: "hermes".to_string(),
            allowed_tools: vec!["check_balance".to_string()],
            max_value_per_tx: None,
            allowed_paths: vec![],
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            policy: PolicyProfile::ReadOnly,
            revoked: false,
            connected_since: 0,
            issuer_pubkey: Vec::new(),
            signature: Vec::new(),
        }
    }

    fn sign_grant(grant: &mut CapabilityGrant) -> ed25519_dalek::SigningKey {
        use ed25519_dalek::Signer;
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        grant.issuer_pubkey = signing.verifying_key().to_bytes().to_vec();
        let preimage = grant.signing_preimage();
        let sig = signing.sign(&preimage);
        grant.signature = sig.to_bytes().to_vec();
        signing
    }

    #[test]
    fn preimage_distinguishes_split_vs_joined_lists() {
        // AR-B-017: a one-element list ["a,b"] must NOT hash to the same
        // pre-image as the split two-element list ["a","b"], nor may a signature
        // over one transfer to the other (scope-widening replay).
        let mut joined = unsigned_grant_for_test();
        joined.allowed_tools = vec!["a,b".to_string()];
        let mut split = unsigned_grant_for_test();
        split.allowed_tools = vec!["a".to_string(), "b".to_string()];
        assert_ne!(
            joined.signing_preimage(),
            split.signing_preimage(),
            "split and joined tool lists must produce different pre-images"
        );
        // Same for paths.
        let mut jp = unsigned_grant_for_test();
        jp.allowed_paths = vec!["/x,/y".to_string()];
        let mut sp = unsigned_grant_for_test();
        sp.allowed_paths = vec!["/x".to_string(), "/y".to_string()];
        assert_ne!(jp.signing_preimage(), sp.signing_preimage());
        // A signature over the one-element grant does not verify for the split.
        let signing = sign_grant(&mut joined);
        split.issuer_pubkey = signing.verifying_key().to_bytes().to_vec();
        split.signature = joined.signature.clone();
        assert!(
            split.verify_signature().is_err(),
            "a signature over ['a,b'] must not verify for ['a','b']"
        );
    }

    #[test]
    fn test_agt06_unsigned_grant_rejected_by_verify() {
        let grant = unsigned_grant_for_test();
        assert!(grant.verify_signature().is_err());
    }

    #[test]
    fn test_agt06_signed_grant_verifies() {
        let mut grant = unsigned_grant_for_test();
        sign_grant(&mut grant);
        grant.verify_signature().expect("verify ok");
    }

    #[test]
    fn test_agt06_tampered_grant_rejected() {
        let mut grant = unsigned_grant_for_test();
        sign_grant(&mut grant);
        // Mutate a field that's part of the preimage.
        grant.allowed_tools.push("send_tx".to_string());
        assert!(
            grant.verify_signature().is_err(),
            "AGT-06: any field change must invalidate the signature"
        );
    }

    #[test]
    fn test_agt06_swapped_pubkey_rejected() {
        let mut grant = unsigned_grant_for_test();
        sign_grant(&mut grant);
        // Replace the issuer_pubkey with a different valid key.
        let other = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        grant.issuer_pubkey = other.verifying_key().to_bytes().to_vec();
        assert!(grant.verify_signature().is_err());
    }

    #[test]
    fn test_agt06_signing_preimage_is_stable() {
        // Two grants with identical content produce identical preimages.
        let g1 = unsigned_grant_for_test();
        let g2 = unsigned_grant_for_test();
        assert_eq!(g1.signing_preimage(), g2.signing_preimage());
    }

    // ── RM-E5 / WP-E5.3 (audit AGT-07) DateTime expiry ──────────────

    #[test]
    fn test_agt07_rfc3339_expiry_parses() {
        let mut grant = unsigned_grant_for_test();
        grant.expires_at = "2026-04-01T00:00:00Z".to_string();
        let dt = grant.parsed_expires_at().expect("parses");
        assert!(dt.is_some());
    }

    #[test]
    fn test_agt07_empty_expiry_means_no_expiry() {
        let mut grant = unsigned_grant_for_test();
        grant.expires_at = "".to_string();
        let dt = grant.parsed_expires_at().expect("ok");
        assert!(dt.is_none(), "empty string = no expiry");
    }

    #[test]
    fn test_agt07_malformed_expiry_errors() {
        let mut grant = unsigned_grant_for_test();
        grant.expires_at = "tomorrow".to_string();
        assert!(grant.parsed_expires_at().is_err());
    }

    /// AGT-07 core case: pre-fix `now > grant.expires_at` was a string
    /// compare. The string `"2025-01-01"` < `"2099-01-01"` correctly,
    /// but `"2025-01-01T15:30:00+05:00"` < `"2025-01-01T11:00:00Z"`
    /// is FALSE lexicographically even though the former is
    /// chronologically later. With parsed DateTime the timezone is
    /// honored.
    #[test]
    fn test_agt07_timezone_handled_correctly() {
        let mut grant = unsigned_grant_for_test();
        // Expiry: 11:00 UTC on day X.
        grant.expires_at = "2025-01-01T11:00:00Z".to_string();
        // "Now": 15:30 +05:00 on day X = 10:30 UTC. Grant NOT yet expired.
        let now = chrono::DateTime::parse_from_rfc3339("2025-01-01T15:30:00+05:00")
            .expect("parse now")
            .with_timezone(&chrono::Utc);
        assert!(!grant.is_expired(now).expect("compares"));
        // 15:30 UTC = 14:30 UTC > 11:00 UTC: expired.
        let later = chrono::DateTime::parse_from_rfc3339("2025-01-01T15:30:00Z")
            .expect("parse later")
            .with_timezone(&chrono::Utc);
        assert!(grant.is_expired(later).expect("compares"));
    }

    #[test]
    fn test_policy_profiles_distinct() {
        assert_ne!(PolicyProfile::ReadOnly, PolicyProfile::Guided);
        assert_ne!(PolicyProfile::Operator, PolicyProfile::Maintainer);
    }

    #[test]
    fn test_benchmark_trace_serializes() {
        let trace = BenchmarkTrace {
            id: "bench-001".to_string(),
            session_id: "sess-001".to_string(),
            task: "Check wallet balance and explain".to_string(),
            model: "qwen2.5:72b".to_string(),
            events: vec![],
            total_duration_ms: 3500,
            tool_call_count: 2,
            approval_count: 0,
            success: true,
            human_rating: Some(4.5),
        };
        let json = serde_json::to_string(&trace).expect("serializes");
        assert!(json.contains("bench-001"));
    }
}
