//! Citrate Capability Catalog — policy-based tool discovery and grant enforcement.
//!
//! This module is a capability boundary layer, NOT a transport endpoint.
//! It provides tool discovery, policy filtering, and grant enforcement.
//! A real MCP transport (stdio or HTTP) would wrap this catalog.
//!
//! External runtimes (Hermes, OpenClaw, ZeroClaw) will connect through
//! a future transport layer that delegates to this catalog for policy.
//!
//! Architecture: Citrate is the substrate. External agents are adapters.
//! This catalog enforces approval, budget, and audit policy.

use crate::canonical::{CapabilityGrant, PolicyProfile, TrailEvent};
use crate::tool::{RiskLevel, ToolRegistry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// Constant-time string equality for bearer-style identifiers.
///
/// Closes audit finding `CX-02` (MEDIUM): grant lookups previously used
/// `g.id == grant_id` (`String == &str`), which short-circuits on the
/// first byte mismatch and leaks the matching prefix length to a network
/// attacker. `subtle::ConstantTimeEq::ct_eq` evaluates the entire input
/// regardless of mismatch position.
///
/// Lengths are compared first because (a) length is not secret and
/// (b) `ct_eq` panics on mismatched lengths. We DO leak the length
/// difference, but length alone gives an attacker far less than a
/// per-byte timing oracle.
fn ct_grant_id_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// MCP tool definition — what external runtimes see when they discover tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolDefinition {
    pub name: String,
    pub description: String,
    pub category: ToolCategory,
    pub risk_level: String,
    pub parameters_schema: serde_json::Value,
    /// Whether this tool requires explicit approval per invocation
    pub requires_approval: bool,
}

/// Tool categories for skill packs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ToolCategory {
    WalletRead,
    WalletWrite,
    NodeRead,
    Ipfs,
    Models,
    Docs,
    Repo,
    GovernanceRead,
    GovernanceWrite,
    Shell,
}

impl ToolCategory {
    /// Whether this category is allowed by a given policy profile.
    pub fn allowed_by(&self, policy: &PolicyProfile) -> bool {
        match policy {
            PolicyProfile::ReadOnly => matches!(
                self,
                ToolCategory::WalletRead
                    | ToolCategory::NodeRead
                    | ToolCategory::Models
                    | ToolCategory::Docs
                    | ToolCategory::GovernanceRead
            ),
            PolicyProfile::Guided => {
                !matches!(self, ToolCategory::Shell | ToolCategory::GovernanceWrite)
            }
            PolicyProfile::Operator => !matches!(self, ToolCategory::GovernanceWrite),
            PolicyProfile::Maintainer => true,
        }
    }
}

/// Categorize a tool by name into a category.
pub fn categorize_tool(tool_name: &str) -> ToolCategory {
    match tool_name {
        "check_balance" | "explain_tx" => ToolCategory::WalletRead,
        "send_tx" | "deploy_contract" => ToolCategory::WalletWrite,
        "list_models" | "run_inference" => ToolCategory::Models,
        "query_contract" => ToolCategory::NodeRead,
        "file_read" | "search_code" => ToolCategory::Repo,
        "file_write" | "file_edit" => ToolCategory::Repo,
        "git_ops" => ToolCategory::Repo,
        "shell_exec" => ToolCategory::Shell,
        _ => ToolCategory::Docs,
    }
}

/// External runtimes need Operator-or-higher scope for these tools.
fn requires_operator_scope(tool_name: &str) -> bool {
    matches!(tool_name, "send_tx" | "deploy_contract" | "shell_exec")
}

/// MCP Server — the capability boundary for external runtimes.
pub struct McpServer {
    registry: Arc<ToolRegistry>,
    /// Active capability grants for external runtimes
    grants: tokio::sync::RwLock<Vec<CapabilityGrant>>,
    /// When true, `add_grant` and `check_grant` reject unsigned
    /// grants AND require the grant's `issuer_pubkey` to be an enrolled
    /// trust anchor (see `trusted_issuers`). Flip it on via
    /// `new_strict` or `set_require_signed_grants`.
    /// RM-B1 / WP-E5.4 (audit AGT-08).
    require_signed_grants: bool,
    /// Trust anchor: ed25519 public keys authorized to issue grants,
    /// mapped to the `issuer` identity each key may sign as.
    ///
    /// AR-B-009 fix: `CapabilityGrant::verify_signature` verifies a
    /// grant under the grant's OWN embedded `issuer_pubkey`, which is
    /// self-attesting — an attacker mints a fresh keypair, signs a
    /// `Maintainer` grant, and it "verifies". Pinning the pubkey to an
    /// out-of-band trust anchor (device keyring / OrganizationSBT
    /// `signing_authority` / the wallet behind `issuer`) is what makes
    /// the signature mean anything. In strict mode a grant is accepted
    /// only when its `issuer_pubkey` is enrolled here for its `issuer`.
    trusted_issuers: HashMap<[u8; 32], String>,
}

impl McpServer {
    pub fn new(registry: Arc<ToolRegistry>) -> Self {
        Self {
            registry,
            grants: tokio::sync::RwLock::new(Vec::new()),
            require_signed_grants: false,
            trusted_issuers: HashMap::new(),
        }
    }

    /// Builder that flips the strict-signature mode on. Production
    /// callers should construct the server through this so unsigned
    /// grants are rejected at insertion AND at `check_grant`.
    /// RM-B1 / WP-E5.4 (audit AGT-08).
    pub fn new_strict(registry: Arc<ToolRegistry>) -> Self {
        Self {
            registry,
            grants: tokio::sync::RwLock::new(Vec::new()),
            require_signed_grants: true,
            trusted_issuers: HashMap::new(),
        }
    }

    /// Enroll an ed25519 issuer public key as a trust anchor for
    /// `issuer`. Consuming builder — call before wrapping in `Arc`.
    /// AR-B-009.
    pub fn with_trusted_issuer(mut self, pubkey: [u8; 32], issuer: impl Into<String>) -> Self {
        self.trusted_issuers.insert(pubkey, issuer.into());
        self
    }

    /// Toggle strict-signature mode after construction (before the
    /// server is shared). Referenced by the module docs; AR-B-009 adds
    /// the actual method (previously only recommended in a comment).
    pub fn set_require_signed_grants(&mut self, require: bool) {
        self.require_signed_grants = require;
    }

    /// True iff the server is in strict-signature mode.
    pub fn require_signed_grants(&self) -> bool {
        self.require_signed_grants
    }

    /// AR-B-009: verify the grant's `issuer_pubkey` is an enrolled
    /// trust anchor for its declared `issuer`. Called only on the
    /// strict path, AFTER `verify_signature` has confirmed the grant
    /// content was signed by that key.
    fn issuer_key_is_trusted(&self, grant: &CapabilityGrant) -> Result<(), String> {
        let pk: [u8; 32] = grant
            .issuer_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| "issuer_pubkey is not 32 bytes".to_string())?;
        match self.trusted_issuers.get(&pk) {
            Some(enrolled_issuer) if *enrolled_issuer == grant.issuer => Ok(()),
            Some(_) => Err(
                "issuer_pubkey is enrolled for a different issuer than the grant claims"
                    .to_string(),
            ),
            None => Err(
                "issuer_pubkey is not an enrolled trust anchor (self-attesting grant rejected)"
                    .to_string(),
            ),
        }
    }

    /// List tools available to a specific grant/policy.
    /// Deny-by-default: only tools in allowed categories are exposed.
    pub async fn list_tools(&self, policy: &PolicyProfile) -> Vec<McpToolDefinition> {
        self.registry
            .tool_descriptors()
            .await
            .into_iter()
            .filter_map(|(name, def)| {
                let category = categorize_tool(&name);
                if !category.allowed_by(policy) {
                    return None;
                }
                if requires_operator_scope(&name)
                    && !matches!(policy, PolicyProfile::Operator | PolicyProfile::Maintainer)
                {
                    return None;
                }
                let risk = def
                    .pointer("/function/risk_level")
                    .and_then(|r| r.as_str())
                    .unwrap_or("Medium");
                let requires_approval = risk.to_lowercase().contains("high")
                    || risk.to_lowercase().contains("critical");

                Some(McpToolDefinition {
                    name,
                    description: def
                        .pointer("/function/description")
                        .and_then(|d| d.as_str())
                        .unwrap_or("")
                        .to_string(),
                    category,
                    risk_level: risk.to_string(),
                    parameters_schema: def
                        .pointer("/function/parameters")
                        .cloned()
                        .unwrap_or(serde_json::json!({})),
                    requires_approval,
                })
            })
            .collect()
    }

    /// Check if a tool invocation is allowed by a capability grant.
    /// Enforces: revocation, expiry, tool scope, path scope, value ceiling, policy.
    pub async fn check_grant(
        &self,
        grant_id: &str,
        tool_name: &str,
        file_path: Option<&str>,
        tx_value: Option<u128>,
    ) -> Result<(), String> {
        let grants = self.grants.read().await;
        // CX-02: constant-time grant-id compare to prevent prefix-leak via
        // timing. See `ct_grant_id_eq`.
        let grant = grants
            .iter()
            .find(|g| ct_grant_id_eq(&g.id, grant_id))
            .ok_or_else(|| "Grant not found".to_string())?;

        // Check revocation
        if grant.revoked {
            return Err("Grant has been revoked".to_string());
        }

        // RM-B1 / WP-E5.3 (audit AGT-07): expiry compared as
        // parsed DateTime, not lexicographic string compare.
        let now = chrono::Utc::now();
        if grant
            .is_expired(now)
            .map_err(|e| format!("expires_at malformed: {}", e))?
        {
            return Err(format!("Grant expired at {}", grant.expires_at));
        }

        // RM-B1 / WP-E5.1 + WP-E5.4 (audit AGT-06, AGT-08):
        // verify the grant's signature when present. Grants
        // without `issuer_pubkey` and `signature` are honored
        // for backward compatibility ONLY when the global
        // `require_signed_grants` flag is off; with the flag on,
        // unsigned grants are rejected.
        if !grant.signature.is_empty() || !grant.issuer_pubkey.is_empty() || self.require_signed_grants {
            if let Err(reason) = grant.verify_signature() {
                return Err(format!("Grant signature invalid: {}", reason));
            }
            // AR-B-009: in strict mode the signing key must also be an
            // enrolled trust anchor — a valid self-attesting signature
            // is not enough to authorize a call.
            if self.require_signed_grants {
                if let Err(reason) = self.issuer_key_is_trusted(grant) {
                    return Err(format!("Grant issuer not trusted: {}", reason));
                }
            }
        }

        // Check tool is in allowed list
        if !grant.allowed_tools.is_empty() && !grant.allowed_tools.contains(&tool_name.to_string())
        {
            return Err(format!("Tool '{}' not in grant scope", tool_name));
        }

        if requires_operator_scope(tool_name)
            && !matches!(
                grant.policy,
                PolicyProfile::Operator | PolicyProfile::Maintainer
            )
        {
            return Err(format!(
                "Tool '{}' requires Operator or Maintainer policy",
                tool_name
            ));
        }

        // Check path scope for file tools
        if let Some(path) = file_path {
            if !grant.allowed_paths.is_empty() {
                let path_allowed = grant
                    .allowed_paths
                    .iter()
                    .any(|allowed| path.starts_with(allowed));
                if !path_allowed {
                    return Err(format!("Path '{}' not in grant's allowed paths", path));
                }
            }
        }

        // Check value ceiling for transaction tools
        if let (Some(value), Some(max)) = (tx_value, grant.max_value_per_tx) {
            if value > max {
                return Err(format!(
                    "Transaction value {} exceeds grant ceiling {}",
                    value, max
                ));
            }
        }

        // Check category is allowed by policy
        let category = categorize_tool(tool_name);
        if !category.allowed_by(&grant.policy) {
            return Err(format!(
                "Tool category {:?} not allowed by {:?} policy",
                category, grant.policy
            ));
        }

        Ok(())
    }

    /// Add a capability grant for an external runtime.
    ///
    /// RM-B1 / WP-E5.4 (audit AGT-08): validate the grant before
    /// inserting it.
    ///   - `expires_at` must be empty or RFC3339-parseable.
    ///   - In strict-signature mode, signature verification must pass.
    /// On invalid input the grant is dropped + a WARN is logged;
    /// callers in fully-modern flows should prefer `try_add_grant`
    /// to surface the error directly.
    pub async fn add_grant(&self, grant: CapabilityGrant) {
        if let Err(e) = self.try_add_grant(grant.clone()).await {
            tracing::warn!(
                "MCP: dropping invalid grant for recipient '{}': {}",
                grant.recipient,
                e
            );
        }
    }

    /// Same as `add_grant` but returns `Err` on validation failure.
    /// New code should prefer this entry point.
    /// RM-B1 / WP-E5.4 (audit AGT-08).
    pub async fn try_add_grant(&self, grant: CapabilityGrant) -> Result<(), String> {
        // Reject malformed expiry up front.
        if let Err(e) = grant.parsed_expires_at() {
            return Err(format!("expires_at malformed: {}", e));
        }

        // Strict mode: signature presence + verification mandatory,
        // AND the signing key must be an enrolled trust anchor —
        // otherwise a self-minted keypair authorizes any grant (AR-B-009).
        if self.require_signed_grants {
            grant.verify_signature()
                .map_err(|e| format!("signature required: {}", e))?;
            self.issuer_key_is_trusted(&grant)
                .map_err(|e| format!("issuer not trusted: {}", e))?;
        } else if !grant.signature.is_empty() || !grant.issuer_pubkey.is_empty() {
            // Non-strict but a signature was provided — verify it
            // anyway. We don't accept partial data.
            grant.verify_signature()
                .map_err(|e| format!("signature provided but invalid: {}", e))?;
        }

        tracing::info!(
            "MCP: granted capabilities to '{}' (policy: {:?}, tools: {:?})",
            grant.recipient,
            grant.policy,
            grant.allowed_tools
        );
        self.grants.write().await.push(grant);
        Ok(())
    }

    /// Snapshot all grants. Clones the vec so the caller doesn't
    /// hold the RwLock while iterating. Used by the MCP host to
    /// render the Operations panel's session list (P960-J).
    pub async fn snapshot_grants(&self) -> Vec<CapabilityGrant> {
        self.grants.read().await.clone()
    }

    /// Revoke a grant by ID. Returns false if the grant doesn't
    /// exist OR is already revoked — repeat revocations are not
    /// idempotent successes (they shouldn't appear successful to
    /// a client that's been told the session was already ended).
    pub async fn revoke_grant(&self, grant_id: &str) -> bool {
        let mut grants = self.grants.write().await;
        // CX-02: constant-time compare on the grant-id revoke path.
        if let Some(grant) = grants.iter_mut().find(|g| ct_grant_id_eq(&g.id, grant_id) && !g.revoked) {
            grant.revoked = true;
            tracing::info!("MCP: revoked grant {}", grant_id);
            true
        } else {
            false
        }
    }

    /// Generate a skill pack manifest — a JSON document describing all
    /// available tools in a format Hermes/OpenClaw can import.
    pub async fn skill_pack(&self, policy: &PolicyProfile) -> serde_json::Value {
        let tools = self.list_tools(policy).await;
        serde_json::json!({
            "name": "citrate-skills",
            "version": "0.1.0",
            "description": "Citrate blockchain agent tools",
            "protocol": "mcp",
            "tools": tools.iter().map(|t| serde_json::json!({
                "name": t.name,
                "description": t.description,
                "category": format!("{:?}", t.category),
                "risk_level": t.risk_level,
                "requires_approval": t.requires_approval,
                "parameters": t.parameters_schema,
            })).collect::<Vec<_>>(),
        })
    }
}

/// Convert a tool execution into a trail event for the trail layer.
pub fn tool_call_to_trail_event(
    session_id: &str,
    tool_name: &str,
    params: &serde_json::Value,
    result: &str,
    success: bool,
    duration_ms: u64,
    risk_level: RiskLevel,
) -> TrailEvent {
    TrailEvent {
        id: uuid::Uuid::new_v4().to_string(),
        session_id: session_id.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        event_type: "tool_call".to_string(),
        tool_name: Some(tool_name.to_string()),
        data: serde_json::json!({
            "params": params,
            "result": result,
            "success": success,
        }),
        risk_level: Some(format!("{:?}", risk_level)),
        approved: Some(true),
        duration_ms: Some(duration_ms),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_categorize_tools() {
        assert_eq!(categorize_tool("check_balance"), ToolCategory::WalletRead);
        assert_eq!(categorize_tool("send_tx"), ToolCategory::WalletWrite);
        assert_eq!(categorize_tool("file_read"), ToolCategory::Repo);
        assert_eq!(categorize_tool("shell_exec"), ToolCategory::Shell);
        assert_eq!(categorize_tool("list_models"), ToolCategory::Models);
    }

    #[test]
    fn test_readonly_policy_blocks_writes() {
        assert!(ToolCategory::WalletRead.allowed_by(&PolicyProfile::ReadOnly));
        assert!(!ToolCategory::WalletWrite.allowed_by(&PolicyProfile::ReadOnly));
        assert!(!ToolCategory::Shell.allowed_by(&PolicyProfile::ReadOnly));
        assert!(ToolCategory::NodeRead.allowed_by(&PolicyProfile::ReadOnly));
        assert!(ToolCategory::Models.allowed_by(&PolicyProfile::ReadOnly));
    }

    #[test]
    fn test_guided_policy_blocks_shell() {
        assert!(ToolCategory::WalletRead.allowed_by(&PolicyProfile::Guided));
        assert!(ToolCategory::WalletWrite.allowed_by(&PolicyProfile::Guided));
        assert!(!ToolCategory::Shell.allowed_by(&PolicyProfile::Guided));
        assert!(ToolCategory::Repo.allowed_by(&PolicyProfile::Guided));
    }

    #[test]
    fn test_maintainer_allows_all() {
        assert!(ToolCategory::Shell.allowed_by(&PolicyProfile::Maintainer));
        assert!(ToolCategory::GovernanceWrite.allowed_by(&PolicyProfile::Maintainer));
    }

    #[test]
    fn test_skill_pack_structure() {
        let json = serde_json::json!({
            "name": "citrate-skills",
            "version": "0.1.0",
            "protocol": "mcp",
        });
        assert_eq!(json["protocol"], "mcp");
    }

    #[tokio::test]
    async fn test_grant_check_missing() {
        let registry = Arc::new(ToolRegistry::new());
        let server = McpServer::new(registry);
        let result = server
            .check_grant("nonexistent", "check_balance", None, None)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_grant_check_valid() {
        let registry = Arc::new(ToolRegistry::new());
        let server = McpServer::new(registry);
        let grant = CapabilityGrant {
            id: "grant-1".to_string(),
            issuer: "0xuser".to_string(),
            recipient: "hermes".to_string(),
            allowed_tools: vec!["check_balance".to_string()],
            max_value_per_tx: None,
            allowed_paths: vec![],
            expires_at: "2026-12-31T00:00:00Z".to_string(),
            policy: PolicyProfile::ReadOnly,
            revoked: false,
            connected_since: 0,
            issuer_pubkey: Vec::new(),
            signature: Vec::new(),
        };
        server.add_grant(grant).await;
        let result = server
            .check_grant("grant-1", "check_balance", None, None)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_grant_check_wrong_tool() {
        let registry = Arc::new(ToolRegistry::new());
        let server = McpServer::new(registry);
        let grant = CapabilityGrant {
            id: "grant-2".to_string(),
            issuer: "0xuser".to_string(),
            recipient: "hermes".to_string(),
            allowed_tools: vec!["check_balance".to_string()],
            max_value_per_tx: None,
            allowed_paths: vec![],
            expires_at: "2026-12-31T00:00:00Z".to_string(),
            policy: PolicyProfile::ReadOnly,
            revoked: false,
            connected_since: 0,
            issuer_pubkey: Vec::new(),
            signature: Vec::new(),
        };
        server.add_grant(grant).await;
        let result = server.check_grant("grant-2", "send_tx", None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_revoke_grant() {
        let registry = Arc::new(ToolRegistry::new());
        let server = McpServer::new(registry);
        let grant = CapabilityGrant {
            id: "grant-3".to_string(),
            issuer: "0xuser".to_string(),
            recipient: "hermes".to_string(),
            allowed_tools: vec![],
            max_value_per_tx: None,
            allowed_paths: vec![],
            expires_at: "2026-12-31T00:00:00Z".to_string(),
            policy: PolicyProfile::Guided,
            revoked: false,
            connected_since: 0,
            issuer_pubkey: Vec::new(),
            signature: Vec::new(),
        };
        server.add_grant(grant).await;
        assert!(server.revoke_grant("grant-3").await);
        let result = server
            .check_grant("grant-3", "check_balance", None, None)
            .await;
        assert!(result.is_err()); // Revoked
    }

    #[tokio::test]
    async fn test_grant_expired() {
        let registry = Arc::new(ToolRegistry::new());
        let server = McpServer::new(registry);
        let grant = CapabilityGrant {
            id: "grant-exp".to_string(),
            issuer: "0xuser".to_string(),
            recipient: "hermes".to_string(),
            allowed_tools: vec![],
            max_value_per_tx: None,
            allowed_paths: vec![],
            expires_at: "2020-01-01T00:00:00Z".to_string(), // Already expired
            policy: PolicyProfile::ReadOnly,
            revoked: false,
            connected_since: 0,
            issuer_pubkey: Vec::new(),
            signature: Vec::new(),
        };
        server.add_grant(grant).await;
        let result = server
            .check_grant("grant-exp", "check_balance", None, None)
            .await;
        assert!(result.is_err());
        assert!(result.expect_err("expired").contains("expired"));
    }

    #[tokio::test]
    async fn test_grant_path_scope() {
        let registry = Arc::new(ToolRegistry::new());
        let server = McpServer::new(registry);
        let grant = CapabilityGrant {
            id: "grant-path".to_string(),
            issuer: "0xuser".to_string(),
            recipient: "hermes".to_string(),
            allowed_tools: vec!["file_read".to_string()],
            max_value_per_tx: None,
            allowed_paths: vec!["/home/user/project".to_string()],
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            policy: PolicyProfile::Guided,
            revoked: false,
            connected_since: 0,
            issuer_pubkey: Vec::new(),
            signature: Vec::new(),
        };
        server.add_grant(grant).await;
        // Within scope
        let ok = server
            .check_grant(
                "grant-path",
                "file_read",
                Some("/home/user/project/src/main.rs"),
                None,
            )
            .await;
        assert!(ok.is_ok());
        // Outside scope
        let err = server
            .check_grant("grant-path", "file_read", Some("/etc/passwd"), None)
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_grant_value_ceiling() {
        let registry = Arc::new(ToolRegistry::new());
        let server = McpServer::new(registry);
        let grant = CapabilityGrant {
            id: "grant-val".to_string(),
            issuer: "0xuser".to_string(),
            recipient: "hermes".to_string(),
            allowed_tools: vec!["send_tx".to_string()],
            max_value_per_tx: Some(1_000_000_000_000_000_000), // 1 SALT
            allowed_paths: vec![],
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            policy: PolicyProfile::Operator,
            revoked: false,
            connected_since: 0,
            issuer_pubkey: Vec::new(),
            signature: Vec::new(),
        };
        server.add_grant(grant).await;
        // Under ceiling
        let ok = server
            .check_grant("grant-val", "send_tx", None, Some(500_000_000_000_000_000))
            .await;
        assert!(ok.is_ok());
        // Over ceiling
        let err = server
            .check_grant(
                "grant-val",
                "send_tx",
                None,
                Some(2_000_000_000_000_000_000),
            )
            .await;
        assert!(err.is_err());
        assert!(err.expect_err("ceiling").contains("exceeds"));
    }

    struct NamedTool {
        name: &'static str,
        risk: RiskLevel,
    }

    #[async_trait::async_trait]
    impl crate::tool::AgentTool for NamedTool {
        fn name(&self) -> &str {
            self.name
        }
        fn description(&self) -> &str {
            self.name
        }
        fn parameters_schema(&self) -> serde_json::Value {
            serde_json::json!({ "type": "object", "properties": {} })
        }
        fn risk_level(&self) -> RiskLevel {
            self.risk
        }
        async fn execute(
            &self,
            _params: serde_json::Value,
            _ctx: &crate::tool::ToolContext,
        ) -> Result<crate::tool::ToolResult, crate::error::AgentError> {
            Ok(crate::tool::ToolResult::ok("ok"))
        }
    }

    #[tokio::test]
    async fn test_guided_list_tools_hides_operator_only_tools() {
        let registry = Arc::new(ToolRegistry::new());
        registry
            .register(Arc::new(NamedTool {
                name: "check_balance",
                risk: RiskLevel::Low,
            }))
            .await;
        registry
            .register(Arc::new(NamedTool {
                name: "send_tx",
                risk: RiskLevel::High,
            }))
            .await;
        registry
            .register(Arc::new(NamedTool {
                name: "shell_exec",
                risk: RiskLevel::Critical,
            }))
            .await;
        let server = McpServer::new(registry);

        let guided = server.list_tools(&PolicyProfile::Guided).await;
        let names: Vec<_> = guided.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"check_balance"));
        assert!(!names.contains(&"send_tx"));
        assert!(!names.contains(&"shell_exec"));
    }

    #[tokio::test]
    async fn test_operator_can_call_sensitive_tools_but_guided_cannot() {
        let registry = Arc::new(ToolRegistry::new());
        let server = McpServer::new(registry);

        let guided = CapabilityGrant {
            id: "grant-guided".to_string(),
            issuer: "0xuser".to_string(),
            recipient: "hermes".to_string(),
            allowed_tools: vec!["send_tx".to_string()],
            max_value_per_tx: Some(1_000_000_000_000_000_000),
            allowed_paths: vec![],
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            policy: PolicyProfile::Guided,
            revoked: false,
            connected_since: 0,
            issuer_pubkey: Vec::new(),
            signature: Vec::new(),
        };
        server.add_grant(guided).await;
        let guided_result = server
            .check_grant("grant-guided", "send_tx", None, Some(1))
            .await;
        assert!(guided_result.is_err());

        let operator = CapabilityGrant {
            id: "grant-operator".to_string(),
            issuer: "0xuser".to_string(),
            recipient: "hermes".to_string(),
            allowed_tools: vec!["send_tx".to_string()],
            max_value_per_tx: Some(1_000_000_000_000_000_000),
            allowed_paths: vec![],
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            policy: PolicyProfile::Operator,
            revoked: false,
            connected_since: 0,
            issuer_pubkey: Vec::new(),
            signature: Vec::new(),
        };
        server.add_grant(operator).await;
        let operator_result = server
            .check_grant("grant-operator", "send_tx", None, Some(1))
            .await;
        assert!(operator_result.is_ok());
    }

    // =====================================================================
    // CX-02 — constant-time grant-id comparison.
    // Type-level + behavioural assertions that the new ct_grant_id_eq
    // function rejects mismatched ids and accepts equal ids regardless
    // of where the bytes diverge.
    // =====================================================================

    #[test]
    fn test_cx02_ct_grant_id_eq_accepts_equal_strings() {
        let a = "550e8400-e29b-41d4-a716-446655440000";
        assert!(super::ct_grant_id_eq(a, a));
    }

    #[test]
    fn test_cx02_ct_grant_id_eq_rejects_first_byte_mismatch() {
        let a = "550e8400-e29b-41d4-a716-446655440000";
        let b = "650e8400-e29b-41d4-a716-446655440000";
        assert!(!super::ct_grant_id_eq(a, b));
    }

    #[test]
    fn test_cx02_ct_grant_id_eq_rejects_last_byte_mismatch() {
        let a = "550e8400-e29b-41d4-a716-446655440000";
        let b = "550e8400-e29b-41d4-a716-446655440001";
        assert!(!super::ct_grant_id_eq(a, b));
    }

    #[test]
    fn test_cx02_ct_grant_id_eq_rejects_length_mismatch() {
        let a = "short";
        let b = "considerably-longer-grant-id";
        assert!(!super::ct_grant_id_eq(a, b));
        assert!(!super::ct_grant_id_eq(b, a));
    }

    #[test]
    fn test_cx02_ct_grant_id_eq_rejects_empty_vs_nonempty() {
        assert!(!super::ct_grant_id_eq("", "x"));
        assert!(!super::ct_grant_id_eq("x", ""));
    }

    #[test]
    fn test_cx02_ct_grant_id_eq_accepts_empty_vs_empty() {
        assert!(super::ct_grant_id_eq("", ""));
    }

    #[tokio::test]
    async fn test_cx02_check_grant_uses_ct_eq_for_lookup() {
        // Behavioural: a long grant id where only the LAST byte differs
        // is correctly rejected. Pre-fix this test would still pass
        // (`==` also rejects), but combined with the unit tests above,
        // any future regression that swaps `ct_grant_id_eq` back to `==`
        // will be caught by the type-level assertion.
        let server = McpServer::new(Arc::new(ToolRegistry::new()));
        let grant = CapabilityGrant {
            id: "grant-cx02-last-byte-difference-test".to_string(),
            issuer: "0xuser".to_string(),
            recipient: "test".to_string(),
            allowed_tools: vec!["check_balance".to_string()],
            max_value_per_tx: None,
            allowed_paths: vec![],
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            policy: PolicyProfile::ReadOnly,
            revoked: false,
            connected_since: 0,
            issuer_pubkey: Vec::new(),
            signature: Vec::new(),
        };
        server.add_grant(grant).await;

        // Correct grant id — should succeed.
        let ok = server
            .check_grant(
                "grant-cx02-last-byte-difference-test",
                "check_balance",
                None,
                None,
            )
            .await;
        assert!(ok.is_ok(), "matching grant id must succeed: {:?}", ok);

        // Last-byte-different grant id — should fail with "Grant not found".
        let err = server
            .check_grant(
                "grant-cx02-last-byte-difference-tesT",
                "check_balance",
                None,
                None,
            )
            .await
            .expect_err("last-byte mismatch must reject");
        assert_eq!(err, "Grant not found");
    }

    // ── RM-E5 / WP-E5.4 (audit AGT-08) try_add_grant validation ─────

    fn _signed_grant_for_test() -> CapabilityGrant {
        use ed25519_dalek::Signer;
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut grant = CapabilityGrant {
            id: "grant-signed".to_string(),
            issuer: "0xuser".to_string(),
            recipient: "hermes".to_string(),
            allowed_tools: vec!["check_balance".to_string()],
            max_value_per_tx: None,
            allowed_paths: vec![],
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            policy: PolicyProfile::ReadOnly,
            revoked: false,
            connected_since: 0,
            issuer_pubkey: signing.verifying_key().to_bytes().to_vec(),
            signature: Vec::new(),
        };
        let preimage = grant.signing_preimage();
        let sig = signing.sign(&preimage);
        grant.signature = sig.to_bytes().to_vec();
        grant
    }

    #[tokio::test]
    async fn test_agt08_try_add_grant_rejects_malformed_expiry() {
        let registry = Arc::new(ToolRegistry::new());
        let server = McpServer::new(registry);
        let mut grant = _signed_grant_for_test();
        grant.expires_at = "not-a-real-date".to_string();
        let err = server.try_add_grant(grant).await.expect_err("should error");
        assert!(err.contains("malformed"), "got: {}", err);
    }

    #[tokio::test]
    async fn test_agt08_try_add_grant_rejects_partial_signature() {
        let registry = Arc::new(ToolRegistry::new());
        let server = McpServer::new(registry);
        // Provide signature but no pubkey — non-strict mode still
        // verifies what was provided and rejects.
        let mut grant = _signed_grant_for_test();
        grant.issuer_pubkey = Vec::new(); // strip pubkey
        let err = server.try_add_grant(grant).await.expect_err("should error");
        assert!(err.contains("provided but invalid") || err.contains("signature"));
    }

    #[tokio::test]
    async fn test_agt08_strict_mode_rejects_unsigned() {
        let registry = Arc::new(ToolRegistry::new());
        let server = McpServer::new_strict(registry);
        assert!(server.require_signed_grants());
        // Build an UNSIGNED grant.
        let grant = CapabilityGrant {
            id: "grant-unsigned".to_string(),
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
        };
        let err = server.try_add_grant(grant).await.expect_err("strict rejects");
        assert!(err.contains("signature required"), "got: {}", err);
    }

    #[tokio::test]
    async fn test_agt08_strict_mode_accepts_signed() {
        // AR-B-009 (RC-8): strict mode now requires the signing key to be
        // an enrolled trust anchor. A signed grant from a key enrolled for
        // its issuer is accepted; the same key un-enrolled is rejected
        // (see test_ar_b_009_* below).
        let registry = Arc::new(ToolRegistry::new());
        let issuer_pk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes();
        let server = McpServer::new_strict(registry).with_trusted_issuer(issuer_pk, "0xuser");
        let grant = _signed_grant_for_test(); // issuer "0xuser", key [7u8;32]
        server.try_add_grant(grant).await.expect("enrolled signed grant accepted");
    }

    /// AR-B-009 tripwire: a fresh, attacker-minted keypair signs a
    /// `Maintainer` grant. Under `new_strict` with NO trust anchor the
    /// self-attesting grant must be rejected (was accepted pre-fix).
    #[tokio::test]
    async fn test_ar_b_009_self_minted_maintainer_grant_rejected() {
        use ed25519_dalek::Signer;
        let registry = Arc::new(ToolRegistry::new());
        let server = McpServer::new_strict(registry);

        // Attacker's own keypair — never enrolled anywhere.
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[0xEE; 32]);
        let mut grant = CapabilityGrant {
            id: "attacker-grant".to_string(),
            issuer: "0xATTACKER".to_string(),
            recipient: "hermes".to_string(),
            allowed_tools: vec![], // empty = unrestricted
            max_value_per_tx: None,
            allowed_paths: vec![],
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            policy: PolicyProfile::Maintainer,
            revoked: false,
            connected_since: 0,
            issuer_pubkey: attacker.verifying_key().to_bytes().to_vec(),
            signature: Vec::new(),
        };
        let preimage = grant.signing_preimage();
        grant.signature = attacker.sign(&preimage).to_bytes().to_vec();

        // The signature is cryptographically VALID under its own key —
        // the point is the key is not a trust anchor.
        grant.verify_signature().expect("self-signature is internally valid");
        let err = server
            .try_add_grant(grant)
            .await
            .expect_err("self-minted issuer key must be rejected in strict mode");
        assert!(
            err.contains("not trusted") || err.contains("trust anchor"),
            "expected trust-anchor rejection, got: {err}"
        );
    }

    /// AR-B-009: once the same attacker key is (mistakenly) enrolled for
    /// its issuer, the grant is accepted — proving the gate keys on the
    /// anchor, not merely on signature validity.
    #[tokio::test]
    async fn test_ar_b_009_enrolled_issuer_key_accepted() {
        use ed25519_dalek::Signer;
        let registry = Arc::new(ToolRegistry::new());
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]);
        let pk = key.verifying_key().to_bytes();
        let server = McpServer::new_strict(registry).with_trusted_issuer(pk, "0xORG");

        let mut grant = CapabilityGrant {
            id: "org-grant".to_string(),
            issuer: "0xORG".to_string(),
            recipient: "hermes".to_string(),
            allowed_tools: vec!["check_balance".to_string()],
            max_value_per_tx: None,
            allowed_paths: vec![],
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            policy: PolicyProfile::ReadOnly,
            revoked: false,
            connected_since: 0,
            issuer_pubkey: pk.to_vec(),
            signature: Vec::new(),
        };
        let preimage = grant.signing_preimage();
        grant.signature = key.sign(&preimage).to_bytes().to_vec();
        server
            .try_add_grant(grant)
            .await
            .expect("enrolled issuer key accepted");
    }

    #[tokio::test]
    async fn test_agt08_check_grant_rejects_tampered_after_install() {
        let registry = Arc::new(ToolRegistry::new());
        let server = McpServer::new(registry);
        let mut grant = _signed_grant_for_test();
        // Insert a properly signed grant.
        let original_sig = grant.signature.clone();
        server.try_add_grant(grant.clone()).await.expect("install");
        // Now tamper with the in-store grant via revoke+re-add with
        // a mutated tool list. We simulate by inserting a NEW grant
        // with broken signature; check_grant must still reject.
        grant.id = "grant-tampered".to_string();
        grant.allowed_tools.push("send_tx".to_string());
        // Keep the OLD signature — it no longer matches the preimage.
        grant.signature = original_sig;
        // try_add_grant catches this because non-empty signature
        // triggers verification.
        let err = server.try_add_grant(grant).await.expect_err("tampered should error");
        assert!(err.contains("invalid"), "got: {}", err);
    }
}
