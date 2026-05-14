//! Hermes sidecar adapter — the flagship external runtime interop.
//!
//! Hermes connects to Citrate through MCP. This adapter provides:
//! - Sidecar configuration for Hermes to discover Citrate tools
//! - Skill pack export in Hermes-compatible format
//! - Trail event ingest from Hermes sessions
//! - LogSeq sync mode for shared note persistence
//!
//! Hermes is a PARTNER, not the AUTHORITY. All tool execution goes
//! through Citrate's ApprovalFlow and CapabilityGrant system.

use crate::canonical::{BenchmarkTrace, PolicyProfile, TrailEvent};
use crate::mcp_server::McpServer;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Hermes sidecar configuration — what Hermes needs to connect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HermesSidecarConfig {
    /// Citrate MCP endpoint (localhost for embedded, remote for networked)
    pub mcp_endpoint: String,
    /// Grant ID for this Hermes instance
    pub grant_id: String,
    /// Policy profile (ReadOnly for first integration)
    pub policy: PolicyProfile,
    /// Skill pack URL or path (IPFS CID or local file)
    pub skill_pack: String,
    /// Whether to sync notes to LogSeq
    pub logseq_sync: bool,
    /// Whether to export benchmark traces
    pub benchmark_export: bool,
}

impl Default for HermesSidecarConfig {
    fn default() -> Self {
        Self {
            mcp_endpoint: "http://localhost:18546/mcp".to_string(),
            grant_id: String::new(),
            policy: PolicyProfile::ReadOnly,
            skill_pack: String::new(),
            logseq_sync: true,
            benchmark_export: false,
        }
    }
}

/// Hermes adapter — bridges Hermes sessions to Citrate's substrate.
pub struct HermesAdapter {
    config: HermesSidecarConfig,
    mcp: Arc<McpServer>,
    /// Ed25519 public key authorized to sign Hermes events. When
    /// `None`, signature checking is OFF (legacy mode); production
    /// callers should set this via `with_signing_key`.
    /// RM-B1 / WP-E5.7 (audit AGT-12).
    expected_signer: Option<[u8; 32]>,
}

impl HermesAdapter {
    pub fn new(config: HermesSidecarConfig, mcp: Arc<McpServer>) -> Self {
        Self { config, mcp, expected_signer: None }
    }

    /// Configure the expected ed25519 signer for incoming Hermes
    /// events. After this is set, `ingest_hermes_event` requires
    /// every event to carry a valid `signature` over the canonical
    /// JSON form, signed by `signer_pubkey`.
    /// RM-B1 / WP-E5.7 (audit AGT-12).
    pub fn with_signing_key(mut self, signer_pubkey: [u8; 32]) -> Self {
        self.expected_signer = Some(signer_pubkey);
        self
    }

    /// Generate a Hermes-compatible skill pack from the MCP server.
    /// Hermes uses a specific skill format with name, description, and parameters.
    pub async fn export_skill_pack(&self) -> serde_json::Value {
        let pack = self.mcp.skill_pack(&self.config.policy).await;
        // Wrap in Hermes skill format
        serde_json::json!({
            "hermes_version": "1.0",
            "source": "citrate",
            "grant_id": self.config.grant_id,
            "policy": format!("{:?}", self.config.policy),
            "mcp_endpoint": self.config.mcp_endpoint,
            "skills": pack["tools"],
        })
    }

    /// Ingest a trail event from a Hermes session into Citrate's trail.
    /// Hermes events are normalized to TrailEvent format before ingestion.
    ///
    /// RM-B1 / WP-E5.7 (audit AGT-12): when `with_signing_key` has
    /// been set, the event MUST carry a top-level `signature` field
    /// (hex-encoded 64 bytes) over the canonical JSON of the event
    /// MINUS the signature field. Events that fail verification are
    /// dropped and logged at WARN.
    pub fn ingest_hermes_event(
        &self,
        hermes_event: &serde_json::Value,
        session_id: &str,
    ) -> Option<TrailEvent> {
        if let Some(expected) = self.expected_signer {
            if let Err(reason) = Self::verify_event_signature(hermes_event, &expected) {
                tracing::warn!(
                    "Hermes adapter: dropping unsigned/invalid event ({}). session={}",
                    reason,
                    session_id
                );
                return None;
            }
        }

        let event_type = hermes_event.get("type")?.as_str()?;
        let tool = hermes_event.get("tool").and_then(|t| t.as_str());
        let data = hermes_event
            .get("data")
            .cloned()
            .unwrap_or(serde_json::json!({}));

        Some(TrailEvent {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type: format!("hermes:{}", event_type),
            tool_name: tool.map(|t| t.to_string()),
            data,
            risk_level: None,
            approved: None,
            duration_ms: None,
        })
    }

    /// Verify the ed25519 signature over an inbound Hermes event.
    /// The signing pre-image is the event JSON serialized with the
    /// `signature` field stripped out — this lets the sender
    /// produce a stable byte string by canonicalizing and signing
    /// before adding the signature.
    fn verify_event_signature(
        event: &serde_json::Value,
        expected_pubkey: &[u8; 32],
    ) -> Result<(), String> {
        let sig_hex = event
            .get("signature")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing signature".to_string())?;
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| format!("signature not hex: {}", e))?;
        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| "signature not 64 bytes".to_string())?;

        let mut clone = event.clone();
        if let Some(obj) = clone.as_object_mut() {
            obj.remove("signature");
        }
        let canonical = serde_json::to_vec(&clone)
            .map_err(|e| format!("canonical serialize failed: {}", e))?;

        let verifying = ed25519_dalek::VerifyingKey::from_bytes(expected_pubkey)
            .map_err(|e| format!("bad expected_pubkey: {}", e))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_array);
        verifying
            .verify_strict(&canonical, &sig)
            .map_err(|e| format!("verify failed: {}", e))
    }

    /// Package a Hermes session as a BenchmarkTrace for research export.
    pub fn package_benchmark(
        &self,
        session_id: &str,
        task: &str,
        model: &str,
        events: Vec<TrailEvent>,
        success: bool,
    ) -> BenchmarkTrace {
        let total_ms: u64 = events.iter().filter_map(|e| e.duration_ms).sum();
        let tool_count = events.iter().filter(|e| e.tool_name.is_some()).count() as u32;
        let approval_count = events.iter().filter(|e| e.approved.is_some()).count() as u32;

        BenchmarkTrace {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            task: task.to_string(),
            model: model.to_string(),
            events,
            total_duration_ms: total_ms,
            tool_call_count: tool_count,
            approval_count,
            success,
            human_rating: None,
        }
    }

    /// Get the sidecar configuration.
    pub fn config(&self) -> &HermesSidecarConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool::ToolRegistry;

    #[test]
    fn test_default_config() {
        let config = HermesSidecarConfig::default();
        assert_eq!(config.policy, PolicyProfile::ReadOnly);
        assert!(config.logseq_sync);
        assert!(!config.benchmark_export);
    }

    #[tokio::test]
    async fn test_export_skill_pack() {
        let registry = Arc::new(ToolRegistry::new());
        let mcp = Arc::new(McpServer::new(registry));
        let config = HermesSidecarConfig::default();
        let adapter = HermesAdapter::new(config, mcp);
        let pack = adapter.export_skill_pack().await;
        assert_eq!(pack["hermes_version"], "1.0");
        assert_eq!(pack["source"], "citrate");
    }

    #[test]
    fn test_ingest_hermes_event() {
        let registry = Arc::new(ToolRegistry::new());
        let mcp = Arc::new(McpServer::new(registry));
        let adapter = HermesAdapter::new(HermesSidecarConfig::default(), mcp);

        let hermes_event = serde_json::json!({
            "type": "tool_call",
            "tool": "check_balance",
            "data": {"address": "0x1234"},
        });
        let trail = adapter.ingest_hermes_event(&hermes_event, "hermes-sess-1");
        assert!(trail.is_some());
        let event = trail.expect("event exists");
        assert_eq!(event.event_type, "hermes:tool_call");
        assert_eq!(event.tool_name.as_deref(), Some("check_balance"));
    }

    // ── RM-E5 / WP-E5.7 (audit AGT-12) Hermes signed events ─────────

    /// Sign an event JSON and return it with a `signature` field.
    fn sign_event(
        event: serde_json::Value,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> serde_json::Value {
        use ed25519_dalek::Signer;
        let canonical = serde_json::to_vec(&event).expect("ser");
        let sig = signing_key.sign(&canonical);
        let mut signed = event;
        if let Some(obj) = signed.as_object_mut() {
            obj.insert(
                "signature".to_string(),
                serde_json::Value::String(hex::encode(sig.to_bytes())),
            );
        }
        signed
    }

    #[test]
    fn test_agt12_unsigned_event_rejected_when_key_set() {
        let registry = Arc::new(ToolRegistry::new());
        let mcp = Arc::new(McpServer::new(registry));
        let signing = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let adapter = HermesAdapter::new(HermesSidecarConfig::default(), mcp)
            .with_signing_key(signing.verifying_key().to_bytes());

        let unsigned = serde_json::json!({
            "type": "tool_call",
            "tool": "check_balance",
            "data": {"address": "0x1234"},
        });
        let trail = adapter.ingest_hermes_event(&unsigned, "sess-1");
        assert!(trail.is_none(), "AGT-12: unsigned event must be dropped");
    }

    #[test]
    fn test_agt12_signed_event_accepted() {
        let registry = Arc::new(ToolRegistry::new());
        let mcp = Arc::new(McpServer::new(registry));
        let signing = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let adapter = HermesAdapter::new(HermesSidecarConfig::default(), mcp)
            .with_signing_key(signing.verifying_key().to_bytes());

        let event = serde_json::json!({
            "type": "tool_call",
            "tool": "check_balance",
            "data": {"address": "0x1234"},
        });
        let signed = sign_event(event, &signing);
        let trail = adapter.ingest_hermes_event(&signed, "sess-1");
        assert!(trail.is_some(), "valid signature must be accepted");
    }

    #[test]
    fn test_agt12_tampered_event_rejected() {
        let registry = Arc::new(ToolRegistry::new());
        let mcp = Arc::new(McpServer::new(registry));
        let signing = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let adapter = HermesAdapter::new(HermesSidecarConfig::default(), mcp)
            .with_signing_key(signing.verifying_key().to_bytes());

        let event = serde_json::json!({
            "type": "tool_call",
            "tool": "check_balance",
            "data": {"address": "0x1234"},
        });
        let mut signed = sign_event(event, &signing);
        // Mutate the data after signing.
        if let Some(obj) = signed.as_object_mut() {
            obj.insert(
                "tool".to_string(),
                serde_json::Value::String("send_tx".to_string()),
            );
        }
        let trail = adapter.ingest_hermes_event(&signed, "sess-1");
        assert!(trail.is_none(), "tampered event must be rejected");
    }

    #[test]
    fn test_agt12_wrong_key_rejected() {
        let registry = Arc::new(ToolRegistry::new());
        let mcp = Arc::new(McpServer::new(registry));
        let signing = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let other = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);
        let adapter = HermesAdapter::new(HermesSidecarConfig::default(), mcp)
            .with_signing_key(signing.verifying_key().to_bytes());

        let event = serde_json::json!({
            "type": "tool_call",
            "tool": "check_balance",
        });
        let signed_by_other = sign_event(event, &other);
        let trail = adapter.ingest_hermes_event(&signed_by_other, "sess-1");
        assert!(trail.is_none(), "different signer must be rejected");
    }

    /// Legacy mode (no signing key configured) accepts unsigned
    /// events — preserves existing behavior for in-process tests.
    #[test]
    fn test_agt12_legacy_mode_accepts_unsigned() {
        let registry = Arc::new(ToolRegistry::new());
        let mcp = Arc::new(McpServer::new(registry));
        // No `with_signing_key` call.
        let adapter = HermesAdapter::new(HermesSidecarConfig::default(), mcp);
        let event = serde_json::json!({
            "type": "tool_call",
            "tool": "check_balance",
        });
        let trail = adapter.ingest_hermes_event(&event, "sess-1");
        assert!(trail.is_some(), "legacy mode permits unsigned");
    }

    #[test]
    fn test_package_benchmark() {
        let registry = Arc::new(ToolRegistry::new());
        let mcp = Arc::new(McpServer::new(registry));
        let adapter = HermesAdapter::new(HermesSidecarConfig::default(), mcp);

        let events = vec![TrailEvent {
            id: "e1".to_string(),
            session_id: "s1".to_string(),
            timestamp: "2026-03-31".to_string(),
            event_type: "tool_call".to_string(),
            tool_name: Some("check_balance".to_string()),
            data: serde_json::json!({}),
            risk_level: Some("low".to_string()),
            approved: Some(true),
            duration_ms: Some(200),
        }];
        let trace = adapter.package_benchmark("s1", "Check balance", "qwen2.5:72b", events, true);
        assert!(trace.success);
        assert_eq!(trace.tool_call_count, 1);
        assert_eq!(trace.total_duration_ms, 200);
    }
}
