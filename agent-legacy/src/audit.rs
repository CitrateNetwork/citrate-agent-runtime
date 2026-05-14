//! Audit trail — immutable log of every tool execution.

use crate::tool::RiskLevel;
use tokio::sync::RwLock;

/// A single audit entry for a tool execution.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEntry {
    /// Unique execution ID
    pub id: String,
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Session ID
    pub session_id: String,
    /// Tool name
    pub tool_name: String,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Parameters (may be redacted for sensitive tools)
    pub params: serde_json::Value,
    /// Whether the user approved (None for auto-approved Low risk)
    pub user_approved: Option<bool>,
    /// Whether execution succeeded
    pub success: bool,
    /// Execution duration in milliseconds
    pub duration_ms: u64,
    /// Error message if failed
    pub error: Option<String>,
}

/// Audit trail — append-only log.
pub struct AuditTrail {
    entries: RwLock<Vec<AuditEntry>>,
    max_entries: usize,
}

impl AuditTrail {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            max_entries,
        }
    }

    /// Record a tool execution.
    pub async fn record(&self, entry: AuditEntry) {
        let mut entries = self.entries.write().await;
        tracing::info!(
            "AUDIT: {} tool={} risk={:?} success={} duration={}ms",
            entry.id,
            entry.tool_name,
            entry.risk_level,
            entry.success,
            entry.duration_ms
        );
        entries.push(entry);
        // Trim if over max
        if entries.len() > self.max_entries {
            let drain_count = entries.len() - self.max_entries;
            entries.drain(0..drain_count);
        }
    }

    /// Get all audit entries.
    pub async fn entries(&self) -> Vec<AuditEntry> {
        self.entries.read().await.clone()
    }

    /// Get entries for a specific session.
    pub async fn entries_for_session(&self, session_id: &str) -> Vec<AuditEntry> {
        self.entries
            .read()
            .await
            .iter()
            .filter(|e| e.session_id == session_id)
            .cloned()
            .collect()
    }

    /// Count of entries.
    pub async fn count(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Export as JSON.
    pub async fn export_json(&self) -> String {
        let entries = self.entries.read().await;
        serde_json::to_string_pretty(&*entries).unwrap_or_else(|_| "[]".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entry(tool: &str, success: bool) -> AuditEntry {
        AuditEntry {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            session_id: "test-session".to_string(),
            tool_name: tool.to_string(),
            risk_level: RiskLevel::Low,
            params: serde_json::json!({}),
            user_approved: None,
            success,
            duration_ms: 42,
            error: if success {
                None
            } else {
                Some("failed".to_string())
            },
        }
    }

    #[tokio::test]
    async fn test_record_and_retrieve() {
        let trail = AuditTrail::new(100);
        trail.record(test_entry("read_file", true)).await;
        assert_eq!(trail.count().await, 1);
        let entries = trail.entries().await;
        assert_eq!(entries[0].tool_name, "read_file");
    }

    #[tokio::test]
    async fn test_max_entries_trim() {
        let trail = AuditTrail::new(2);
        trail.record(test_entry("a", true)).await;
        trail.record(test_entry("b", true)).await;
        trail.record(test_entry("c", true)).await;
        assert_eq!(trail.count().await, 2);
        let entries = trail.entries().await;
        assert_eq!(entries[0].tool_name, "b"); // "a" was trimmed
    }

    #[tokio::test]
    async fn test_session_filter() {
        let trail = AuditTrail::new(100);
        trail.record(test_entry("tool1", true)).await;
        let filtered = trail.entries_for_session("test-session").await;
        assert_eq!(filtered.len(), 1);
        let other = trail.entries_for_session("other-session").await;
        assert!(other.is_empty());
    }

    #[tokio::test]
    async fn test_export_json() {
        let trail = AuditTrail::new(100);
        trail.record(test_entry("tool1", true)).await;
        let json = trail.export_json().await;
        assert!(json.contains("tool1"));
    }
}
