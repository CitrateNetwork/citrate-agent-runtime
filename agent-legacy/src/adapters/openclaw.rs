//! OpenClaw bridge adapter — skill/workspace import and session-to-trail bridge.
//!
//! OpenClaw is an interop target, not the core runtime.
//! This adapter provides migration and session bridging for OpenClaw users.

use crate::canonical::{LogseqProjection, TrailEvent};
use serde::{Deserialize, Serialize};

/// OpenClaw skill manifest — imported from OpenClaw workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenClawSkillManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub tools: Vec<OpenClawTool>,
}

/// A tool from an OpenClaw skill pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenClawTool {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

/// Convert an OpenClaw skill manifest to Citrate MCP tool definitions.
pub fn import_openclaw_skills(manifest: &OpenClawSkillManifest) -> Vec<serde_json::Value> {
    manifest
        .tools
        .iter()
        .map(|tool| {
            serde_json::json!({
                "type": "function",
                "function": {
                    "name": format!("openclaw:{}", tool.name),
                    "description": format!("[OpenClaw] {}", tool.description),
                    "parameters": tool.input_schema,
                }
            })
        })
        .collect()
}

/// Convert an OpenClaw session log entry to a Citrate TrailEvent.
pub fn openclaw_session_to_trail(
    session_entry: &serde_json::Value,
    citrate_session_id: &str,
) -> Option<TrailEvent> {
    let action = session_entry.get("action")?.as_str()?;
    let tool = session_entry.get("tool").and_then(|t| t.as_str());
    let data = session_entry
        .get("result")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    Some(TrailEvent {
        id: uuid::Uuid::new_v4().to_string(),
        session_id: citrate_session_id.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        event_type: format!("openclaw:{}", action),
        tool_name: tool.map(|t| t.to_string()),
        data,
        risk_level: None,
        approved: None,
        duration_ms: None,
    })
}

/// Generate migration docs as a LogSeq page — helps OpenClaw users adopt Citrate.
pub fn migration_page(skill_count: usize, session_count: usize) -> LogseqProjection {
    let content = format!(
        "- **OpenClaw → Citrate Migration**\n\
         - Imported skills: {}\n\
         - Imported sessions: {}\n\
         - All imported tools are prefixed with `openclaw:` for disambiguation\n\
         - Session events are recorded in the Citrate trail with `openclaw:` prefix\n\
         - Original OpenClaw workspace data is preserved as-is\n",
        skill_count, session_count
    );

    LogseqProjection {
        title: "OpenClaw Migration".to_string(),
        page_type: "summary".to_string(),
        content,
        content_hash: None,
        source_event_ids: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_openclaw_skills() {
        let manifest = OpenClawSkillManifest {
            name: "test-skills".to_string(),
            version: "1.0".to_string(),
            description: "Test skill pack".to_string(),
            tools: vec![OpenClawTool {
                name: "search_web".to_string(),
                description: "Search the web".to_string(),
                input_schema: serde_json::json!({"type": "object", "properties": {"query": {"type": "string"}}}),
            }],
        };
        let defs = import_openclaw_skills(&manifest);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0]["function"]["name"], "openclaw:search_web");
    }

    #[test]
    fn test_session_to_trail() {
        let entry = serde_json::json!({
            "action": "tool_use",
            "tool": "search_web",
            "result": {"hits": 5},
        });
        let trail = openclaw_session_to_trail(&entry, "sess-1");
        assert!(trail.is_some());
        let event = trail.expect("trail event");
        assert_eq!(event.event_type, "openclaw:tool_use");
    }

    #[test]
    fn test_migration_page() {
        let page = migration_page(5, 10);
        assert!(page.content.contains("Imported skills: 5"));
        assert!(page.content.contains("Imported sessions: 10"));
    }
}
