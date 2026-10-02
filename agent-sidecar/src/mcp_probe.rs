//! HUP-S4.4: the dry-run probe behind `POST /mcp/probe`. citrate-core's Settings sends one
//! user-added server entry; the sidecar validates it with the user-entry rules
//! (`citrate_agent_mcp_host::user`), starts or reaches the server, runs the handshake, lists its
//! tools, and stops it. Nothing is registered with sessions: the configured MCP servers change only
//! when the allowlist file changes and the sidecar restarts. One probe runs at a time.
//!
//! Keyless: the probe never calls a tool, holds no key, and signs nothing.

use axum::http::StatusCode;
use axum::Json;
use citrate_agent_mcp_host::probe::probe;
use citrate_agent_mcp_host::user::validate_user_entry;
use std::sync::atomic::{AtomicBool, Ordering};

static PROBE_BUSY: AtomicBool = AtomicBool::new(false);

/// A single-holder slot. Held for the length of one probe; released on drop.
pub struct ProbeSlot(&'static AtomicBool);

impl ProbeSlot {
    /// Take the sidecar's probe slot, or `None` while another probe holds it.
    pub fn try_take() -> Option<ProbeSlot> {
        Self::try_take_from(&PROBE_BUSY)
    }

    /// Take the slot guarded by `flag`.
    pub fn try_take_from(flag: &'static AtomicBool) -> Option<ProbeSlot> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| ProbeSlot(flag))
    }
}

impl Drop for ProbeSlot {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

type Reply = Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)>;

fn refuse(code: StatusCode, body: serde_json::Value) -> Reply {
    Err((code, Json(body)))
}

/// Validate and probe one entry. The caller has already checked the bearer.
pub async fn handle(entry: serde_json::Value) -> Reply {
    let cfg = match validate_user_entry(&entry) {
        Ok(c) => c,
        Err(errors) => {
            return refuse(
                StatusCode::UNPROCESSABLE_ENTITY,
                serde_json::json!({ "error": "invalid server entry", "errors": errors }),
            )
        }
    };
    let Some(slot) = ProbeSlot::try_take() else {
        return refuse(
            StatusCode::TOO_MANY_REQUESTS,
            serde_json::json!({ "error": "another server check is running; try again when it finishes" }),
        );
    };
    // Process spawn and blocking HTTP stay off the async runtime.
    let report = tokio::task::spawn_blocking(move || {
        let r = probe(&cfg);
        drop(slot);
        r
    })
    .await;
    match report.map(|r| serde_json::to_value(&r)) {
        Ok(Ok(v)) => Ok(Json(v)),
        _ => refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({ "error": "the server check did not complete" }),
        ),
    }
}
