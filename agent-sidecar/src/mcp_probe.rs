//! HUP-S4.4: the dry-run probe behind `POST /mcp/probe`. citrate-core's Settings sends one
//! user-added server entry; the sidecar validates it with the user-entry rules
//! (`citrate_agent_mcp_host::user`), checks that core has already saved exactly that entry, starts
//! or reaches the server, runs the handshake, lists its tools, and stops it.
//!
//! The saved-entry check: core stores every user-added server, disabled, in its owner-only server
//! list (`mcp-servers.json`) before asking for a review, and names that file to the sidecar in
//! [`MCP_REGISTRY_ENV`]. The sidecar re-reads it on every probe and refuses (starting nothing) when
//! the file is not configured, is not a regular owner-only file, has no entry by that name, or
//! that entry would run something different from the request. So a bearer holder alone cannot
//! make the sidecar start an arbitrary program. Nothing is registered with sessions: the configured MCP servers change only
//! when the allowlist file changes and the sidecar restarts. One probe runs at a time.
//!
//! Keyless: the probe never calls a tool, holds no key, and signs nothing.

use axum::http::StatusCode;
use axum::Json;
use citrate_agent_mcp_host::probe::probe;
use citrate_agent_mcp_host::user::validate_user_entry;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// The env var naming core's saved server list (`<hermes dir>/mcp-servers.json`). Unset = the
/// probe refuses every entry.
pub const MCP_REGISTRY_ENV: &str = "CITRATE_HERMES_MCP_REGISTRY";
/// Largest saved server list read.
const MAX_REGISTRY_BYTES: u64 = 1 << 20;

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

/// The runtime `[[servers]]` entry for one saved server (core's `StoredServer` shape; the same
/// mapping core uses when it writes the allowlist).
fn saved_entry(s: &serde_json::Value) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    for k in ["name", "transport"] {
        if let Some(v) = s.get(k) {
            m.insert(k.into(), v.clone());
        }
    }
    if s.get("transport").and_then(serde_json::Value::as_str) == Some("stdio") {
        if let Some(c) = s.get("command").filter(|v| !v.is_null()) {
            m.insert("command".into(), c.clone());
        }
        m.insert(
            "args".into(),
            s.get("args").cloned().unwrap_or(serde_json::json!([])),
        );
        m.insert(
            "env".into(),
            s.get("env").cloned().unwrap_or(serde_json::json!({})),
        );
        if let Some(c) = s.get("cwd").filter(|v| !v.is_null()) {
            m.insert("cwd".into(), c.clone());
        }
    } else if let Some(u) = s.get("url").filter(|v| !v.is_null()) {
        m.insert("url".into(), u.clone());
    }
    m.insert(
        "allow_write_tools".into(),
        s.get("allow_write_tools")
            .cloned()
            .unwrap_or(serde_json::json!(false)),
    );
    serde_json::Value::Object(m)
}

/// Read the saved server list: a regular file (not a symlink), owner-only on Unix, at most
/// [`MAX_REGISTRY_BYTES`]. The checks are made on the opened file (opened without following a
/// symlink at the last component), so the file cannot be swapped between the check and the read.
/// The reason never quotes the file.
fn read_registry(path: &Path) -> Result<Vec<serde_json::Value>, String> {
    use std::io::Read;
    let unreadable = || "the saved server list could not be read".to_string();
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match opts.open(path) {
        Ok(f) => f,
        Err(_) => {
            return Err(match std::fs::symlink_metadata(path) {
                Ok(m) if !m.file_type().is_file() => {
                    "the saved server list is not a regular file".to_string()
                }
                _ => unreadable(),
            })
        }
    };
    let meta = file.metadata().map_err(|_| unreadable())?;
    if !meta.file_type().is_file() {
        return Err("the saved server list is not a regular file".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("the saved server list is open to other users".to_string());
        }
    }
    if meta.len() > MAX_REGISTRY_BYTES {
        return Err("the saved server list is too large".to_string());
    }
    let mut text = String::new();
    file.take(MAX_REGISTRY_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| unreadable())?;
    if text.len() as u64 > MAX_REGISTRY_BYTES {
        return Err("the saved server list is too large".to_string());
    }
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| unreadable())?;
    Ok(v.get("servers")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default())
}

/// Validate and probe one entry. The caller has already checked the bearer. `registry` is core's
/// saved server list ([`MCP_REGISTRY_ENV`]); without it nothing is probed.
pub async fn handle(entry: serde_json::Value, registry: Option<&Path>) -> Reply {
    let cfg = match validate_user_entry(&entry) {
        Ok(c) => c,
        Err(errors) => {
            return refuse(
                StatusCode::UNPROCESSABLE_ENTITY,
                serde_json::json!({ "error": "invalid server entry", "errors": errors }),
            )
        }
    };
    let Some(registry) = registry else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({ "error": "server checks need the app's saved server list, which this Hermes was not given; nothing was started" }),
        );
    };
    let not_saved = |why: &str| {
        refuse(
            StatusCode::FORBIDDEN,
            serde_json::json!({ "error": format!("{why}; nothing was started") }),
        )
    };
    let saved = match read_registry(registry) {
        Ok(list) => list,
        Err(why) => return not_saved(&why),
    };
    let Some(stored) = saved
        .iter()
        .find(|s| s.get("name").and_then(serde_json::Value::as_str) == Some(cfg.name.as_str()))
    else {
        return not_saved("this server is not in the app's saved server list");
    };
    match validate_user_entry(&saved_entry(stored)) {
        Ok(saved_cfg) if saved_cfg == cfg => {}
        _ => return not_saved("this server differs from the one the app saved"),
    }
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
