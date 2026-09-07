//! Memory adapter — bridges a Citrate agent to a citrate-memories gateway.
//!
//! This is the recall/assert hook: an agent reaches OUT to the memory DAG ("git
//! for agents") to recall storyline/code-shape and to write signed, append-only
//! assertions. It speaks the BYOM MCP-over-HTTP surface (`POST /mcp/u/:sub`),
//! JSON-RPC to the same 11 `memory.*` tools the stdio/daemon transports serve.
//! The gateway mints the capability grant server-side from the connect token, so
//! this adapter carries only the token; it holds no grant and no keys.
//!
//! No HTTP client is baked in (the crate is audited and dep-pinned). Instead the
//! network boundary is an injectable [`MemoryTransport`] — production wires a
//! real client (ureq/reqwest/hyper) at the app layer; tests pass a mock. This
//! mirrors the injectable-transport pattern in the JS/Python SDK memory modules,
//! and keeps the adapter fail-closed: a missing origin/sub/token is a typed error.

use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use serde_json::{json, Value};

/// The 11 canonical memory tool names served over MCP.
pub const MEMORY_TOOLS: [&str; 11] = [
    "memory.recall",
    "memory.search",
    "memory.neighbors",
    "memory.as_of",
    "memory.verify",
    "memory.critique",
    "memory.analogy",
    "memory.assert",
    "memory.merge_diff",
    "memory.propose_edge",
    "memory.confirm_edge",
];

#[derive(Debug, thiserror::Error)]
pub enum MemoryError {
    #[error("memory adapter config: {0}")]
    Config(String),
    #[error("memory transport error: {0}")]
    Transport(String),
    #[error("memory gateway http {0}")]
    Http(u16),
    #[error("memory rpc error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("bad memory response: {0}")]
    BadResponse(String),
}

/// The injectable network boundary. Implementors POST `body` to `url` with an
/// `Authorization: Bearer <bearer>` header and return `(status, body_text)`.
/// Any transport-level failure (DNS, connect, timeout) is `Err(String)`.
#[async_trait]
pub trait MemoryTransport: Send + Sync {
    async fn post(&self, url: &str, bearer: &str, body: &str) -> Result<(u16, String), String>;
}

/// Configuration for a BYOM memory connection.
///
/// AR-B-027: `Debug` is hand-implemented to REDACT `connect_token` — the derived
/// `Debug` printed the HS256 bearer verbatim, so any `{:?}` (a log line, a panic
/// message, a `dbg!`) would leak it. `Serialize`/`Deserialize` are retained
/// because the config is round-tripped to the user's local credential store.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryAdapterConfig {
    /// Gateway origin, e.g. `https://mem-gateway.example.com` (no baked host).
    pub origin: String,
    /// The connect-token-verified principal; must match the token's subject.
    pub sub: String,
    /// HS256 connect token (byte-matches the gateway's MEM_CONNECT_SECRET issuance).
    pub connect_token: String,
}

impl std::fmt::Debug for MemoryAdapterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryAdapterConfig")
            .field("origin", &self.origin)
            .field("sub", &self.sub)
            .field("connect_token", &"<redacted>")
            .finish()
    }
}

impl MemoryAdapterConfig {
    /// Resolve credentials WITHOUT forcing the user to touch environment
    /// variables. Sources, first hit wins:
    ///
    /// 1. **Session/config file** — a JSON `{origin, sub, connect_token}` at
    ///    `CITRATE_MEMORY_CONFIG`, else `$XDG_CONFIG_HOME/citrate/memory.json`,
    ///    else `$HOME/.config/citrate/memory.json`. The host app (citrate-core /
    ///    Studio) writes this once, after the user logs in — so an in-app agent
    ///    is credentialed by the login the user already did, not by a dotfile edit.
    /// 2. **Environment** — `MEM_GATEWAY_ORIGIN` / `MEM_GATEWAY_SUB` /
    ///    `MEM_CONNECT_TOKEN`. Last resort, for CI and self-hosters.
    ///
    /// `None` means unconfigured — memory is optional, so callers no-op quietly.
    /// (An explicit, code-supplied config bypasses this entirely: just build the
    /// adapter with [`MemoryAdapter::new`].)
    pub fn resolve() -> Option<Self> {
        Self::from_config_file().or_else(Self::from_env_vars)
    }

    /// Read credentials from the session/config JSON file, if present and complete.
    pub fn from_config_file() -> Option<Self> {
        Self::from_json_path(&Self::config_path()?)
    }

    /// Read credentials from `MEM_GATEWAY_ORIGIN` / `MEM_GATEWAY_SUB` /
    /// `MEM_CONNECT_TOKEN`. All three required; blanks are treated as unset.
    pub fn from_env_vars() -> Option<Self> {
        let var = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());
        match (
            var("MEM_GATEWAY_ORIGIN"),
            var("MEM_GATEWAY_SUB"),
            var("MEM_CONNECT_TOKEN"),
        ) {
            (Some(origin), Some(sub), Some(connect_token)) => Some(Self {
                origin,
                sub,
                connect_token,
            }),
            _ => None,
        }
    }

    /// Parse a session/config JSON file at `path`. Returns `None` on a missing
    /// file, bad JSON, or any blank field (fail-closed — never a half-built config).
    pub fn from_json_path(path: &std::path::Path) -> Option<Self> {
        let bytes = std::fs::read(path).ok()?;
        let cfg: Self = serde_json::from_slice(&bytes).ok()?;
        let complete = ![&cfg.origin, &cfg.sub, &cfg.connect_token]
            .iter()
            .any(|s| s.trim().is_empty());
        complete.then_some(cfg)
    }

    /// The session/config file location: `CITRATE_MEMORY_CONFIG`, else an
    /// XDG/`$HOME`-based default. No machine-specific path is baked in.
    fn config_path() -> Option<std::path::PathBuf> {
        if let Ok(p) = std::env::var("CITRATE_MEMORY_CONFIG") {
            if !p.trim().is_empty() {
                return Some(std::path::PathBuf::from(p));
            }
        }
        let base = std::env::var("XDG_CONFIG_HOME")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| std::env::var("HOME").ok().map(|h| format!("{h}/.config")))?;
        Some(
            std::path::PathBuf::from(base)
                .join("citrate")
                .join("memory.json"),
        )
    }
}

/// A memory client for one principal over one gateway. Generic over the
/// transport so production and tests share the exact request/parse logic.
pub struct MemoryAdapter<T: MemoryTransport> {
    transport: T,
    url: String,
    connect_token: String,
    next_id: AtomicU64,
}

impl<T: MemoryTransport> MemoryAdapter<T> {
    /// Build an adapter, validating config fail-closed.
    pub fn new(config: MemoryAdapterConfig, transport: T) -> Result<Self, MemoryError> {
        if config.origin.is_empty() {
            return Err(MemoryError::Config("memory gateway origin not configured".into()));
        }
        if config.sub.is_empty() {
            return Err(MemoryError::Config("BYOM sub required".into()));
        }
        if config.connect_token.is_empty() {
            return Err(MemoryError::Config("BYOM connect token required".into()));
        }
        let origin = config.origin.trim_end_matches('/');
        let url = format!("{origin}/mcp/u/{}", encode_path_segment(&config.sub));
        Ok(Self {
            transport,
            url,
            connect_token: config.connect_token,
            next_id: AtomicU64::new(0),
        })
    }

    /// Send one JSON-RPC request and return its `result` (maps a JSON-RPC error
    /// object, a non-2xx status, or a malformed body to a typed [`MemoryError`]).
    pub async fn rpc(&self, method: &str, params: Value) -> Result<Value, MemoryError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let payload = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let body = serde_json::to_string(&payload)
            .map_err(|e| MemoryError::BadResponse(format!("encode request: {e}")))?;
        let (status, text) = self
            .transport
            .post(&self.url, &self.connect_token, &body)
            .await
            .map_err(MemoryError::Transport)?;
        if !(200..300).contains(&status) {
            return Err(MemoryError::Http(status));
        }
        // The BYOM endpoint answers newline-delimited JSON-RPC; one request → one
        // response object. Take the first non-empty line.
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .ok_or_else(|| MemoryError::BadResponse("empty JSON-RPC response".into()))?;
        let msg: Value = serde_json::from_str(line)
            .map_err(|e| MemoryError::BadResponse(format!("malformed JSON-RPC: {e}")))?;
        if let Some(err) = msg.get("error").filter(|e| !e.is_null()) {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("JSON-RPC error")
                .to_string();
            return Err(MemoryError::Rpc { code, message });
        }
        Ok(msg.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Invoke one `memory.*` tool via MCP `tools/call`.
    pub async fn call_tool(&self, name: &str, args: Value) -> Result<Value, MemoryError> {
        if !MEMORY_TOOLS.contains(&name) {
            return Err(MemoryError::Config(format!("unknown memory tool: {name}")));
        }
        self.rpc("tools/call", json!({ "name": name, "arguments": args }))
            .await
    }

    /// Recall the storyline of a repo.
    pub async fn recall(&self, args: Value) -> Result<Value, MemoryError> {
        self.call_tool("memory.recall", args).await
    }

    /// Semantic search within a repo.
    pub async fn search(&self, args: Value) -> Result<Value, MemoryError> {
        self.call_tool("memory.search", args).await
    }

    /// Is a node current, superseded, or contradicted?
    pub async fn verify(&self, args: Value) -> Result<Value, MemoryError> {
        self.call_tool("memory.verify", args).await
    }

    /// Write a signed, append-only assertion.
    pub async fn assert_node(&self, args: Value) -> Result<Value, MemoryError> {
        self.call_tool("memory.assert", args).await
    }
}

// --------------------------------------------------------------------------
// Batteries-included reqwest transport (opt-in: feature = "reqwest-transport").
// --------------------------------------------------------------------------

/// A [`MemoryTransport`] backed by `reqwest`. This is the production transport
/// most agents want; provide a custom impl only for an exotic client or an
/// offline test. Enable with `features = ["reqwest-transport"]` — the audited
/// default build pulls in no HTTP client.
#[cfg(feature = "reqwest-transport")]
pub struct ReqwestMemoryTransport {
    client: reqwest::Client,
}

#[cfg(feature = "reqwest-transport")]
impl ReqwestMemoryTransport {
    /// Build with a default client.
    pub fn new() -> Result<Self, MemoryError> {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| MemoryError::Transport(format!("build reqwest client: {e}")))?;
        Ok(Self { client })
    }

    /// Build from a pre-configured client (proxies, timeouts, custom TLS).
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[cfg(feature = "reqwest-transport")]
#[async_trait]
impl MemoryTransport for ReqwestMemoryTransport {
    async fn post(&self, url: &str, bearer: &str, body: &str) -> Result<(u16, String), String> {
        let resp = self
            .client
            .post(url)
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| e.to_string())?;
        Ok((status, text))
    }
}

#[cfg(feature = "reqwest-transport")]
impl MemoryAdapter<ReqwestMemoryTransport> {
    /// Build a reqwest-backed adapter from resolved credentials (session/config
    /// file, then env — see [`MemoryAdapterConfig::resolve`]). This is the path
    /// that lets an in-app agent be credentialed by the user's login, with no
    /// environment variables. Unconfigured → `Ok(None)` (memory is optional).
    pub fn resolved() -> Result<Option<Self>, MemoryError> {
        Self::build(MemoryAdapterConfig::resolve())
    }

    /// Build a reqwest-backed adapter from environment variables only. Prefer
    /// [`resolved`](Self::resolved) for user-facing surfaces; use this for CI or
    /// self-hosting where env is the intended configuration channel.
    pub fn from_env() -> Result<Option<Self>, MemoryError> {
        Self::build(MemoryAdapterConfig::from_env_vars())
    }

    /// Shared: build from an optional config, minting the reqwest client once.
    /// `None` config → `Ok(None)`; a present config still fails closed if the
    /// client can't be built.
    fn build(cfg: Option<MemoryAdapterConfig>) -> Result<Option<Self>, MemoryError> {
        match cfg {
            Some(cfg) => Ok(Some(Self::new(cfg, ReqwestMemoryTransport::new()?)?)),
            None => Ok(None),
        }
    }
}

/// Percent-encode a path segment conservatively (agents' `sub` is usually an
/// OIDC subject with `:`/`/`; keep the URL well-formed without a URL crate).
fn encode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let ok = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if ok {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn debug_redacts_the_connect_token() {
        // AR-B-027: the derived Debug printed the HS256 bearer verbatim; the
        // hand-impl must redact it so a stray {:?} / log line cannot leak it.
        let cfg = MemoryAdapterConfig {
            origin: "https://mem.example.com".into(),
            sub: "did:citrate:agent:0xabc".into(),
            connect_token: "SUPER-SECRET-HS256-TOKEN".into(),
        };
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("SUPER-SECRET-HS256-TOKEN"),
            "Debug must not leak the connect token; got: {dbg}"
        );
        assert!(dbg.contains("<redacted>"), "got: {dbg}");
    }

    /// Records the last request and returns a canned (status, body).
    struct MockTransport {
        response: (u16, String),
        seen: Mutex<Option<(String, String, String)>>, // (url, bearer, body)
    }

    impl MockTransport {
        fn new(status: u16, body: &str) -> Self {
            Self {
                response: (status, body.to_string()),
                seen: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl MemoryTransport for MockTransport {
        async fn post(&self, url: &str, bearer: &str, body: &str) -> Result<(u16, String), String> {
            *self.seen.lock().unwrap() = Some((url.to_string(), bearer.to_string(), body.to_string()));
            Ok(self.response.clone())
        }
    }

    fn cfg() -> MemoryAdapterConfig {
        MemoryAdapterConfig {
            origin: "https://mem-gateway.example.com".into(),
            sub: "user-123".into(),
            connect_token: "connect.tok".into(),
        }
    }

    #[test]
    fn fail_closed_on_empty_config() {
        let t = || MockTransport::new(200, "{}");
        assert!(MemoryAdapter::new(MemoryAdapterConfig { origin: "".into(), ..cfg() }, t()).is_err());
        assert!(MemoryAdapter::new(MemoryAdapterConfig { sub: "".into(), ..cfg() }, t()).is_err());
        assert!(
            MemoryAdapter::new(MemoryAdapterConfig { connect_token: "".into(), ..cfg() }, t()).is_err()
        );
    }

    #[tokio::test]
    async fn recall_wraps_tools_call_and_returns_result() {
        let resp = r#"{"jsonrpc":"2.0","id":1,"result":{"items":[]}}"#;
        let adapter = MemoryAdapter::new(cfg(), MockTransport::new(200, resp)).unwrap();
        let out = adapter.recall(json!({ "repo": "citrate-chain" })).await.unwrap();
        assert_eq!(out, json!({ "items": [] }));

        let seen = adapter.transport.seen.lock().unwrap().clone().unwrap();
        assert_eq!(seen.0, "https://mem-gateway.example.com/mcp/u/user-123");
        assert_eq!(seen.1, "connect.tok");
        let sent: Value = serde_json::from_str(&seen.2).unwrap();
        assert_eq!(sent["method"], "tools/call");
        assert_eq!(sent["params"]["name"], "memory.recall");
        assert_eq!(sent["params"]["arguments"]["repo"], "citrate-chain");
    }

    #[tokio::test]
    async fn json_rpc_error_maps_to_typed_error() {
        let resp = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"grant rejected"}}"#;
        let adapter = MemoryAdapter::new(cfg(), MockTransport::new(200, resp)).unwrap();
        let err = adapter.verify(json!({ "id": "ab" })).await.unwrap_err();
        match err {
            MemoryError::Rpc { code, message } => {
                assert_eq!(code, -32001);
                assert!(message.contains("grant rejected"));
            }
            other => panic!("expected Rpc error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_2xx_status_is_http_error() {
        let adapter = MemoryAdapter::new(cfg(), MockTransport::new(401, "")).unwrap();
        let err = adapter.recall(json!({ "repo": "r" })).await.unwrap_err();
        assert!(matches!(err, MemoryError::Http(401)));
    }

    #[tokio::test]
    async fn unknown_tool_rejected_before_transport() {
        let adapter = MemoryAdapter::new(cfg(), MockTransport::new(200, "{}")).unwrap();
        let err = adapter.call_tool("memory.nope", json!({})).await.unwrap_err();
        assert!(matches!(err, MemoryError::Config(_)));
        // transport never called
        assert!(adapter.transport.seen.lock().unwrap().is_none());
    }

    #[test]
    fn sub_is_path_encoded() {
        let c = MemoryAdapterConfig { sub: "oidc|abc/def".into(), ..cfg() };
        let adapter = MemoryAdapter::new(c, MockTransport::new(200, "{}")).unwrap();
        assert_eq!(adapter.url, "https://mem-gateway.example.com/mcp/u/oidc%7Cabc%2Fdef");
    }

    #[cfg(feature = "reqwest-transport")]
    #[test]
    fn reqwest_transport_builds_a_valid_adapter() {
        let transport = ReqwestMemoryTransport::new().expect("build reqwest transport");
        let adapter = MemoryAdapter::new(cfg(), transport).expect("build adapter");
        assert_eq!(adapter.url, "https://mem-gateway.example.com/mcp/u/user-123");
    }

    #[test]
    fn config_file_resolves_when_complete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memory.json");
        std::fs::write(
            &path,
            r#"{"origin":"https://mg.example.com","sub":"u-9","connect_token":"tok-9"}"#,
        )
        .unwrap();
        let cfg = MemoryAdapterConfig::from_json_path(&path).expect("complete config resolves");
        assert_eq!(cfg.origin, "https://mg.example.com");
        assert_eq!(cfg.sub, "u-9");
        assert_eq!(cfg.connect_token, "tok-9");
        // and it builds a usable adapter
        let adapter = MemoryAdapter::new(cfg, MockTransport::new(200, "{}")).unwrap();
        assert_eq!(adapter.url, "https://mg.example.com/mcp/u/u-9");
    }

    #[test]
    fn config_file_fails_closed_on_blank_or_missing() {
        // a blank field is treated as unconfigured (no half-built config)
        let dir = tempfile::tempdir().unwrap();
        let blank = dir.path().join("blank.json");
        std::fs::write(&blank, r#"{"origin":"https://x","sub":"","connect_token":"t"}"#).unwrap();
        assert!(MemoryAdapterConfig::from_json_path(&blank).is_none());
        // a missing file is None, not an error
        assert!(MemoryAdapterConfig::from_json_path(dir.path().join("nope.json").as_path()).is_none());
    }
}
