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
#[derive(Debug, Clone)]
pub struct MemoryAdapterConfig {
    /// Gateway origin, e.g. `https://mem-gateway.example.com` (no baked host).
    pub origin: String,
    /// The connect-token-verified principal; must match the token's subject.
    pub sub: String,
    /// HS256 connect token (byte-matches the gateway's MEM_CONNECT_SECRET issuance).
    pub connect_token: String,
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
    /// Build a reqwest-backed adapter from the environment. Memory is optional
    /// for an agent, so an unconfigured environment is `Ok(None)` (not an error);
    /// a partially-configured one is also `Ok(None)` — fail-closed, never a
    /// half-built client. Reads `MEM_GATEWAY_ORIGIN`, `MEM_GATEWAY_SUB`,
    /// `MEM_CONNECT_TOKEN`.
    pub fn from_env() -> Result<Option<Self>, MemoryError> {
        let var = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());
        match (
            var("MEM_GATEWAY_ORIGIN"),
            var("MEM_GATEWAY_SUB"),
            var("MEM_CONNECT_TOKEN"),
        ) {
            (Some(origin), Some(sub), Some(connect_token)) => {
                let transport = ReqwestMemoryTransport::new()?;
                let cfg = MemoryAdapterConfig {
                    origin,
                    sub,
                    connect_token,
                };
                Ok(Some(Self::new(cfg, transport)?))
            }
            _ => Ok(None),
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
}
