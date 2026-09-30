//! HUP-S1.1b — the production [`LlmClient`]: OpenAI-compatible chat completions over HTTP
//! (the bundled llama-server on loopback, or an https gateway). The wire mapping is pure and
//! tested; the transport is a thin blocking `reqwest` call run on the blocking pool.
//!
//! Errors are coarse on purpose: they never carry the endpoint, the bearer, or a request body.

use citrate_agent_loop::{AssistantTurn, CompletionRequest, LlmClient, LlmError, Role, ToolCall};
use serde_json::{json, Value};
use std::time::Duration;

/// Map a [`CompletionRequest`] to the OpenAI chat-completions body.
pub fn to_wire_body(req: &CompletionRequest) -> Value {
    let messages: Vec<Value> = req
        .messages
        .iter()
        .map(|m| {
            let role = match m.role {
                Role::System => "system",
                Role::User => "user",
                Role::Assistant => "assistant",
                Role::Tool => "tool",
            };
            let mut o = serde_json::Map::new();
            o.insert("role".into(), json!(role));
            o.insert("content".into(), json!(m.content));
            if !m.tool_calls.is_empty() {
                o.insert(
                    "tool_calls".into(),
                    Value::Array(
                        m.tool_calls
                            .iter()
                            .map(|c| json!({"id": c.id, "type": "function", "function": {"name": c.name, "arguments": c.arguments}}))
                            .collect(),
                    ),
                );
            }
            if let Some(id) = &m.tool_call_id {
                o.insert("tool_call_id".into(), json!(id));
            }
            Value::Object(o)
        })
        .collect();
    let mut body = json!({
        "model": req.model,
        "messages": messages,
        "max_tokens": req.max_tokens,
        "stream": false,
    });
    if !req.tools.is_empty() {
        body["tools"] = Value::Array(
            req.tools
                .iter()
                .map(|t| json!({"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.parameters}}))
                .collect(),
        );
    }
    body
}

/// Parse `choices[0].message` into an [`AssistantTurn`]. Tool-call arguments may arrive as a JSON
/// string (the spec) or an object (some servers); both become a string.
pub fn parse_turn(body: &str) -> Result<AssistantTurn, LlmError> {
    let v: Value =
        serde_json::from_str(body).map_err(|_| LlmError::BadResponse("not JSON".into()))?;
    let msg = v
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .and_then(|c| c.get("message"))
        .ok_or_else(|| LlmError::BadResponse("no choices[0].message".into()))?;
    let content = msg
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mut tool_calls = Vec::new();
    if let Some(arr) = msg.get("tool_calls").and_then(Value::as_array) {
        for (i, tc) in arr.iter().enumerate() {
            let f = tc.get("function").cloned().unwrap_or(Value::Null);
            let name = f
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            let arguments = match f.get("arguments") {
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                None => "{}".into(),
            };
            let id = tc
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| format!("call_{i}"));
            tool_calls.push(ToolCall {
                id,
                name,
                arguments,
            });
        }
    }
    if content.is_empty() && tool_calls.is_empty() {
        return Err(LlmError::BadResponse("empty assistant message".into()));
    }
    Ok(AssistantTurn {
        content,
        tool_calls,
    })
}

/// Blocking OpenAI-compatible client. Build once per session.
pub struct OpenAiCompatClient {
    url: String,
    bearer: String,
    http: Option<reqwest::blocking::Client>,
}

impl OpenAiCompatClient {
    /// `base_url` like `http://127.0.0.1:18080/v1`; `/chat/completions` is appended.
    pub fn new(base_url: &str, bearer: &str, timeout: Duration) -> Self {
        let http = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(timeout)
            .build()
            .ok();
        OpenAiCompatClient {
            url: format!("{}/chat/completions", base_url.trim_end_matches('/')),
            bearer: bearer.to_string(),
            http,
        }
    }
}

impl LlmClient for OpenAiCompatClient {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let http = self
            .http
            .as_ref()
            .ok_or_else(|| LlmError::Transport("HTTP client unavailable".into()))?;
        let mut rb = http.post(&self.url).json(&to_wire_body(req));
        if !self.bearer.is_empty() {
            rb = rb.bearer_auth(&self.bearer);
        }
        let resp = rb.send().map_err(|e| {
            LlmError::Transport(if e.is_timeout() {
                "timed out".into()
            } else if e.is_connect() {
                "could not connect".into()
            } else {
                "request failed".into()
            })
        })?;
        let status = resp.status();
        let text = resp
            .text()
            .map_err(|_| LlmError::Transport("could not read the response".into()))?;
        if !status.is_success() {
            return Err(LlmError::Provider(format!("HTTP {}", status.as_u16())));
        }
        parse_turn(&text)
    }
}
