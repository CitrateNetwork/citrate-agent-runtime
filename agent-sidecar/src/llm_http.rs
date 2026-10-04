//! HUP-S1.1b — the production [`LlmClient`]: OpenAI-compatible chat completions over HTTP
//! (the bundled llama-server on loopback, or an https gateway). The wire mapping is pure and
//! tested; the transport is a thin blocking `reqwest` call run on the blocking pool.
//!
//! Errors are coarse on purpose: they never carry the endpoint, the bearer, or a request body.

use citrate_agent_loop::{
    AssistantTurn, CompletionRequest, LlmClient, LlmError, Role, TokenUsage, ToolCall,
};
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

/// HUP-S7.5: the `usage` block of an OpenAI-compatible response (llama-server and gateways report
/// it). Both `prompt_tokens` and `completion_tokens` must be non-negative integers; anything else
/// is unknown (`None`), never zero.
pub fn parse_usage(body: &str) -> Option<TokenUsage> {
    let v: Value = serde_json::from_str(body).ok()?;
    let u = v.get("usage")?;
    Some(TokenUsage {
        prompt_tokens: u.get("prompt_tokens")?.as_u64()?,
        completion_tokens: u.get("completion_tokens")?.as_u64()?,
    })
}

/// HUP-S1.1 (g1-render): the streaming form of [`to_wire_body`] (`stream: true`, and usage on the
/// last chunk so metering still sees the provider's own token counts).
pub fn to_stream_body(req: &CompletionRequest) -> Value {
    let mut body = to_wire_body(req);
    body["stream"] = json!(true);
    body["stream_options"] = json!({"include_usage": true});
    body
}

/// One tool call while its pieces are still arriving.
#[derive(Debug, Default)]
struct PartialCall {
    id: Option<String>,
    name: String,
    arguments: String,
}

/// HUP-S1.1 (g1-render): rebuilds an assistant turn from an OpenAI-compatible server-sent-event
/// stream (`data: {chunk}` lines, ending with `data: [DONE]`). Text deltas are returned as they
/// arrive; tool-call pieces are joined by their `index`; `usage` is taken from whichever chunk
/// carries it. The finished turn is what [`parse_turn`] would have returned for the same answer.
#[derive(Debug, Default)]
pub struct StreamAssembler {
    content: String,
    calls: Vec<PartialCall>,
    usage: Option<TokenUsage>,
    /// `[DONE]` arrived or a choice reported a `finish_reason`.
    finished: bool,
}

impl StreamAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one line of the stream. Returns the assistant text it carried (empty when none).
    pub fn line(&mut self, raw: &str) -> Result<String, LlmError> {
        let line = raw.trim_end_matches(['\r', '\n']);
        let Some(data) = line.strip_prefix("data:") else {
            // Blank separators, comments (`:`), `event:`/`id:` fields: nothing to read.
            return Ok(String::new());
        };
        let data = data.trim_start();
        if data == "[DONE]" {
            self.finished = true;
            return Ok(String::new());
        }
        let v: Value = serde_json::from_str(data)
            .map_err(|_| LlmError::BadResponse("a stream chunk was not JSON".into()))?;
        if v.get("error").is_some() {
            return Err(LlmError::Provider(
                "the model server reported an error mid-answer".into(),
            ));
        }
        if let Some(u) = v.get("usage") {
            if let (Some(p), Some(c)) = (
                u.get("prompt_tokens").and_then(Value::as_u64),
                u.get("completion_tokens").and_then(Value::as_u64),
            ) {
                self.usage = Some(TokenUsage {
                    prompt_tokens: p,
                    completion_tokens: c,
                });
            }
        }
        let Some(choice) = v
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|c| c.first())
        else {
            return Ok(String::new());
        };
        if choice.get("finish_reason").is_some_and(|f| !f.is_null()) {
            self.finished = true;
        }
        let Some(delta) = choice.get("delta") else {
            return Ok(String::new());
        };
        if let Some(arr) = delta.get("tool_calls").and_then(Value::as_array) {
            for (pos, tc) in arr.iter().enumerate() {
                let idx = tc
                    .get("index")
                    .and_then(Value::as_u64)
                    .and_then(|i| usize::try_from(i).ok())
                    .unwrap_or(pos);
                // A server that skips indexes is not trusted to allocate unbounded slots.
                if idx > 64 {
                    return Err(LlmError::BadResponse(
                        "a tool call index is out of range".into(),
                    ));
                }
                while self.calls.len() <= idx {
                    self.calls.push(PartialCall::default());
                }
                let slot = &mut self.calls[idx];
                if let Some(id) = tc.get("id").and_then(Value::as_str) {
                    if !id.is_empty() {
                        slot.id = Some(id.to_string());
                    }
                }
                if let Some(f) = tc.get("function") {
                    if let Some(n) = f.get("name").and_then(Value::as_str) {
                        slot.name.push_str(n);
                    }
                    match f.get("arguments") {
                        Some(Value::String(a)) => slot.arguments.push_str(a),
                        Some(Value::Null) | None => {}
                        Some(other) => slot.arguments.push_str(&other.to_string()),
                    }
                }
            }
        }
        match delta.get("content").and_then(Value::as_str) {
            Some(t) if !t.is_empty() => {
                self.content.push_str(t);
                Ok(t.to_string())
            }
            _ => Ok(String::new()),
        }
    }

    /// The whole turn. A stream that stopped before it finished is an error, never a short answer.
    pub fn finish(self) -> Result<(AssistantTurn, Option<TokenUsage>), LlmError> {
        if !self.finished {
            return Err(LlmError::Transport("the answer stream ended early".into()));
        }
        let tool_calls: Vec<ToolCall> = self
            .calls
            .into_iter()
            .enumerate()
            .filter(|(_, c)| !c.name.is_empty())
            .map(|(i, c)| ToolCall {
                id: c.id.unwrap_or_else(|| format!("call_{i}")),
                name: c.name,
                arguments: if c.arguments.is_empty() {
                    "{}".into()
                } else {
                    c.arguments
                },
            })
            .collect();
        if self.content.is_empty() && tool_calls.is_empty() {
            return Err(LlmError::BadResponse("empty assistant message".into()));
        }
        Ok((
            AssistantTurn {
                content: self.content,
                tool_calls,
            },
            self.usage,
        ))
    }
}

/// Environment switch for streamed answers (`0` turns streaming off; anything else, or unset,
/// leaves it on).
pub const LLM_STREAM_ENV: &str = "CITRATE_HERMES_LLM_STREAM";

/// Whether [`LLM_STREAM_ENV`]'s value turns streaming on.
pub fn streaming_from_value(v: Option<&str>) -> bool {
    !matches!(v.map(str::trim), Some("0") | Some("false") | Some("off"))
}

/// Blocking OpenAI-compatible client. Holds only configuration: the `reqwest` blocking client (which
/// owns an internal runtime) is built inside [`LlmClient::complete`], which always runs on the
/// blocking pool. Building or dropping it inside an async handler panics and poisons shared locks.
pub struct OpenAiCompatClient {
    url: String,
    bearer: String,
    timeout: Duration,
    /// HUP-S1.1 (g1-render): ask for a streamed answer in [`LlmClient::complete_streaming`].
    streaming: bool,
}

impl OpenAiCompatClient {
    /// `base_url` like `http://127.0.0.1:18080/v1`; `/chat/completions` is appended.
    pub fn new(base_url: &str, bearer: &str, timeout: Duration) -> Self {
        OpenAiCompatClient {
            url: format!("{}/chat/completions", base_url.trim_end_matches('/')),
            bearer: bearer.to_string(),
            timeout,
            streaming: true,
        }
    }

    /// Turn streamed answers on or off (on by default).
    pub fn with_streaming(mut self, on: bool) -> Self {
        self.streaming = on;
        self
    }

    fn http(&self) -> Result<reqwest::blocking::Client, LlmError> {
        reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(self.timeout)
            .build()
            .map_err(|_| LlmError::Transport("HTTP client unavailable".into()))
    }

    fn send(&self, body: &Value) -> Result<reqwest::blocking::Response, LlmError> {
        let mut rb = self.http()?.post(&self.url).json(body);
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
        if !status.is_success() {
            return Err(LlmError::Provider(format!("HTTP {}", status.as_u16())));
        }
        Ok(resp)
    }
}

/// HUP-S1.1 (g1-render): read a streamed answer, handing each text delta to `on_delta`. A server
/// that ignored `stream: true` and sent one JSON body is read as a normal answer (no deltas).
pub fn read_streamed(
    content_type: &str,
    body: impl std::io::Read,
    on_delta: &mut dyn FnMut(&str),
) -> Result<(AssistantTurn, Option<TokenUsage>), LlmError> {
    use std::io::{BufRead, Read};
    if !content_type.contains("text/event-stream") {
        let mut text = String::new();
        std::io::BufReader::new(body)
            .read_to_string(&mut text)
            .map_err(|_| LlmError::Transport("could not read the response".into()))?;
        let turn = parse_turn(&text)?;
        return Ok((turn, parse_usage(&text)));
    }
    let mut asm = StreamAssembler::new();
    let mut reader = std::io::BufReader::new(body);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .map_err(|_| LlmError::Transport("the answer stream was cut off".into()))?;
        if n == 0 {
            break;
        }
        let d = asm.line(&line)?;
        if !d.is_empty() {
            on_delta(&d);
        }
    }
    asm.finish()
}

impl LlmClient for OpenAiCompatClient {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        self.complete_with_usage(req).map(|(t, _)| t)
    }

    fn complete_with_usage(
        &self,
        req: &CompletionRequest,
    ) -> Result<(AssistantTurn, Option<TokenUsage>), LlmError> {
        let resp = self.send(&to_wire_body(req))?;
        let text = resp
            .text()
            .map_err(|_| LlmError::Transport("could not read the response".into()))?;
        let turn = parse_turn(&text)?;
        Ok((turn, parse_usage(&text)))
    }

    fn complete_streaming(
        &self,
        req: &CompletionRequest,
        on_delta: &mut dyn FnMut(&str),
    ) -> Result<(AssistantTurn, Option<TokenUsage>), LlmError> {
        if !self.streaming {
            return self.complete_with_usage(req);
        }
        let resp = self.send(&to_stream_body(req))?;
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        read_streamed(&content_type, resp, on_delta)
    }
}

#[cfg(test)]
mod stream_tests {
    include!("llm_stream_tests.rs");
}
