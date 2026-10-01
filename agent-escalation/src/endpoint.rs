//! A member-added OpenAI-compatible endpoint: one request, priced and settled.
//!
//! citrate-core owns the endpoint list, seals each API key in the OS keyring, checks the spend
//! budget, and reserves the worst-case cost **before** it calls the sidecar. The sidecar receives
//! the key inside that one request ([`EscalationRequest::api_key`]), uses it as a bearer header,
//! and drops it (the buffer is wiped). Nothing here writes the key to disk, logs it, or returns it.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::price::{input_token_bound, Price, Usage};

/// The longest prompt (and system prompt) accepted, in bytes.
pub const MAX_PROMPT_BYTES: usize = 64 * 1024;
/// The largest completion a request may ask for.
pub const MAX_ESCALATION_TOKENS: u32 = 8192;
/// The longest API key accepted.
pub const MAX_KEY_LEN: usize = 512;

/// An escalation failure. No variant carries the endpoint URL, the key, or the provider's body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EscalationError {
    /// The request was refused before anything was sent.
    #[error("invalid escalation request: {0}")]
    Invalid(String),
    /// Connection, TLS or timeout failure.
    #[error("the escalation endpoint {0}")]
    Transport(String),
    /// The provider answered with a non-2xx status.
    #[error("the escalation endpoint answered HTTP {0}")]
    Provider(u16),
    /// The provider's answer was not a usable chat completion.
    #[error("the escalation endpoint sent an unusable answer: {0}")]
    BadResponse(String),
}

impl EscalationError {
    /// Whether any byte of the request may have reached the provider (so it may have been billed).
    /// Only a request refused by validation is known not to have been sent.
    pub fn may_have_reached_provider(&self) -> bool {
        !matches!(self, EscalationError::Invalid(_))
    }
}

/// An API key held for one request. `Debug` is redacted, the buffer is wiped on drop, and it can
/// be deserialized (from core's request) but never serialized.
pub struct ApiKey(Zeroizing<String>);

impl ApiKey {
    /// `None` for an empty key, one longer than [`MAX_KEY_LEN`], or one with any byte outside
    /// visible ASCII (so it can never split a header line).
    pub fn new(raw: String) -> Option<ApiKey> {
        let raw = Zeroizing::new(raw);
        if raw.is_empty() || raw.len() > MAX_KEY_LEN || !raw.bytes().all(|b| b.is_ascii_graphic()) {
            return None;
        }
        Some(ApiKey(raw))
    }

    pub(crate) fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for ApiKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        ApiKey::new(raw).ok_or_else(|| serde::de::Error::custom("unusable api key"))
    }
}

/// `POST /escalations` body, built by citrate-core after its budget check.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EscalationRequest {
    /// Core's id for this escalation (letters, digits, `-`, `_`; at most 64).
    pub escalation_id: String,
    /// The endpoint's OpenAI-compatible base, e.g. `https://api.example.com/v1`.
    pub base_url: String,
    pub model: String,
    pub api_key: ApiKey,
    #[serde(default)]
    pub system: Option<String>,
    /// The exact text the member saw on the price card.
    pub prompt: String,
    pub max_tokens: u32,
    pub price: Price,
    /// What core reserved against the budget for this request. Must cover the worst case.
    pub reserved_micros: u64,
}

/// Only `https://host[:port]/path` or `http://<loopback>[:port]/path`, with no userinfo, query,
/// fragment, whitespace or control characters.
pub fn validate_base_url(url: &str) -> Result<(), String> {
    if url.len() > 2048 || url.bytes().any(|b| !b.is_ascii_graphic()) {
        return Err("the endpoint URL has characters that are not allowed".into());
    }
    if url.contains('?') || url.contains('#') {
        return Err("the endpoint URL may not carry a query or fragment".into());
    }
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else {
        return Err("the endpoint must be https:// (or http:// on this computer)".into());
    };
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err("the endpoint URL has no host".into());
    }
    if authority.contains('@') {
        return Err("the endpoint URL may not carry a user name or password".into());
    }
    if scheme == "http" {
        let host = if let Some(h) = authority.strip_prefix('[') {
            h.split(']').next().unwrap_or("")
        } else {
            authority
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(authority)
        };
        let loopback = host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
        if !loopback {
            return Err("plain http is only allowed to this computer (loopback)".into());
        }
    }
    Ok(())
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl EscalationRequest {
    /// The most this request can cost under its own price card.
    pub fn worst_case_micros(&self) -> Option<u64> {
        // Count only the messages actually sent (an empty system prompt is omitted on the wire).
        let input = match self.system.as_deref().filter(|s| !s.is_empty()) {
            Some(s) => input_token_bound(&[s, &self.prompt]),
            None => input_token_bound(&[&self.prompt]),
        };
        self.price.upper_bound(input, u64::from(self.max_tokens))
    }

    /// Shape checks, plus the budget-side guard: core's reservation must cover the worst case,
    /// so a settled charge can never exceed what the budget already holds for this request.
    pub fn validate(&self) -> Result<(), EscalationError> {
        let bad = |m: &str| Err(EscalationError::Invalid(m.to_string()));
        if !valid_id(&self.escalation_id) {
            return bad("escalation id");
        }
        if let Err(m) = validate_base_url(&self.base_url) {
            return Err(EscalationError::Invalid(m));
        }
        if self.model.is_empty() || self.model.len() > 200 {
            return bad("model name");
        }
        if self.prompt.trim().is_empty() || self.prompt.len() > MAX_PROMPT_BYTES {
            return bad("prompt must be 1 to 65536 bytes");
        }
        if self
            .system
            .as_deref()
            .is_some_and(|s| s.len() > MAX_PROMPT_BYTES)
        {
            return bad("system prompt too long");
        }
        if self.max_tokens == 0 || self.max_tokens > MAX_ESCALATION_TOKENS {
            return bad("max tokens must be 1 to 8192");
        }
        match self.worst_case_micros() {
            None => bad("price overflow"),
            Some(w) if w > self.reserved_micros => {
                bad("the reservation does not cover the worst-case cost")
            }
            Some(_) => Ok(()),
        }
    }
}

/// The chat-completions body: an optional system message and the user prompt. No tools are
/// offered to the remote model; its answer comes back to the local loop as text.
pub fn wire_body(req: &EscalationRequest) -> Value {
    let mut messages = Vec::with_capacity(2);
    if let Some(s) = req.system.as_deref().filter(|s| !s.is_empty()) {
        messages.push(json!({"role": "system", "content": s}));
    }
    messages.push(json!({"role": "user", "content": req.prompt}));
    json!({
        "model": req.model,
        "messages": messages,
        "max_tokens": req.max_tokens,
        "stream": false,
    })
}

/// `choices[0].message.content` and the optional `usage` block.
pub fn parse_reply(body: &str) -> Result<(String, Option<Usage>), EscalationError> {
    let v: Value =
        serde_json::from_str(body).map_err(|_| EscalationError::BadResponse("not JSON".into()))?;
    let content = v
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if content.trim().is_empty() {
        return Err(EscalationError::BadResponse("no answer text".into()));
    }
    let usage = v.get("usage").and_then(|u| {
        Some(Usage {
            prompt_tokens: u.get("prompt_tokens")?.as_u64()?,
            completion_tokens: u.get("completion_tokens")?.as_u64()?,
        })
    });
    Ok((content, usage))
}

/// What one escalation is charged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Charge {
    pub charged_micros: u64,
    /// The provider reported token usage (otherwise the full reservation is charged).
    pub usage_reported: bool,
    /// The reported usage priced above the reservation. The charge is capped at the reservation,
    /// and the member is told the provider's own bill may differ.
    pub exceeded_quote: bool,
}

/// Charge the reported usage, never more than the reservation; with no usage, the reservation.
pub fn settle(price: &Price, reserved_micros: u64, usage: Option<Usage>) -> Charge {
    match usage.map(|u| price.cost(u)) {
        Some(Some(c)) if c <= reserved_micros => Charge {
            charged_micros: c,
            usage_reported: true,
            exceeded_quote: false,
        },
        Some(_) => Charge {
            charged_micros: reserved_micros,
            usage_reported: true,
            exceeded_quote: true,
        },
        None => Charge {
            charged_micros: reserved_micros,
            usage_reported: false,
            exceeded_quote: false,
        },
    }
}

/// The one HTTP operation an escalation needs.
pub trait Transport: Send + Sync {
    /// `POST url` with a JSON body and `Authorization: Bearer <bearer>`; returns status + body.
    fn post_json(
        &self,
        url: &str,
        bearer: &str,
        body: &Value,
        timeout: Duration,
    ) -> Result<(u16, String), EscalationError>;
}

/// Production transport: blocking `reqwest` with rustls. Call it from a blocking thread only
/// (the blocking client owns a runtime and panics inside an async context).
pub struct HttpTransport;

impl Transport for HttpTransport {
    fn post_json(
        &self,
        url: &str,
        bearer: &str,
        body: &Value,
        timeout: Duration,
    ) -> Result<(u16, String), EscalationError> {
        let http = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| EscalationError::Transport("could not start an HTTP client".into()))?;
        let resp = http
            .post(url)
            .bearer_auth(bearer)
            .json(body)
            .send()
            .map_err(|e| {
                EscalationError::Transport(if e.is_timeout() {
                    "timed out".into()
                } else if e.is_connect() {
                    "could not be reached".into()
                } else {
                    "request failed".into()
                })
            })?;
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .map_err(|_| EscalationError::Transport("answer could not be read".into()))?;
        Ok((status, text))
    }
}

/// The result of one escalation, returned to core. Carries the answer text and the charge; never
/// the key or the endpoint URL.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EscalationOutcome {
    pub escalation_id: String,
    pub content: String,
    pub usage: Option<Usage>,
    pub charged_micros: u64,
    pub usage_reported: bool,
    pub exceeded_quote: bool,
}

/// Validate, send, parse and settle one escalation.
pub fn run(
    req: &EscalationRequest,
    transport: &dyn Transport,
    timeout: Duration,
) -> Result<EscalationOutcome, EscalationError> {
    req.validate()?;
    let url = format!("{}/chat/completions", req.base_url.trim_end_matches('/'));
    let (status, body) =
        transport.post_json(&url, req.api_key.expose(), &wire_body(req), timeout)?;
    if !(200..300).contains(&status) {
        return Err(EscalationError::Provider(status));
    }
    let (content, usage) = parse_reply(&body)?;
    let charge = settle(&req.price, req.reserved_micros, usage);
    Ok(EscalationOutcome {
        escalation_id: req.escalation_id.clone(),
        content,
        usage,
        charged_micros: charge.charged_micros,
        usage_reported: charge.usage_reported,
        exceeded_quote: charge.exceeded_quote,
    })
}
