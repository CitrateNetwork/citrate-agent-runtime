//! The registry route: escalate to a model served by an `InferenceRouter` provider and pay with an
//! x402 authorization (ADR-2026-09-30 Rule-3 amendment, D3: the EIP-3009
//! `TransferWithAuthorization` form).
//!
//! The split ("brain in the sidecar, hands in core"):
//!
//! - **citrate-core** reads the router on chain (`getProviders(modelHash)`, `providers(address)`),
//!   picks the provider, quotes its `minPrice` in the pinned asset, builds the authorization with a
//!   CSPRNG nonce and a validity window of at most ten minutes, asks the member to approve it in
//!   the SignatureCeremony, checks the signature recovers to the member's wallet, and only then
//!   calls `POST /escalations/registry` here. It also decides whether the route is on at all: it
//!   needs a pinned `InferenceRouter` and an allowlisted asset (ADR owner decision O-1).
//! - **This module** validates the signed payment, sends ONE chat completion to the provider's
//!   endpoint with the payment in the `X-PAYMENT` header (x402 v1, `exact` scheme), reads the
//!   answer and the provider's `X-PAYMENT-RESPONSE` receipt, and returns both. It never signs,
//!   never holds a key, and never talks to a chain. Settlement on chain is the provider's call to
//!   the asset's `transferWithAuthorization`; core confirms it independently with
//!   `authorizationState(from, nonce)`.
//!
//! [`X402PaymentRequest`] is the structured shape the ADR fixes for a request travelling toward
//! core (`{quote_id, recipient, asset, amount, resource}`). The sidecar never sends raw typed data.

use std::time::Duration;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::endpoint::{
    parse_reply, validate_base_url, EscalationError, HttpTransport, MAX_ESCALATION_TOKENS,
    MAX_PROMPT_BYTES, MAX_REPLY_BYTES,
};
use crate::price::Usage;

/// The x402 protocol version this sidecar speaks.
pub const X402_VERSION: u32 = 1;
/// The only x402 scheme carried: `exact` (EIP-3009 on EVM).
pub const X402_SCHEME: &str = "exact";
/// Request header carrying the payment.
pub const X_PAYMENT: &str = "X-PAYMENT";
/// Response header carrying the provider's settlement receipt.
pub const X_PAYMENT_RESPONSE: &str = "X-PAYMENT-RESPONSE";
/// The largest receipt header read (base64 JSON).
pub const MAX_RECEIPT_HEADER_BYTES: usize = 4096;

/// The structured payment request the sidecar would hand to core (ADR D3: `{quote_id, recipient,
/// asset, amount, resource}`). Never raw EIP-712 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentRequest {
    pub quote_id: String,
    /// The payee core compares with the provider the router names.
    pub recipient: String,
    /// The allowlisted x402 asset contract.
    pub asset: String,
    /// Base units of the asset, as a decimal string (U256 range; core parses and caps it).
    pub amount: String,
    /// What is being paid for (the model hash or route).
    pub resource: String,
}

/// A registry-route failure in building a request shape.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("invalid x402 payment request: {0}")]
    Invalid(String),
}

/// The sidecar's half of the registry route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryRouteStatus {
    /// The sidecar can carry a payment core built and the member approved.
    pub enabled: bool,
    pub transport: String,
    pub reason: String,
    pub missing: Vec<String>,
}

/// What the sidecar reports for `GET /escalations/registry`. Whether registry escalation is on is
/// citrate-core's decision; the sidecar only says what it can carry.
pub fn registry_route_status() -> RegistryRouteStatus {
    RegistryRouteStatus {
        enabled: true,
        transport: format!("x402 v{X402_VERSION} {X402_SCHEME} (EIP-3009 TransferWithAuthorization)"),
        reason: "The sidecar carries an x402 payment that Citrate Core built and you approved. Whether registry escalation is on is Citrate Core's decision: it needs a pinned InferenceRouter and an allowlisted payment token.".into(),
        missing: Vec::new(),
    }
}

fn is_address(s: &str) -> bool {
    s.len() == 42 && s.starts_with("0x") && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_hex_bytes(s: &str, n: usize) -> bool {
    s.len() == 2 + 2 * n && s.starts_with("0x") && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_amount(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 78
        && s.bytes().all(|b| b.is_ascii_digit())
        && !s.bytes().all(|b| b == b'0')
}

/// Build the structured payment request, checking its shape. `amount` must be a positive decimal
/// integer of at most 78 digits (the U256 range); core re-checks it against the caps.
pub fn x402_payment_request(
    quote_id: &str,
    recipient: &str,
    asset: &str,
    amount: &str,
    resource: &str,
) -> Result<X402PaymentRequest, RegistryError> {
    let bad = |m: &str| Err(RegistryError::Invalid(m.to_string()));
    if quote_id.is_empty()
        || quote_id.len() > 64
        || !quote_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return bad("quote id");
    }
    if !is_address(recipient) {
        return bad("recipient must be a 20-byte hex address");
    }
    if !is_address(asset) {
        return bad("asset must be a 20-byte hex address");
    }
    if !is_amount(amount) {
        return bad("amount must be a positive whole number of base units");
    }
    if resource.is_empty() || resource.len() > 256 || resource.bytes().any(|b| b.is_ascii_control())
    {
        return bad("resource");
    }
    Ok(X402PaymentRequest {
        quote_id: quote_id.to_string(),
        recipient: recipient.to_ascii_lowercase(),
        asset: asset.to_ascii_lowercase(),
        amount: amount.to_string(),
        resource: resource.to_string(),
    })
}

/// A payment core built and the member approved: the EIP-3009 authorization and its signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPayment {
    /// CAIP-2 network id, `eip155:<chainId>`.
    pub network: String,
    /// The asset contract (its EIP-712 domain is what core signed under).
    pub asset: String,
    pub from: String,
    pub to: String,
    /// Base units, decimal.
    pub value: String,
    pub valid_after: u64,
    pub valid_before: u64,
    /// `0x` + 64 hex.
    pub nonce: String,
    /// `0x` + 130 hex (`r ‖ s ‖ v`).
    pub signature: String,
}

impl SignedPayment {
    /// Shape checks, and the window: an authorization that is already expired at `now_secs` (or
    /// expires within `margin_secs`) is refused before anything is sent.
    pub fn validate(&self, now_secs: u64, margin_secs: u64) -> Result<(), String> {
        let chain = self.network.strip_prefix("eip155:").unwrap_or("");
        if chain.is_empty() || chain.len() > 20 || !chain.bytes().all(|b| b.is_ascii_digit()) {
            return Err("the payment network must be eip155:<chain id>".into());
        }
        for (what, a) in [("asset", &self.asset), ("payer", &self.from), ("payee", &self.to)] {
            if !is_address(a) {
                return Err(format!("the payment {what} is not a 20-byte hex address"));
            }
        }
        if !is_amount(&self.value) {
            return Err("the payment amount must be a positive whole number of base units".into());
        }
        if !is_hex_bytes(&self.nonce, 32) {
            return Err("the payment nonce must be 32 bytes of hex".into());
        }
        if !is_hex_bytes(&self.signature, 65) {
            return Err("the payment signature must be 65 bytes of hex".into());
        }
        if self.valid_after >= self.valid_before {
            return Err("the payment window is empty".into());
        }
        if self.valid_before <= now_secs.saturating_add(margin_secs) {
            return Err("the payment authorization has expired; ask for a new quote".into());
        }
        Ok(())
    }

    /// The `X-PAYMENT` header value: base64 of the x402 v1 `exact` payload. Numbers are decimal
    /// strings, as the x402 reference implementations send them.
    pub fn header_value(&self) -> String {
        let payload = serde_json::json!({
            "x402Version": X402_VERSION,
            "scheme": X402_SCHEME,
            "network": self.network,
            "payload": {
                "signature": self.signature,
                "authorization": {
                    "from": self.from,
                    "to": self.to,
                    "value": self.value,
                    "validAfter": self.valid_after.to_string(),
                    "validBefore": self.valid_before.to_string(),
                    "nonce": self.nonce,
                },
            },
        });
        base64::engine::general_purpose::STANDARD.encode(payload.to_string())
    }
}

/// The provider's settlement receipt (`X-PAYMENT-RESPONSE`), as the provider claims it. Core
/// confirms the payment on chain separately; this is what the provider said.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentReceipt {
    pub success: bool,
    /// The settlement transaction hash, when the provider names one.
    #[serde(default)]
    pub transaction: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub payer: Option<String>,
}

/// Decode an `X-PAYMENT-RESPONSE` header. A malformed or oversized one is `None` (no receipt),
/// never an error: the answer already arrived and the payment may have settled.
pub fn parse_payment_response(header: &str) -> Option<PaymentReceipt> {
    if header.is_empty() || header.len() > MAX_RECEIPT_HEADER_BYTES {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(header.trim())
        .ok()?;
    let v: Value = serde_json::from_slice(&raw).ok()?;
    let success = v.get("success")?.as_bool()?;
    let field = |k: &str, ok: &dyn Fn(&str) -> bool| {
        v.get(k)
            .and_then(Value::as_str)
            .filter(|s| ok(s))
            .map(str::to_ascii_lowercase)
    };
    Some(PaymentReceipt {
        success,
        transaction: field("transaction", &|s| is_hex_bytes(s, 32)),
        network: field("network", &|s| s.len() <= 64 && s.bytes().all(|b| b.is_ascii_graphic())),
        payer: field("payer", &is_address),
    })
}

/// What a provider asked for when it answered HTTP 402 (`accepts[0]`), so the member can see why
/// the payment was refused. Only the fields shown are kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequired {
    pub max_amount_required: Option<String>,
    pub pay_to: Option<String>,
    pub asset: Option<String>,
    pub network: Option<String>,
}

/// Read an HTTP 402 body (`{x402Version, accepts: [...], error}`). `None` when it is not one.
pub fn parse_payment_required(body: &str) -> Option<PaymentRequired> {
    let v: Value = serde_json::from_str(body).ok()?;
    let first = v.get("accepts")?.as_array()?.first()?;
    let s = |k: &str| {
        first
            .get(k)
            .and_then(Value::as_str)
            .filter(|s| s.len() <= 128 && s.bytes().all(|b| b.is_ascii_graphic()))
            .map(str::to_string)
    };
    Some(PaymentRequired {
        max_amount_required: s("maxAmountRequired").filter(|a| is_amount(a)),
        pay_to: s("payTo").filter(|a| is_address(a)),
        asset: s("asset").filter(|a| is_address(a)),
        network: s("network"),
    })
}

/// `POST /escalations/registry` body, built by citrate-core after the member approved the payment.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryEscalationRequest {
    pub escalation_id: String,
    /// The provider's OpenAI-compatible base URL, as the router lists it.
    pub base_url: String,
    /// The model id sent to the provider (core sends the router's model hash).
    pub model: String,
    #[serde(default)]
    pub system: Option<String>,
    pub prompt: String,
    pub max_tokens: u32,
    pub payment: SignedPayment,
}

/// Refuse a payment that would expire before the provider can settle it.
pub const SETTLE_MARGIN_SECS: u64 = 15;

impl RegistryEscalationRequest {
    pub fn validate(&self, now_secs: u64) -> Result<(), EscalationError> {
        let bad = |m: &str| Err(EscalationError::Invalid(m.to_string()));
        if self.escalation_id.is_empty()
            || self.escalation_id.len() > 64
            || !self
                .escalation_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return bad("escalation id");
        }
        if let Err(m) = validate_base_url(&self.base_url) {
            return Err(EscalationError::Invalid(m));
        }
        if self.model.is_empty()
            || self.model.len() > 200
            || self.model.bytes().any(|b| b.is_ascii_control())
        {
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
        self.payment
            .validate(now_secs, SETTLE_MARGIN_SECS)
            .map_err(EscalationError::Invalid)
    }

    fn wire_body(&self) -> Value {
        let mut messages = Vec::with_capacity(2);
        if let Some(s) = self.system.as_deref().filter(|s| !s.is_empty()) {
            messages.push(serde_json::json!({"role": "system", "content": s}));
        }
        messages.push(serde_json::json!({"role": "user", "content": self.prompt}));
        serde_json::json!({
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "stream": false,
        })
    }
}

/// A provider's answer to a paid request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidReply {
    pub status: u16,
    pub body: String,
    /// The raw `X-PAYMENT-RESPONSE` header, if any.
    pub payment_response: Option<String>,
}

/// The one HTTP operation a registry escalation needs.
pub trait PaidTransport: Send + Sync {
    /// `POST url` with a JSON body and `X-PAYMENT: <payment>`; no bearer, no redirects.
    fn post_json_paid(
        &self,
        url: &str,
        payment: &str,
        body: &Value,
        timeout: Duration,
    ) -> Result<PaidReply, EscalationError>;
}

impl PaidTransport for HttpTransport {
    fn post_json_paid(
        &self,
        url: &str,
        payment: &str,
        body: &Value,
        timeout: Duration,
    ) -> Result<PaidReply, EscalationError> {
        let http = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| EscalationError::Transport("could not start an HTTP client".into()))?;
        let resp = http
            .post(url)
            .header(X_PAYMENT, payment)
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
        let payment_response = resp
            .headers()
            .get(X_PAYMENT_RESPONSE)
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        let mut buf = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(resp, MAX_REPLY_BYTES as u64 + 1),
            &mut buf,
        )
        .map_err(|_| EscalationError::Transport("answer could not be read".into()))?;
        if buf.len() > MAX_REPLY_BYTES {
            return Err(EscalationError::BadResponse(
                "the answer is too large".into(),
            ));
        }
        let body = String::from_utf8(buf)
            .map_err(|_| EscalationError::BadResponse("the answer is not UTF-8".into()))?;
        Ok(PaidReply {
            status,
            body,
            payment_response,
        })
    }
}

/// The result of one registry escalation, returned to core. The charge is the authorized value:
/// an EIP-3009 authorization pays its full value or nothing.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryOutcome {
    pub escalation_id: String,
    pub content: String,
    pub usage: Option<Usage>,
    pub asset: String,
    pub network: String,
    pub payee: String,
    pub charged_base_units: String,
    /// The provider's receipt, if it sent one. Core verifies settlement on chain.
    pub receipt: Option<PaymentReceipt>,
}

/// Validate, send with the payment, parse. A provider that answers 402 refused the payment; the
/// error says what it asked for. Every failure after the send counts as possibly settled.
pub fn run_registry(
    req: &RegistryEscalationRequest,
    transport: &dyn PaidTransport,
    timeout: Duration,
    now_secs: u64,
) -> Result<RegistryOutcome, EscalationError> {
    req.validate(now_secs)?;
    let url = format!("{}/chat/completions", req.base_url.trim_end_matches('/'));
    let reply = transport.post_json_paid(
        &url,
        &req.payment.header_value(),
        &req.wire_body(),
        timeout,
    )?;
    if reply.status == 402 {
        let why = match parse_payment_required(&reply.body) {
            Some(p) => format!(
                "the provider refused the payment (it asks for {} base units to {})",
                p.max_amount_required.as_deref().unwrap_or("an unknown amount"),
                p.pay_to.as_deref().unwrap_or("an unknown payee")
            ),
            None => "the provider refused the payment".to_string(),
        };
        return Err(EscalationError::BadResponse(why));
    }
    if !(200..300).contains(&reply.status) {
        return Err(EscalationError::Provider(reply.status));
    }
    let (content, usage) = parse_reply(&reply.body)?;
    Ok(RegistryOutcome {
        escalation_id: req.escalation_id.clone(),
        content,
        usage,
        asset: req.payment.asset.to_ascii_lowercase(),
        network: req.payment.network.clone(),
        payee: req.payment.to.to_ascii_lowercase(),
        charged_base_units: req.payment.value.clone(),
        receipt: reply
            .payment_response
            .as_deref()
            .and_then(parse_payment_response),
    })
}
