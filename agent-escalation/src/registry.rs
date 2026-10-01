//! The registry route: escalate to a ModelRegistry CID through the InferenceRouter and pay with a
//! capped x402 authorization (ADR-2026-09-30 Rule-3 amendment, D3, kind B-2).
//!
//! This route is **disabled** in this build. The interface is here so the router, the activity
//! monitor and core's status surface share one shape, but [`DisabledRegistry`] refuses every
//! request and reports what is missing:
//!
//! - no InferenceRouter address is pinned for chain 40204 (the post-reroll redeploy, federation F-4);
//! - the x402 asset allowlist is empty: SALT is native, and B-2 needs a token implementing
//!   `TransferWithAuthorization` (for example a wrapped SALT; ADR owner decision O-1);
//! - core's lean crypto build has no EIP-712 hasher yet (ADR D3 precondition);
//! - registry model routing waits on the model precompile integration (federation F-1).
//!
//! Per ADR D3 the sidecar never sends typed-data bytes. It sends core the structured
//! [`X402PaymentRequest`] and core builds, caps and signs the authorization in its ceremony.

use serde::Serialize;

use crate::endpoint::EscalationOutcome;

/// The structured payment request the sidecar would hand to core (ADR D3: `{quote_id, recipient,
/// asset, amount, resource}`). Never raw EIP-712 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentRequest {
    pub quote_id: String,
    /// The InferenceRouter settlement address (core compares it with the pinned recipient).
    pub recipient: String,
    /// The allowlisted x402 asset contract.
    pub asset: String,
    /// Base units of the asset, as a decimal string (U256 range; core parses and caps it).
    pub amount: String,
    /// What is being paid for (the model CID or route).
    pub resource: String,
}

/// A registry-route failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("registry escalation is unavailable: {0}")]
    Disabled(String),
    #[error("invalid x402 payment request: {0}")]
    Invalid(String),
}

/// Whether the registry route can run, and why not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryRouteStatus {
    pub enabled: bool,
    pub reason: String,
    pub missing: Vec<String>,
}

/// The registry escalation route.
pub trait RegistryEscalation: Send + Sync {
    fn status(&self) -> RegistryRouteStatus;
    fn escalate(
        &self,
        model_cid: &str,
        payment: &X402PaymentRequest,
    ) -> Result<EscalationOutcome, RegistryError>;
}

/// The only registry route in this build: it refuses, honestly.
pub struct DisabledRegistry;

/// Why the registry route is off.
pub const REGISTRY_DISABLED_REASON: &str =
    "registry escalation is not deployed yet on chain 40204; use a member endpoint instead";

impl RegistryEscalation for DisabledRegistry {
    fn status(&self) -> RegistryRouteStatus {
        RegistryRouteStatus {
            enabled: false,
            reason: REGISTRY_DISABLED_REASON.to_string(),
            missing: vec![
                "InferenceRouter address pinned for chain 40204 (post-reroll redeploy, federation F-4)".into(),
                "x402 asset: a token with TransferWithAuthorization, such as a wrapped SALT (ADR O-1); the allowlist is empty".into(),
                "EIP-712 hasher in core's lean crypto build (ADR D3 precondition)".into(),
                "registry model routing after the model precompile integration (federation F-1)".into(),
            ],
        }
    }

    fn escalate(
        &self,
        _model_cid: &str,
        _payment: &X402PaymentRequest,
    ) -> Result<EscalationOutcome, RegistryError> {
        Err(RegistryError::Disabled(
            REGISTRY_DISABLED_REASON.to_string(),
        ))
    }
}

fn is_address(s: &str) -> bool {
    s.len() == 42 && s.starts_with("0x") && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
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
    if amount.is_empty()
        || amount.len() > 78
        || !amount.bytes().all(|b| b.is_ascii_digit())
        || amount.bytes().all(|b| b == b'0')
    {
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
