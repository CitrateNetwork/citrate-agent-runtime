//! # citrate-agent-escalation: escalate when needed, at a price the member sees (HUP-S1.5)
//!
//! US-1.5: Hermes can hand a hard planning step to the member's own endpoint (or, later, a
//! registry model) and pay for it within the member's budget.
//!
//! The split ("brain in the sidecar, hands in core", ADR-2026-09-30-hermes-loop-in-sidecar):
//!
//! - **citrate-core** owns the member's endpoint list, seals each API key in the OS keyring,
//!   quotes the worst-case price, shows it, checks the daily spend budget (asking the member when
//!   the price would exceed it), reserves the price write-ahead, and only then calls the sidecar.
//! - **This crate** (used by the sidecar's `POST /escalations`) validates the request, refuses one
//!   whose reservation does not cover the worst case, sends one chat completion with the key it was
//!   handed for that request, and settles: the provider's reported usage at the member's price,
//!   never more than the reservation. The key is never written to disk, logged, or returned.
//! - The **registry route** (InferenceRouter + x402, [`run_registry`]): core reads the router on
//!   chain, builds an EIP-3009 authorization, has the member approve it in the SignatureCeremony,
//!   and passes the signed payment here; this crate sends one paid chat completion with the
//!   `X-PAYMENT` header and returns the answer with the provider's `X-PAYMENT-RESPONSE` receipt.
//!   Core decides whether the route is on (pinned router, allowlisted asset).
//!
//! Keyless (Rule 3): nothing here signs, holds a wallet key, or talks to a chain.

mod endpoint;
mod price;
mod registry;

pub use endpoint::{
    parse_reply, run, settle, validate_base_url, wire_body, ApiKey, Charge, EscalationError,
    EscalationOutcome, EscalationRequest, HttpTransport, Transport, MAX_ESCALATION_TOKENS,
    MAX_KEY_LEN, MAX_PROMPT_BYTES, MAX_REPLY_BYTES,
};
pub use price::{input_token_bound, Price, Usage, PER_MESSAGE_OVERHEAD_TOKENS};
pub use registry::{
    parse_payment_required, parse_payment_response, registry_route_status, run_registry,
    x402_payment_request, PaidReply, PaidTransport, PaymentReceipt, PaymentRequired,
    RegistryError, RegistryEscalationRequest, RegistryOutcome, RegistryRouteStatus, SignedPayment,
    X402PaymentRequest, MAX_RECEIPT_HEADER_BYTES, SETTLE_MARGIN_SECS, X402_SCHEME, X402_VERSION,
    X_PAYMENT, X_PAYMENT_RESPONSE,
};
