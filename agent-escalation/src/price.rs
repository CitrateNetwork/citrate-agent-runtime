//! The member's price card for an endpoint, and the arithmetic that turns tokens into a cost.
//!
//! Amounts are integer **micro-units** of the member's currency (micro-USD for a typical
//! OpenAI-compatible provider). Prices are per one million tokens, the unit providers publish.
//! All arithmetic is done in `u128` and fails closed (`None`) when the result does not fit `u64`.

use serde::{Deserialize, Serialize};

/// Tokens added per message for the chat template (role markers, separators). Conservative.
pub const PER_MESSAGE_OVERHEAD_TOKENS: u64 = 16;

const PER_MTOK: u128 = 1_000_000;

/// A member-entered price card. The member copies these numbers from their provider's pricing
/// page; the app cannot verify them, and says so wherever a price is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Price {
    /// Micro-units charged per 1,000,000 input (prompt) tokens.
    pub input_micros_per_mtok: u64,
    /// Micro-units charged per 1,000,000 output (completion) tokens.
    pub output_micros_per_mtok: u64,
}

/// Token counts as the provider reported them in `usage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

impl Price {
    /// The most this request can cost: `input_tokens` at the input price plus `max_output_tokens`
    /// at the output price, rounded **up** to the next whole micro-unit. `None` on overflow.
    pub fn upper_bound(&self, input_tokens: u64, max_output_tokens: u64) -> Option<u64> {
        let a = u128::from(input_tokens).checked_mul(u128::from(self.input_micros_per_mtok))?;
        let b =
            u128::from(max_output_tokens).checked_mul(u128::from(self.output_micros_per_mtok))?;
        let total = a.checked_add(b)?;
        let micros = total.div_ceil(PER_MTOK);
        u64::try_from(micros).ok()
    }

    /// The cost of a completed request from the provider's reported usage (same rounding).
    pub fn cost(&self, usage: Usage) -> Option<u64> {
        self.upper_bound(usage.prompt_tokens, usage.completion_tokens)
    }
}

/// An upper bound on the input tokens of a request made of `texts` (one per message).
///
/// Byte-level tokenizers emit at most one token per byte for ordinary text, so the UTF-8 byte
/// count plus a per-message template allowance never under-counts. It over-counts by roughly 3-4x
/// for English, which makes the quoted price a ceiling; settlement then charges the provider's
/// reported usage when it reports one.
pub fn input_token_bound(texts: &[&str]) -> u64 {
    texts.iter().fold(0u64, |acc, t| {
        acc.saturating_add(t.len() as u64)
            .saturating_add(PER_MESSAGE_OVERHEAD_TOKENS)
    })
}
