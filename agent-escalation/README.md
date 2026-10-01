---
created: 2026-10-01T00:00:00Z
branch: hup/n4-escalation
author: Larry Klosowski + Claude Opus 5.5
status: active
wp: HUP-S1.5
---

# citrate-agent-escalation

The runtime half of the Hermes escalation router (HUP-S1.5, US-1.5). citrate-core owns the
member's endpoints, seals each API key in the OS keyring, quotes and shows the worst-case price,
checks the daily spend budget (asking the member when needed) and reserves the price before it
calls the sidecar. This crate, behind the sidecar's `POST /escalations`:

- validates the request and refuses one whose reservation is below the worst case under its own
  price card (so a settled charge can never exceed what core's budget already holds);
- sends one OpenAI-compatible chat completion with the key it was handed for that request (a
  bearer header; the buffer is wiped; never logged, stored or returned; redirects are not
  followed);
- settles: the provider's reported usage at the member's price, capped at the reservation, or the
  full reservation when no usage is reported.

Errors carry `sent`: `false` only when nothing left the machine (core then charges nothing).

The registry route (ModelRegistry CID through the InferenceRouter, paid by a capped x402
authorization per ADR-2026-09-30 D3) is an interface, `RegistryEscalation`, with one
implementation, `DisabledRegistry`, which refuses and lists what is missing: an InferenceRouter
pinned on 40204 (federation F-4), an allowlisted x402 asset such as a wrapped SALT (ADR O-1),
core's EIP-712 hasher (ADR D3), and registry model routing (federation F-1).

Keyless (Rule 3): nothing here signs, holds a wallet key, or talks to a chain.

Cross-repo golden: `worst_case_golden_shared_with_core` must match citrate-core
`escalation_tests.rs::the_quote_matches_the_sidecars_worst_case_golden`.
