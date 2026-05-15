# query-decisions-by-tenant — Standard Operating Procedure

> Reads the N most-recent decisions for a tenant from
> AgentDecisionRegistryV2 on chain 40204.

## Purpose

Replacement for the BFR-INT-12 `query_decisions_by_tenant` chat
tool. First **multi-call** capsule: makes 1 + N eth_call
requests per invocation (one `latestByTenant` + one `getDecision`
per ID returned).

## Exported function

```wit
query: func(tenant: string, n: u32) -> result<list<decision-summary>, string>;
```

- `tenant`: 32-byte scope hash, `0x<64-hex>` or `<64-hex>`.
- `n`: max number of decisions to fetch (capped at 50 inside
  the capsule).
- Returns `list<decision-summary>` — empty if no decisions exist
  for the tenant.

## Role gate

`Operator` (tier-low, auto-approved).

## Side effects

None. All reads.

## N-cap policy

The capsule clamps `n` to `MAX_N = 50` silently. Rationale:

- The LLM passes user intent (a number); the capsule enforces
  the bound. An adversarial input of `n = 2^32 - 1` does NOT
  trigger billions of RPC calls.
- The cap mirrors the BFR-INT-12 chat-tool contract; consumers
  see consistent behavior across the migration.
- The host fn would have no way to enforce this cap centrally
  because "what `n` means" varies per tool.

## How the capsule guarantees one-contract scope

`REGISTRY_ADDR = 0x4a86659BDab24dc444C72fbbaD4cd83491820E40` is
hardcoded into the Rust source. Both eth_call invocations use
this exact address. The manifest's `chain_calls` allow-list
MUST match — if it doesn't, the FIRST call fails with
`ChainCallNotAuthorized` and the capsule short-circuits the
loop (no subsequent calls go out).

## Failure modes

| Failure | Capsule returns |
|---|---|
| `tenant` not 32-byte hex | `Err("expected 32-byte hex (64 chars), got N")` |
| `latestByTenant` response < 64 bytes | `Err("bytes32[] response too short")` |
| Decision response missing outer offset | `Err("decision response missing outer offset")` |
| Host fn rejects (allow-list miss) | `Err("ChainCallNotAuthorized: 0x...")` propagated |
| `getDecision` response truncated for ID N | Loop short-circuits with the decode error |

## Compliance evidence

Like list-compliance-posture, this capsule is the only path the
agent has to read AgentDecisionRegistryV2 data. The compiled
WASM is reproducible from source + signed by the bundled-tier
publisher key.
