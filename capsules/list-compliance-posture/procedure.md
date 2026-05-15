# list-compliance-posture — Standard Operating Procedure

> Reads a single compliance row from BoeingComplianceRegistry on
> chain 40204 (Stage-9 deployment).

## Purpose

Replacement for the BFR-INT-12 `list_compliance_posture` chat
tool. Same functional behavior (return one row given
`(framework_slug, scope)`), but executed inside a wasmtime
sandbox with manifest-declared capabilities.

## Exported function

```wit
query: func(framework: string, scope: string) -> result<posture-row, string>;
```

- `framework`: slug like `"fedramp-moderate"`, `"fedramp-high"`,
  `"cmmc-l3"`, `"itar"`. The capsule keccak256-hashes the slug
  to derive the bytes32 framework key the contract expects.
- `scope`: 32-byte tenant hash, supplied as `0x<64-hex>` or
  `<64-hex>`. The capsule rejects non-32-byte input.
- Returns `posture-row` (9 fields) on success; `string` error
  on parse failure, calldata rejection, or response decode
  failure.

## Role gate

`Operator` (tier-low, auto-approved under the standard policy
bundle).

## Side effects

None. The capsule only performs `eth_call` reads. The host fn
enforces that the destination is the manifest's single declared
address: `0x8dbbbc46d840f40205b48d76aa9fc5063b7d55d8`.

## How the capsule guarantees the call goes to the right contract

The contract address is **hardcoded into the capsule's Rust
source** (`REGISTRY_ADDR = [0x8d, 0xbb, ...]`). It cannot be
overridden by the LLM, the harness, or the operator. The
manifest's `chain_calls` allow-list MUST match this hardcoded
address — if a future contract redeployment moves the registry,
the capsule must be rebuilt + re-published with the new address.

This is the harder route over "pass the contract address as an
argument": one less untrusted input to the call, and any
mismatch between the capsule's compiled-in address and the
manifest's allow-list fails CLOSED at the host fn boundary.

## Failure modes

| Failure | Capsule returns |
|---|---|
| `scope` not 32-byte hex | `Err("expected 32-byte hex (64 chars), got N")` |
| `scope` has non-hex chars | `Err("bad hex at byte N: XX")` |
| Host fn rejects `to` (cap allow-list miss) | `Err("ChainCallNotAuthorized: 0x...")` propagated |
| Response < 288 bytes | `Err("row response truncated: got N, expected ≥ 288")` |

## Compliance evidence

This capsule's existence + signature is the evidence artifact
for SI-7 ("Software, Firmware, and Information Integrity"): the
agent CANNOT call BoeingComplianceRegistry except through this
capsule, and this capsule's bytes are reproducible from source
+ signed by the bundled-tier publisher key.
