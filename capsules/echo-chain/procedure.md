# echo-chain — Standard Operating Procedure

> Proof-of-pipeline capsule for the `citrate:chain/eth-call`
> host function. Used by integration tests to verify the
> capability sandbox enforces per-address allow-listing.

## Purpose

The seven defense_prime tool capsules (CIT-AGENT-9c-1..7) all import
`citrate:chain/eth-call` and declare a single-address allow-list
in their manifest. This capsule is the minimal version of that
shape — it forwards `(to, data)` directly to the host fn so the
test harness can exercise both the authorized and unauthorized
paths.

## Exported function

```wit
query: func(to: list<u8>, data: list<u8>) -> result<list<u8>, string>;
```

## Role gate

`Operator` (tier-low, auto-approved under the standard policy
bundle).

## Side effects

None. The `eth-call` host fn is read-only.

## Allow-listed addresses

- `0x4a86659BDab24dc444C72fbbaD4cd83491820E40` — defense_prime
  AgentDecisionRegistryV2 contract (BFR-INT-12b).

Any other `to` argument produces
`Err("ChainCallNotAuthorized: 0x<address>")` returned through
the WIT `result<>` type. The host fn does not log or audit the
rejection — the capsule's caller is responsible for surfacing
the failure to the operator.

## Failure modes

| Failure | Symptom |
|---|---|
| `to.len() != 20` | `Err("ChainCallNotAuthorized: `to` must be 20 bytes, got N")` |
| `to` not in allow-list | `Err("ChainCallNotAuthorized: 0x<hex>")` |
| (CIT-AGENT-9c-1: RPC unavailable) | `Err("eth_call RPC: <reason>")` |
