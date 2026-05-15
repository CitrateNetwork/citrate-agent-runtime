# query-supplier-status — Standard Operating Procedure

> Reads a supplier row from SupplierRegistry on chain 40204.

## Exported function

```wit
query: func(supplier-id: string) -> result<supplier-view, string>;
```

`supplier-id` is a 32-byte hash as `0x<64-hex>`. Returns a
5-field record: `(supplier-id, scope, state, registered-at,
qualification-period-days)`.

## Role gate

`Operator` (tier-low).

## Side effects

None.

## Failure modes

| Failure | Capsule returns |
|---|---|
| `supplier-id` not 32-byte hex | `Err("expected 32-byte hex (64 chars), got N")` |
| Response < 192 bytes | `Err("supplier response truncated: got N, expected ≥ 192")` |
| Host fn rejects (allow-list miss) | `Err("ChainCallNotAuthorized: 0x...")` propagated |
| Supplier doesn't exist (contract reverts) | (after 9c-1-rpc) RPC error propagated |

## How the capsule guarantees one-contract scope

Hardcoded `REGISTRY_ADDR = 0x425064443c3c3392c47dcbe10d455831545efd9b`.
Manifest's `chain_calls` allow-list must match — any drift
fails closed at the host fn boundary.
