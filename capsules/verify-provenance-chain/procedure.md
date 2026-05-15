# verify-provenance-chain — Standard Operating Procedure

> Single-call verifyChain against PartProvenanceRegistry. Returns
> a (bool ok, chain: list<bytes32>) tuple.

## Exported function

```wit
query: func(part-hash: string) -> result<verify-result, string>;
```

- `part-hash`: 32-byte hash as `0x<64-hex>`.
- Returns `verify-result { ok: bool, chain: list<list<u8>> }`.

`ok = false` with `chain = []` is a VALID response (unknown
part). The capsule returns this as `Ok(verify-result)`, NOT
`Err(...)` — the caller distinguishes "verification ran and
said no" from "verification couldn't run."

## Role gate

`Operator` (tier-low).

## Side effects

None.

## ABI decoder notes

The Solidity return for `(bool, bytes32[])`:
- chunk 0 (0..32): bool
- chunk 1 (32..64): offset to array (typically 0x40)
- at offset: array length, then N × 32-byte entries

The capsule reads the offset, jumps there, then reads length +
entries. Variable-length tail is bounded by the response size
the host fn returns; an under-sized response fails decode with
`"verifyChain chain entries truncated: ..."`.

## Failure modes

| Failure | Capsule returns |
|---|---|
| `part-hash` not 32-byte hex | `Err("expected 32-byte hex (64 chars), got N")` |
| Response < 64 bytes | `Err("verifyChain response too short")` |
| Offset header has bits beyond u64 | `Err("bytes32[] offset has unexpected high bits")` |
| Chain entries truncated for declared length | `Err("verifyChain chain entries truncated: ...")` |
| Host fn rejects (allow-list miss) | `Err("ChainCallNotAuthorized: 0x...")` |
