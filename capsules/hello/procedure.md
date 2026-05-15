# hello — Standard Operating Procedure

> Pure-compute proof-of-pipeline capsule. No side effects.

## Purpose

Demonstrates the cit-agent capsule build → archive → load →
instantiate pipeline with a minimal worked example. Useful as:

- Smoke test for the toolchain (cargo-component, wasm-tools)
- Reference shape for the 7 Boeing tool conversions
  (CIT-AGENT-9c) and beyond
- Empirical witness that the cit-agent linker can load a real
  compiled WASM component (CIT-AGENT-9a covered the converse —
  rejecting a component with undeclared imports)

## Exported function

```wit
greet: func(name: string) -> string;
```

Returns `"Hello, <name>"`, or `"Hello, world"` if `name` is empty.

## Role gate

`Operator` (tier-low, auto-approved under the standard policy
bundle).

## Side effects

None.

## Failure modes

- `WitMismatchError` — bundle's WIT does not match the manifest's
  declared capability set. (Cannot occur for this capsule: the
  WIT declares no imports; the manifest declares zero capabilities.)
- `CapsuleSignatureInvalid` — manifest signature does not verify
  against the bundled-tier canonical publisher key. (Will be
  exercised once CIT-AGENT-10 wires the bundled-tier signing
  ceremony.)
