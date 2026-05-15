# eth-sender-test — Standard Operating Procedure

> **NOT a production tool.** Exists only as a fixture for the
> cit-agent-core integration tests that exercise the three-layer
> write-path enforcement: allow-list, HITL approval gate, and
> dispatcher.

## Why this capsule exists

Production write tools (provision_user, revoke_role,
anchor_session) all import `citrate:chain/eth-send` and call it
with tool-specific calldata. Before any of those land, the
harness needs an empirical witness that the host fn enforces:

1. allow-list (writes to undeclared addresses are blocked)
2. HITL approval gate (every write traverses the gate)
3. dispatcher (signed calldata reaches the chain only after
   approval)

This capsule is the minimal shape that drives the test surface.
It forwards `(to, data)` directly so the test fully controls
both inputs.

## Exported function

```wit
send: func(to: list<u8>, data: list<u8>) -> result<list<u8>, string>;
```

## Role gate

`Reviewer` + `ComplianceOfficer` (tier-high). Tests use a simple
allow-or-deny `ApprovalGate` implementation; the role-lattice
integration with the full BFT-style quorum lands in
CIT-AGENT-9c-5/6/7 alongside production tools.

## Side effects

In tests: none (canned tx hash). In production with a real
dispatcher: a signed transaction.

## Failure modes

| Failure | Capsule returns |
|---|---|
| `to.len() != 20` | `Err("ChainSendNotAuthorized: \`to\` must be 20 bytes, got N")` |
| `to` not in allow-list | `Err("ChainSendNotAuthorized: 0x<hex>")` |
| Approval gate denies | `Err("ChainSendApprovalRejected: <reason>")` |
| No approval gate configured | `Err("ChainSendApprovalRejected: no approval gate configured")` |
| Approval granted but no dispatcher | `Err("ChainSendDispatchFailed: no eth_send dispatcher configured")` |
| Dispatcher error | `Err("ChainSendDispatchFailed: <dispatcher message>")` |
