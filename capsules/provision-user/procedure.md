# provision-user — Standard Operating Procedure

> Tier-high write tool. Encodes `requestElevation(...)` for
> RoleEscalation and submits via the eth-send three-layer
> write path.

## Exported function

```wit
provision: func(user: string, tenant: string, role: string,
                duration-sec: u32, reauth-kind: string)
    -> result<list<u8>, string>;
```

## Calldata derivation (inside the capsule)

- `corr_id = keccak256("provision_user|0x<user>|0x<tenant>")` —
  deterministic so retries land on the same on-chain entry
  (contract enforces NoDoubleActiveGrant).
- `reauth_proof = [0x01]` — placeholder until CIT-AGENT-10's
  PIV/CAC signing surface lands.

## Role gate

Reviewer + ComplianceOfficer (tier-high). The harness's
`ApprovalGate` intercepts the eth_send call before any signature
or RPC happens.

## Side effects

State change on RoleEscalation. The host fn's `eth_send_history`
records the call BEFORE the gate consultation — denied attempts
are audited alongside successful submissions.

## Failure modes

| Failure | Capsule returns |
|---|---|
| Any bytes32 arg malformed | `Err("expected 32-byte hex (64 chars), got N")` |
| Allow-list miss | `Err("ChainSendNotAuthorized: 0x...")` |
| HIC denial | `Err("ChainSendApprovalRejected: <reason>")` |
| Dispatcher error | `Err("ChainSendDispatchFailed: <e>")` |

## TLA+ spec carry-forward

Tier-high tools require a TLA+ spec per RFC §9.2. The RoleEscalation
state machine (provision → active → revoked / expired) is shared
between this capsule and revoke-role. Deferred to
CIT-AGENT-9c-write-specs.
