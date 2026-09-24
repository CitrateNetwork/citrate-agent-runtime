# revoke-role — Standard Operating Procedure

> Tier-high write tool. Encodes `revoke(...)` for RoleEscalation
> via the eth-send three-layer write path. Static 4-slot calldata.

## Exported function

```wit
revoke: func(user: string, tenant: string, reason: string)
    -> result<list<u8>, string>;
```

`reason` is free-form text; the capsule keccak256-hashes it to
the on-chain `bytes32 reason` field, matching the defense_prime
chat-tool semantics.

## Calldata derivation (inside the capsule)

- `reason_b = keccak256(reason)`
- `corr_id = keccak256("revoke_role|0x<user>|0x<tenant>|<reason>")`

## Role gate

Reviewer + ComplianceOfficer.

## Side effects

State change on RoleEscalation. Audit log records the call before
gate consultation.

## TLA+ spec carry-forward

Shares the RoleEscalation state machine with provision-user.
Deferred to CIT-AGENT-9c-write-specs.
