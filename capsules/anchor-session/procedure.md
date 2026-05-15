# anchor-session — Standard Operating Procedure

> Tier-high write tool. Encodes `anchor(...)` for
> AuditBundleRegistry. Static 7-slot calldata.

## Exported function

```wit
anchor: func(kind: u8, session-id: string, scope: string,
             merkle-root: string, ipfs-cid: string,
             entry-count: u64)
    -> result<list<u8>, string>;
```

## Calldata derivation (inside the capsule)

- `bundle_id = keccak256(session_id || merkle_root)` —
  deterministic for idempotent retries.
- Empty / `"0x"` ipfs_cid is treated as zero bytes32.
- `kind` is bounded 0..2 inside the capsule.

## Role gate

Reviewer + ComplianceOfficer.

## Side effects

State change on AuditBundleRegistry. Audit log records the call
before gate consultation.

## TLA+ spec carry-forward

AuditBundleRegistry state machine (anchored / finalized) deferred
to CIT-AGENT-9c-write-specs.
