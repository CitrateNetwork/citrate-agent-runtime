---
created: 2026-10-01
branch: hup/n3-anchor-batch
author: Larry Klosowski + Claude Opus 5.5
status: active
---

# citrate-agent-anchor

The nightly anchor batch over the local decision records (HUP-S7.3, runtime half; D-23).

Every HIC-1 / HIC-2 decision is a record in `citrate-agent-records`' hash-chained log. That chain
catches an edited, reordered or cut-off record, but not someone with write access rewriting the
whole log consistently. The nightly anchor closes that gap: once a UTC day is over, its records
become one batch and one 32-byte value on chain, and any record of that day can later be proven
against it.

## What it builds

| Piece | API | Notes |
|---|---|---|
| Batch | `build_day_batch(day, leaves)` | The day's records across segment rotations, in `seq` order. A gap or reorder is refused. 0 records: no batch. Deterministic. |
| Tree | `Tree` | RFC 6962: leaf `SHA-256(0x00 \|\| record_hash)`, node `SHA-256(0x01 \|\| left \|\| right)`; odd sizes promote the last node (never duplicate it). Uses `citrate_agent_records::merkle`'s hash functions; checked against its root and audit paths for sizes 1..70. Keeps every level, so a proof is O(log n). |
| Commitment | `BatchHeader::commitment()` | `SHA-256("citrate.agent-anchor.nightly.v1\n" \|\| be32(v) \|\| be64(day) \|\| be64(first_seq) \|\| be64(last_seq) \|\| be64(count) \|\| tree_root)`. This is the anchored value. |
| Proofs | `DayBatch::proof(seq)`, `prove(dir, ledger, seq)`, `verify_proof`, `verify_record_proof` | A proof carries the header, the record hash, its leaf index and the path. Verification checks the header commits to the anchored value, `seq = first_seq + leaf_index`, and the path. |
| Ledger | `AnchorLedger` | One JSON file, atomic rewrite, single writer (OS file lock). A day is recorded once; a different root for a recorded day is `Conflict`; overlapping `seq` ranges are `Overlap`; partly pruned days are recorded `incomplete` (reported, never anchored). |
| Plan | `plan_day(dir, ledger, day, now_ms, registry)`, `pending_days` | Closed days only (`DayNotClosed` otherwise). Returns `Empty`, `Pruned`, `Incomplete`, `Ready { call }` or `AlreadyAnchored`. |
| Calldata | `UnsignedAnchorCall`, `anchor_calldata`, `is_anchored_calldata`, `decode_anchor_calldata` | `AnchorRegistry.anchor(AnchorKind.NightlyMerkle, commitment)`: selector `0x9e621f4c` (`anchor(uint8,bytes32)`), kind word `2`, chain id 40204, value 0. `isAnchored(bytes32)` is `0x4f0b5801` for a read-only check. |

### Why a commitment and not the bare tree root

`AnchorRegistry` keys anchors by the committed value and refuses a value it has seen. Committing
to the day and the `seq` range as well as the tree root means the on-chain value says exactly which
records it covers, two days can never produce the same value, and a proof for one record cannot
be replayed for another (the `seq` is bound to the leaf position). The tree root alone is still in
the header, so a verifier with the header can recompute both.

### The ABI, pinned

Read from citrate-chain `contracts/src/cit_agent/AnchorRegistry.sol` (sha256
`deabbc4c…c585f8`, chain commit `0aab474b`): `enum AnchorKind { PerCapsule, PerApproval,
NightlyMerkle }` and `function anchor(AnchorKind kind, bytes32 root)`. Tests pin the selector
against keccak-256 of the signature and against `forge inspect AnchorRegistry methodIdentifiers`,
and the full calldata against `cast calldata "anchor(uint8,bytes32)" 2 0x11…11`.

Checked once on a local anvil devnet (2026-10-01, forge/cast/anvil 1.5.1): the registry deployed
from that source accepted the pinned calldata (`status 1`), `isAnchored(root)` returned `true`
through the crate's `isAnchored` calldata, `rootCountByKind(2)` returned `1`, and sending the same
calldata again reverted with `AlreadyAnchored`. That was a manual check with anvil's public
development account; nothing in this crate sends.

## Keyless (Rule 3)

Nothing here holds a key, signs or sends. Under the accepted Rule-3 ADR
(ADR-2026-09-30-rule3-budgetable-signatures; D-23 as amended by RT-2) the nightly anchor is signed
by a separate no-funds anchor key inside citrate-core's signature ceremony. This crate stops at the
unsigned call.

## Not built here (later WPs)

- The core half of S7.3: the anchor key, the ceremony path that signs and sends the call, the
  nightly schedule that calls `plan_day` for each `pending_days` entry, and writing the
  confirmation back with `AnchorLedger::mark_confirmed`.
- The `AnchorRegistry` address: no address is hard-coded. The 40204 address book was cleaned for
  the fresh-keys reroll, so core passes the address when it has one (`registry` argument).
- Proof survival across pruning: proofs are rebuilt from the retained records. Once a record of a
  batched day is pruned, `prove` for that day returns `PrunedDay`. Keep a day's segments for as long
  as its proofs are needed (agent-records' `max_segments` is off by default).
- No sidecar route or UI calls this crate yet.

## Formal model

`formal/AnchorBatch.tla`, TLC-green at two bounds and mutation-checked per property. See
[`formal/README.md`](formal/README.md).
