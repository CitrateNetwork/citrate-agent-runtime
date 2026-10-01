---
created: 2026-10-01
branch: hup/n3-anchor-batch
author: Larry Klosowski + Claude Opus 5.5
status: active
---

# agent-anchor formal model

| Module | Models | Properties | WP |
|---|---|---|---|
| `AnchorBatch.tla` | `plan_day` / `prove` / `AnchorLedger` over a decision log that grows on the current UTC day, rotates and prunes oldest first, and can be rewritten wholesale by someone with disk access | `BatchedHaveValidProof`, `ProofsSound`, `RootCoversExactlyDay`, `NoDoubleAnchor`, `NoRebatchDifferentRoot`, `IncompleteNeverAnchored` (invariants); `EveryRecordEventuallyBatchedOrReported` (liveness) | HUP-S7.3 |

The planset (03_TLA_SPECS) names `EveryDecisionEventuallyAnchoredOrReported` and
`NoDoubleAnchor`. Here the liveness half is stated up to the ledger ("batched or reported"),
because getting a batched day on chain is core's ceremony (a later WP); `NoDoubleAnchor` is split
into the per-record form (`NoDoubleAnchor`: no record in two ledger entries) and the per-day form
(`NoRebatchDifferentRoot`: a day is never recorded with two roots).

What is abstracted:

- **Hashing.** The root is `<<day, {(seq, content)}>>`, an injective commitment. That is the
  collision-resistance assumption on SHA-256; the RFC 6962 tree shape, the leaf/node prefixes and
  the commitment bytes are covered by the Rust tests (the tree is checked against
  `citrate_agent_records::merkle` for every size 1..70, and the commitment formula is pinned).
- **Time.** A record's day is the clock day when it is appended. The decision log clamps
  timestamps to be non-decreasing, so a closed day never gains a record; `Batch(d)` requires
  `d < clock`, matching `plan_day`'s `DayNotClosed`.
- **Rewrite.** `Rewrite(i)` bumps a retained record's content version: a consistent rewrite of
  the log, which the hash chain alone does not detect. `ReBatch` models `plan_day` on an already
  batched day whose records changed: refused with `Conflict` (an alarm), ledger unchanged.
- **Proofs.** `ProveResult` is `prove`: unavailable when the record or part of its day was
  pruned, `conflict` when the rebuilt root differs from the recorded one, else `valid`, and
  `MkProof` is the proof it builds from the day's retained records.

## Run

```sh
cd agent-anchor/formal
"$(brew --prefix openjdk)/bin/java" -XX:+UseParallelGC -cp ~/.tla/tla2tools.jar tlc2.TLC \
  -workers auto AnchorBatch.tla -config AnchorBatch.cfg
```

## Results (2026-10-01, TLC 2.x, openjdk via Homebrew)

| Config | States generated | Distinct | Depth | Time | Result |
|---|---|---|---|---|---|
| `AnchorBatch.cfg`: `MaxDay = 3, MaxRecords = 4, MaxPrune = 2, MaxRewrite = 1` (invariants + liveness) | 12,329 | 5,813 | 15 | 1 s | no error |
| `AnchorBatch_Large.cfg`: `MaxDay = 4, MaxRecords = 6, MaxPrune = 3, MaxRewrite = 2` (invariants + liveness) | 2,073,572 | 756,731 | 22 | 3 min 51 s | no error |

## Mutation check (each one a single edit, run with a config holding only `TypeOK` and the target property, then restored)

| Mutant | Caught by |
|---|---|
| `Batch` allows the current day (`d <= clock`), so a record can join a day after its root is fixed | `RootCoversExactlyDay` |
| `Batch` selects `day <= d` and drops the overlap guard | `NoDoubleAnchor` |
| `ReBatch` overwrites the root instead of raising `Conflict` | `NoRebatchDifferentRoot` |
| the incomplete branch also records a root | `IncompleteNeverAnchored` |
| `prove` builds the tree over every retained record, not the day's | `BatchedHaveValidProof` |
| `prove` skips the root comparison (always `valid`) | `ProofsSound` |
| no fairness on `Batch` | `EveryRecordEventuallyBatchedOrReported` |

With the full config, the first two mutants are reported by `BatchedHaveValidProof` first (it is
checked before the others); the single-property runs show each property bites on its own.

The matching Rust mutants (seq-to-position binding dropped from `verify_proof`, last node
duplicated instead of promoted, open day allowed, overlap guard off, partial-day check
off-by-one, day dropped from the commitment, ledger idempotency ignoring the commitment,
`plan_day` conflict check off, seq gap check off, dirty calldata word accepted, `prove`'s
pruned-day check off) each fail at
least one test in `agent-anchor/tests/anchor.rs`.
