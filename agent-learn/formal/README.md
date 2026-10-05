---
created: 2026-10-01
branch: hup/n3-verified-learning
author: Larry Klosowski + Claude Opus 5.5
status: active
---

# agent-learn formal model

| Module | Models | Invariants | WP |
|---|---|---|---|
| `LearnRestart.tla` | One skill proposal across sidecar crashes and restarts: the proposals file, the write-ahead decision log, lost saves, log crash recovery, and reconciling the file with the log on open (HUP-S3.4 wiring) | `AtMostOneWrite`, `WriteImpliesRecorded`, `RejectFinal`, `AckedNotLost`, `PersistedIsTrue` (plus `TypeOK`) | HUP-S3.4 wiring |
| `ContradictionResolve.tla` | Learned memories on one key that disagree: accept (core's ledger marks every side `both`), the member's resolve (keep one, retract another), core applying it from the route answer or a later sync, lost saves, crashes and reconciling with the log (HUP-S3.4, fan-out 5) | `RetractRecorded`, `OneStanding`, `ResolveFinal`, `NoSilentMerge`, `LedgerFalseIsRetracted`, `LedgerTrueIsStanding` (plus `TypeOK`) | HUP-S3.4 |
| `SkillPersistence.tla` | Proposal, verifiers, member accept or reject, conflicts, the write (which can fail), publish approval, the publish build, and outside edits to the saved file, for independent proposals | `NothingProposedWithoutVerifiers`, `PersistImpliesVerifiedAndAccepted`, `NoSilentMerge`, `RejectRecordedAndFinal`, `PublishImpliesHIC1` (plus `TypeOK`) | HUP-S3.4 |

The planset (03_TLA_SPECS) names two invariants for this module, `PersistImpliesVerifiedAndAccepted`
and `PublishImpliesHIC1`. The other three cover the rest of US-3.4: nothing proposed without
verifiers, contradictions never merged silently, and a reject that is recorded and final.

As in `agent-loop/formal/TaintDowngrade.tla`, ground truth (`verdict`, `claim`, `acceptedEver`,
`conflict`, `approved`, `diskOk`) is kept apart from the guards the implementation evaluates
(`CanPropose`, `PersistGuard`, `PublishGuard`), so each guard can be mutated on its own. The
model's `claim` is ground truth too: it is what the model said, and no guard may read it.

Rust counterparts: `CanPropose` is `run_verified_workflow` (a `VerifiedRun` exists only after
`WorkflowOutcome::Succeeded` and a cross-check of the recorded verdicts), `PersistGuard` is
`Learner::accept`, and `PublishGuard` is `Learner::prepare_publish`.

## Run

```sh
cd agent-learn/formal
"$(brew --prefix openjdk)/bin/java" -XX:+UseParallelGC -cp ~/.tla/tla2tools.jar tlc2.TLC \
  -workers auto SkillPersistence.tla -config SkillPersistence.cfg
```

`CHECK_DEADLOCK FALSE` is set because the environment moves are bounded by `MaxSteps`, so every
behaviour ends; a final state is not a deadlock of the protocol.

## Results (2026-10-01, TLC 2.19 rev 5a47802)

| Config | States generated | Distinct | Depth | Result |
|---|---|---|---|---|
| `Props = {p1, p2}, MaxSteps = 3` (checked in) | 4,442,337 | 480,480 | 19 | no error (5 s) |
| `Props = {p1, p2}, MaxSteps = 6` | 9,542,421 | 936,780 | 21 | no error (10 s) |

## Mutation check (each one a single edit to the checked-in config, then restored)

| Mutant | Caught by |
|---|---|
| `CanPropose` reads the model's claim instead of the verdict | `NothingProposedWithoutVerifiers` |
| `CanPropose == TRUE` | `NothingProposedWithoutVerifiers` |
| persist without the member's press | `PersistImpliesVerifiedAndAccepted` |
| the accept decision is not recorded | `PersistImpliesVerifiedAndAccepted` |
| a hard conflict (same-name user skill) is ignored | `NoSilentMerge` |
| a soft conflict is written without the member's acknowledgement | `NoSilentMerge` |
| persist allowed from `rejected` | `RejectRecordedAndFinal` |
| persist allowed from any non-idle state | `RejectRecordedAndFinal` |
| the reject is not recorded | `RejectRecordedAndFinal` |
| publish allowed before persist | `PublishImpliesHIC1` |
| publish without the explicit approval | `PublishImpliesHIC1` |
| publish without re-reading the saved file | `PublishImpliesHIC1` |

A first draft stated the reject invariant over the current state only (`rejected => ~persisted`),
and the "persist from rejected" mutant survived, because after the bad write the state is no
longer `rejected`. The invariant now says a recorded reject keeps the proposal in `rejected`.

The matching Rust mutants (final verdict not required to pass, blocking conflict ignored, acks
ignored, approval not matched, publish before persist, publish without re-reading the file,
reject recorded as an approval, a contradiction stored as `true`, accept from any state,
provenance unchecked, persisted skill not validated by the loader) each fail at least one test
in `agent-learn/tests/learn_tests.rs` or the unit tests in `src/evidence.rs`.

## LearnRestart (2026-10-01, branch hup/n4-learn-e2e)

Rust counterpart: `Learner::open` (load the proposals file, then `reconcile_with_log`),
`Learner::propose` (save, or roll back and refuse), and the record, write, close order of
`Learner::accept`. Any save may be lost before a crash (`Save` is a separate, optional step).

```sh
cd agent-learn/formal
"$(brew --prefix openjdk)/bin/java" -XX:+UseParallelGC -cp ~/.tla/tla2tools.jar tlc2.TLC \
  -workers auto LearnRestart.tla -config LearnRestart.cfg
```

| Config | States generated | Distinct | Depth | Result |
|---|---|---|---|---|
| `MaxCrashes = 3` (checked in) | 287 | 183 | 13 | no error (under 1 s) |
| `MaxCrashes = 8` | 757 | 473 | 25 | no error (under 1 s) |

Mutation check (each a single edit, then restored):

| Mutant | Caught by |
|---|---|
| restart loads the file and ignores the log | `RejectFinal` |
| propose reports success without saving the file | `AckedNotLost` |
| the accept guard ignores the skill folder already on disk | `AtMostOneWrite` |
| reconcile treats any recorded accept as persisted | `PersistedIsTrue` |
| the accept is not recorded before the write | `WriteImpliesRecorded` |
| the reject is not written to the log | `RejectFinal` |

## ContradictionResolve (2026-10-01, branch hup/n5-learn-rest)

Rust counterparts: `Learner::resolve` (`ResolveGuard`, record first, then `Retracted`),
`reconcile_with_log` (`Reconcile`), `memory_conflicts` (which memories count as accepted), and
citrate-core `hermes_learn.rs` `Ledger::apply_resolution` (`CoreApply`, `CoreGuard`).

```sh
cd agent-learn/formal
"$(brew --prefix openjdk)/bin/java" -XX:+UseParallelGC -cp ~/.tla/tla2tools.jar tlc2.TLC \
  -workers auto ContradictionResolve.tla -config ContradictionResolve.cfg
```

| Config | States generated | Distinct | Depth | Result |
|---|---|---|---|---|
| `Mems = {m1, m2, m3}, MaxCrashes = 2` (checked in) | 38,627 | 12,900 | 17 | no error (1 s) |
| `Mems = {m1, m2, m3}, MaxCrashes = 3` | 64,754 | 22,296 | 18 | no error (1 s) |

The model found three things before any of them shipped, each now a Rust test:

1. A file that lost both the accept and the resolve of a memory brought it back as `proposed`
   after a restart (reconcile only handled a `persisted` file). Now a recorded resolution
   retracts whatever the file says
   (`store_tests::a_resolution_is_applied_even_when_the_accept_before_it_was_lost_too`).
2. Core must only promote the KEPT memory to `true` when it applies one resolution: promoting
   any memory left with no contradiction marks one `true` whose own retraction core has not
   applied yet (its answer was lost). Any other memory left `both` with nothing to contradict is
   settled by core's sync (`CoreSettle`), and only when the sidecar shows it standing. Core's
   `apply_resolution` and `sync_with_sidecar` follow the model.
3. A memory offered again after a lost save (`persist_failed`) did not count as accepted, so a
   later memory that disagreed was stored as plain `true` next to it. It counts now
   (`store_tests::a_memory_offered_again_after_a_lost_save_still_counts_as_accepted_for_contradictions`).

Mutation check (each a single edit, then restored):

| Mutant | Caught by |
|---|---|
| the kept memory may be in any state | `OneStanding` |
| a memory may be kept and retracted at once | `OneStanding` |
| the resolve is not recorded | `RetractRecorded` |
| reconcile retracts only a `persisted` file (finding 1) | `ResolveFinal` |
| reconcile ignores resolve records | `ResolveFinal` |
| core applies a resolution before the sidecar shows it | `NoSilentMerge` |
| core promotes any memory left without a contradiction (finding 2) | `NoSilentMerge` |
| core promotes the kept memory even when it is already `false` | `LedgerTrueIsStanding` |
| a memory offered again does not count as accepted (finding 3) | `LedgerTrueIsStanding` |
| core's sync settles a memory without asking whether the sidecar shows it standing | `NoSilentMerge` |
| core's sync settles a memory that still has contradictions | `NoSilentMerge` |

Rust mutants on `Learner::resolve` and the reconcile/conflict changes: dropping the `persisted`
check, the key check, the decision record, the widened reconcile arm, the `persist_failed`
counting, or counting a retracted memory as known each fail a test. The "same value" and "same
id" refusals guard each other (the same id is also the same value), and two accepted memories
with the same value cannot be built through the API (`already_known`), so those two mutants
survive as equivalent; both refusals stay as defence in depth.
