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
