---
created: 2026-09-30
branch: hup/s2-taint
author: Larry Klosowski + Claude Opus 5.5
status: active
---

# agent-loop formal models

| Module | Models | Properties | WP |
|---|---|---|---|
| `TaintDowngrade.tla` | `run_turn_with`'s per-call path choice and `TaintState`, with the real annotations (`effect` none/write/spend/sign/unknown, `trust` trusted/untrusted/unknown), host capability (`honors_explicit_approval`), outcomes, loop-generated errors and member clears | `NoUnapprovedEffectAfterTaint`, `TaintedEffectNeedsHIC`, `UntaintedUnchanged`, `TaintSound` (invariants); `TaintMonotone` (action property: taint only goes away by `MemberClear`) | HUP-S2.7 |

It refines the abstract `TaintDowngrade` invariant of citrate-core's
`src-tauri/formal/AgentLoop.tla` (HUP-S1.3), which models the gate as
`{human-approve, human-deny, auto}`. This module adds the parts that one leaves out:
unknown annotations, hosts that cannot ask a person (the call is refused), per-result trust, and
the member clear.

The properties are stated over **ground truth** (`MayChangeState`, `CarriesOutsideContent`), and the
guard is modelled separately as **the implementation** (`IsEffectful`, `OutputUntrusted`,
`NeedsHIC`, `PathOf`). The first draft defined both through the same helpers, so two mutants
survived. The split is what makes mutating the guard detectable.

## Run

```sh
cd agent-loop/formal
"$(brew --prefix openjdk)/bin/java" -XX:+UseParallelGC -cp ~/.tla/tla2tools.jar tlc2.TLC \
  -workers auto TaintDowngrade.tla -config TaintDowngrade.cfg
```

## Results (2026-09-30, TLC 2.x)

| Config | States generated | Distinct | Depth | Result |
|---|---|---|---|---|
| `MaxCalls = 5, MaxClears = 1` (checked in) | 21,900 | 120 | 7 | no error |
| `MaxCalls = 8, MaxClears = 3` | 80,358 | 399 | 12 | no error |

## Mutation check (each one a single edit, then restored)

| Mutant | Caught by |
|---|---|
| unknown effect treated as not effectful (`IsEffectful`) | `NoUnapprovedEffectAfterTaint` |
| guard ignores taint (`NeedsHIC == FALSE`) | `NoUnapprovedEffectAfterTaint` |
| a host that cannot ask a person still gets the call (ordinary path) | `NoUnapprovedEffectAfterTaint` |
| guard ignores the taint flag, so every effectful call is explicit even untainted | `UntaintedUnchanged` |
| taint recomputed per call (`tainted' = ingest`) | `TaintSound` |
| an error body from an untrusted tool does not taint | `TaintSound` |
| unknown trust treated as trusted (`OutputUntrusted`) | `TaintSound` |
| a call clears the taint (both flags reset without a member) | `TaintMonotone` |

The matching Rust mutants (guard off, unknown effect/trust defaults flipped, error bodies ignored,
refusal off, `taint()` clearing an existing taint) each fail at least one test in
`agent-loop/tests/taint_tests.rs`.
