---
created: 2026-10-01
branch: hup/n3-folder-grants
author: Larry Klosowski + Claude Opus 5.5
status: active
---

# agent-grants formal model

| Module | Models | Properties | WP |
|---|---|---|---|
| `FolderGrant.tla` | `FolderGrants::{grant, revoke, check}` over a small folder tree with a deny-list subtree (`~/.ssh`), `.env` files inside and outside a project, and requests that separate what the agent wrote (`lex`) from where the kernel lands (`res`): plain, symlink into the deny list, `link/..`, symlink out of a grant, symlink into a grant, a deny-list name linking somewhere harmless. Grants: root, read/write, subtree/shallow, folder/full access, grant time, expiry, revoked. A discrete clock | Invariants `NoParentEscape`, `SecretsNeverReadable`, `ExpiredGrantInert`, `NoAccessOutsideActiveGrant`, `ReadNotImpliesWrite`, `DotEnvOnlyViaFolderGrant`, `FullAccessReadOnly`, `FullAccessBounded`, `NoGrantRootedInDenyList`; liveness `FullAccessExpires` (weak fairness on the clock) | HUP-S2.1 |

The planset (`03_TLA_SPECS.md`) names `NoParentEscape`, `SecretsNeverReadable`,
`ExpiredGrantInert` and `ReadNotImpliesWrite`; the WP brief adds "no access
outside an active grant" (`NoAccessOutsideActiveGrant`, the conjunction of the
first three), "deny list always wins" (`SecretsNeverReadable`), "expired and
revoked grants never allow" (`ExpiredGrantInert`) and "full access expires"
(`FullAccessBounded` + `FullAccessExpires`, with `FullAccessReadOnly` for the
D-15 amendment).

As in `agent-loop/formal/TaintDowngrade.tla`, the properties are stated over
**ground truth** (`SpecUnder`, `SpecSecret`, `SpecCovers`, `SpecLive`, all on
the resolved target) and the checker is modelled separately as **the
implementation** (`ImplUnder`, `ImplSecret`, `GuardDenies`, `ImplCovers`,
`ImplActive`, `Decide`, and `GrantA`'s guard). `Decide` is a pure function of
the state, and each property quantifies over every request and operation in
every reachable state, so no history variable is needed (the first draft kept
a `last` decision and ran past 4 million distinct states without finishing).
Members may ask for any grant, including invalid full-access ones; only
`GrantA`'s guard refuses them, so that guard is what the mutants test.

Model bound: a full-access grant is only issued when it expires within
`MaxClock`, so the liveness check sees the clock reach its expiry. Real time
does not stop at `MaxClock`.

## Finding

The first draft of both the Rust `check` and the model registered every live
folder grant's root as a `.env` project root for the guard, then picked any
covering grant. TLC found a short counterexample: a **shallow** folder
grant on a high folder made it a project root without covering a `.env` file
two levels down, and a full-access grant then covered that file, so full access
read a `.env`. The fix, in both: check folder grants first (their roots as
project roots, allowed only if one covers the target), then full access with
the guard re-run without project roots. Rust regression test:
`a_shallow_folder_grant_does_not_unlock_dotenv_below_it_for_full_access`
(seen failing before the fix); the traversal fuzz's full-access world now
holds a shallow grant and fails on the old code too.

## Run

```sh
cd agent-grants/formal
"$(brew --prefix openjdk)/bin/java" -XX:+UseParallelGC -cp ~/.tla/tla2tools.jar tlc2.TLC \
  -workers auto FolderGrant.tla -config FolderGrant.cfg
```

## Results (TLC 2.19, 2026-10-01)

| Config | States generated | Distinct | Depth | Time | Result |
|---|---|---|---|---|---|
| `FolderGrant.cfg`: `MaxGrants = 2, MaxClock = 3, FullTTL = 2, FolderTTLs = {0, 1}`, all invariants + `FullAccessExpires` | 270,585 | 153,484 | 8 | 1 min 29 s | no error |
| `FolderGrant_Larger.cfg`: `MaxGrants = 2, MaxClock = 4, FullTTL = 3, FolderTTLs = {0, 1, 2}`, same properties | 1,071,285 | 595,915 | 9 | 4 min 34 s | no error |

Non-vacuity: each of `SomethingAllowedNever`, `FullReadNever` (a read allowed
through full access) and `EnvAllowedNever` (a `.env` read allowed), added as an
invariant, is violated. So allowed decisions, full-access reads and `.env`
reads through a folder grant are all reachable, and the properties above are
not true only because nothing is ever allowed.

## Mutation check (each one a single edit, then restored)

| Mutant | Caught by |
|---|---|
| coverage judged on the lexical location (a `..`-first order) | `NoParentEscape` |
| guard checks only the request as written, not the resolved target | `SecretsNeverReadable` |
| revocation ignored | `ExpiredGrantInert` |
| expiry inclusive (`t <= exp`) | `ExpiredGrantInert` |
| access ignored when selecting live grants | `ReadNotImpliesWrite` |
| full-access phase reuses the folder project roots (the finding) | `DotEnvOnlyViaFolderGrant` |
| full access may be granted for writing | `FullAccessReadOnly` |
| full-access TTL limit off by one | `FullAccessBounded` |
| shallow scope reaches grandchildren | `NoParentEscape` |
| grant-root deny check skipped | `NoGrantRootedInDenyList` |
| no fairness on the clock | `FullAccessExpires` (temporal) |

The matching Rust mutants are listed in the crate README; each fails at least
one test.
