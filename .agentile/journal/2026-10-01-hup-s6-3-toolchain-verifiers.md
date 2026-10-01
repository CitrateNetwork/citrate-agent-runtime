---
created: 2026-10-01
branch: hup/n3-toolchain-verifiers
author: Larry Klosowski + Claude Opus 5.5
status: active
---

# Journal: HUP-S6.3, toolchain verifiers (overnight fan-out lane)

**What shipped on the branch.** The toolchain verifiers in `agent-loop` (forge JSON, SARIF
2.1.0 from slither and aderyn, medusa's summary) and four sidecar tools that run the programs
through `agent-shell` and hand back an envelope the verifiers re-judge. Off by default
(`CITRATE_HERMES_TOOLCHAIN=1`). Details in `agent-loop/TOOLCHAIN.md`.

**What I learned.**

- slither's SARIF puts every result at `level: warning`. Severity lives in the rule's
  `security-severity` property and in the rule-id prefix. A parser that trusted `level` would
  have scored a reentrancy as medium and let the D-4 gate pass. The real fixture caught this
  before any code was written.
- aderyn does the opposite: no rules, no `security-severity`, highs as `warning`, lows as
  `note`. One generic mapping cannot serve both, so the parser takes a per-tool profile and
  fails closed on a driver it does not expect.
- forge under a scratch `HOME` cannot see the member's svm compilers and tries to download one.
  `FOUNDRY_OFFLINE=true` plus `FOUNDRY_SOLC` keeps runs offline and on the chain's pinned 0.8.36.
- medusa prints test results after each failing test's call sequence, and a call sequence can
  contain any string a contract emits. The last `Test summary:` line is the only one the fuzzer
  writes after all of that, so it is authoritative, and a listed `[FAILED]` it does not account
  for still fails the run.
- Trust: the model gets counts and identifiers, not tool prose. That keeps the tools trusted, so
  running the tests does not taint the session and block the next run.

**Left open.** No OS sandbox; a stop does not interrupt a running tool (the timeout bounds it);
granted folders come from an env var until S2.1 grants reach the sidecar; aderyn and medusa
fixtures are constructed from their source, not captured, until S6.1 bundles the tools.
