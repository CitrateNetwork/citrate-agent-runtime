---
created: 2026-10-01
branch: hup/n3-toolchain-verifiers
author: Larry Klosowski + Claude Opus 5.5
status: active
---

# Toolchain tools and their verifiers (HUP-S6.3)

Code: [`src/verifiers_tooling.rs`](src/verifiers_tooling.rs) (parsers, verdicts, envelope,
workflow verifiers) and `agent-sidecar/src/toolchain.rs` (the four sidecar-hosted tools).
Tests: [`tests/toolchain_verifier_tests.rs`](tests/toolchain_verifier_tests.rs) and
`agent-sidecar/src/toolchain_tests.rs`. Planset: citrate-core
`.agentile/planset/2026-09-30-hermes-upskill/05_SPRINTS_AND_WPS.md`, row S6.3, and decision D-4
(the deploy gate) in `00_OVERVIEW.md`.

## What it does

"Only verifiers say done." A dApp-forge step is judged by the toolchain's own reports, never by
the model saying the tests pass.

| Tool | Program and fixed argv | Verdict passes when |
|---|---|---|
| `forge_test` | `forge test --json [--match-test T] [--match-contract C]` | at least one test ran and none failed |
| `slither_scan` | `slither . --sarif - --exclude-dependencies --disable-color` | no finding at or above `fail_on` (default high) |
| `aderyn_scan` | `aderyn . --output aderyn-report.sarif --stdout --skip-update-check` | no finding at or above `fail_on` (default high) |
| `medusa_fuzz` | `medusa fuzz --no-color --test-limit N --timeout S` | the run printed its summary, at least one test ran, none failed |

The model supplies only the project folder and a few validated options (`match_test` and
`match_contract` are `[A-Za-z0-9_]{1,64}`, `fail_on` is a severity, `test_limit` is 1 to
1,000,000 calls with a default of 50,000, `timeout_secs` is 1 to 900). It never supplies argv,
environment, or a program name.

Each tool result is a `ToolchainEnvelope` (`schema: citrate.toolchain/v1`): a status
(`completed`, `not_installed`, `timed_out`, `refused`, `failed`), a one-line summary, the
verdict with its evidence counts, run facts (exit code, duration, output sizes), and, for a build
that produced no report, sanitized compiler error headers. The workflow verifiers
`ForgeTestsPass`, `SarifBelowThreshold` and `MedusaNoFailures` read the latest envelope of their
tool in the step and judge its evidence counts again with their own threshold. A missing,
declined, refused, timed-out, truncated, or unparseable run is a failure with a reason, never a
pass.

## Turning it on

| Variable | Meaning |
|---|---|
| `CITRATE_HERMES_TOOLCHAIN` | `1` registers the four tools in every session. Anything else, or unset, leaves them off (the default). |
| `CITRATE_HERMES_TOOLCHAIN_ROOTS` | Granted project folders, a path list. Unset means every toolchain run is refused. |
| `CITRATE_HERMES_TOOLCHAIN_PATH` | Search path override. Default: `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin`, `/bin`, then `~/.foundry/bin`, `~/.local/bin`, `~/.cargo/bin`, `~/go/bin`. |
| `CITRATE_HERMES_SOLC` | Absolute path of the solc forge should use. Default: the pinned 0.8.36 in the per-user svm directory, when present. |

While the toolchain is on, a session may not declare its own tool with one of the four names.

## Safety properties (and what is not covered yet)

- Programs run through `citrate-agent-shell`: allowlisted bare names resolved from the fixed
  search path, argv only, a scrubbed environment with a scratch `HOME`, a process-group
  wall-clock timeout, and capped capture (4 MiB stdout, 256 KiB stderr). Output over the cap is
  not judged.
- The project must resolve, symlinks followed, inside a granted folder and pass the agent-guard
  default-deny list (`.ssh`, keychains, wallet storage and the rest are refused even inside a
  grant).
- Every run gets `FOUNDRY_OFFLINE=true`, so forge, and the forge build slither starts, never
  downloads a compiler.
- Results reach the model as structure only: counts, sanitized test and rule identifiers, and
  `file:line` locations. Revert reasons, SARIF message text, medusa call sequences, and source
  lines in compiler output are dropped. That is why the tools are annotated `trust: trusted`.
  They are annotated `effect: write` because builds write `out/` and `cache/`, so after a session
  is tainted they need a member's decision like every other effectful tool.
- Not covered yet: there is no OS sandbox (US-2.2 AC1 is its own work item), and the programs
  execute project code by design (tests, compilation, FFI when a project enables it). A session
  stop or the e-stop does not interrupt a run in progress; the wall-clock timeout bounds it. The
  granted folders come from an environment variable until the S2.1 folder grants reach the
  sidecar.
- Rule 3: nothing here holds a key or signs.

## Severity in SARIF

1. A `security-severity` property on the result, then on its rule, bucketed as code-scanning
   tools do: 9.0 and up critical, 7.0 up high, 4.0 up medium, above 0 low, 0 info. slither
   writes 8.0 for high, 4.0 medium, 3.0 low, 0.0 informational.
2. slither only: the rule-id prefix `<impact>-<confidence>-<check>` (impact 0 high, 1 medium,
   2 low, 3 and 4 info).
3. The SARIF `level` (result, then the rule's default, then the spec default `warning`): aderyn
   writes high issues as `warning` and low issues as `note`, so for aderyn `warning` is high.
   For other producers `error` is high, `warning` medium, `note` low, `none` info. An unknown
   level counts as high.

Results whose `kind` is `pass` or `notApplicable` are not findings. Suppressed results still
count. A log that is not 2.1.0, has no runs, has a run without `results`, reports
`executionSuccessful: false`, or comes from a different driver than the profile expects fails
closed.

## Fixtures

In `tests/fixtures/toolchain/`:

| File | Source |
|---|---|
| `forge-test-pass.json`, `forge-test-fail.json` | Real `forge test --json` runs (forge 1.5.1, solc 0.8.36) on a three-file Foundry project in a temp dir; the failing one adds a test whose `require` fails. |
| `slither-info-only.sarif`, `slither-medium.sarif`, `slither-high.sarif` | Real `slither . --sarif` runs (slither 0.11.6) on the same project: a counter only (informational), a contract with divide-before-multiply and a missing zero check (medium, low), and a vault with a reentrancy and an unprotected selfdestruct (high). |
| `aderyn-shape.sarif`, `aderyn-lows-only.sarif` | Constructed. aderyn is not installed on the build machine, so these follow the shape of aderyn's SARIF printer (`aderyn_driver/src/interface/sarif.rs`, Cyfrin/aderyn at de6a090): highs as `warning`, lows as `note`, no rules array. |
| `medusa-pass.txt`, `medusa-fail-ansi.txt`, `medusa-cut-off.txt`, `medusa-no-tests.txt` | Constructed. medusa is not installed, so these follow the log lines in medusa's source (`fuzzing/fuzzer.go` `printExitingResults` and the metrics loop, crytic/medusa at 87f65e2). The failing one keeps the colour codes and includes a call-sequence line that tries to spoof a `[PASSED]` result. |

When aderyn and medusa are bundled (S6.1), replace the constructed fixtures with captured runs.

The sidecar's deterministic tests put small `/bin/sh` stand-ins for the programs on a private
search path, so the whole host path runs in CI without the toolchain. Two `live_*` tests run the
real forge and slither and are ignored by default:

```sh
cargo test -p agent-sidecar --lib live_ -- --ignored
```
