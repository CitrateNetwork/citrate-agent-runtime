---
created: 2026-10-01
branch: hup/n4-search-decide
author: Larry Klosowski + Claude Opus 5.5
status: active
---

# The decide() System-1 slot (HUP-S5.3, D-14)

Code: [`src/decide.rs`](src/decide.rs) (types, validation, the local grammar backend, the Jev
adapter, the `Decider` policy, the snapshot-ref parser and the suite runner),
`agent-sidecar/src/decide.rs` (HTTP transport, env settings, metering) and
`agent-metering/src/decisions.rs` (per-backend report). Tests:
[`tests/decide_tests.rs`](tests/decide_tests.rs), `agent-sidecar/src/decide_route_tests.rs`,
`agent-metering/tests/decision_tests.rs`, and the live run in `agent-sidecar/tests/decide_live.rs`.
Formal model: [`formal/DecideEgress.tla`](formal/DecideEgress.tla).

## What it is

`decide(options[], context) -> {choice, probs}`: one choice from a fixed option set, for routing,
ranking and picking the next browser element over snapshot refs. The answer is always an offered
option id or an error; a backend answer outside the set is an error, never a guess. Verifier
verdicts are not a purpose: they come from deterministic parsers only.

## Backends

| Backend | Default | How it answers | Egress |
|---|---|---|---|
| `local` | yes | llama-server chat completions with a GBNF grammar that only admits the option keys (`A`..`Z`, or `1`..`n` past 26), `temperature 0`, thinking off, first-token `top_logprobs` for the distribution | none |
| `jev` | off | TypeSafe System One decisions wire: one `choice` question whose criteria are the option ids and labels; the answer is validated (offered id, distribution sums to one within 0.02 and peaks at the choice, confidence in [0, 1]) | every call; the decision carries `egress {destination, bytes_sent}` |

The Jev wire shape follows the Apache-2.0 `ThinkFlowLab/system1-agents` adapter. It has not been
exercised against the live service from here (no key is held), so the first opted-in use is the
real check.

## When Jev may answer

`Decider` routes to Jev only when all of these hold (red-team correction 5):

1. the member turned Jev on and a key file is configured;
2. for a web decision: the origin (taken by the caller from the top-level frame) normalizes to an
   exact entry on the member's Jev allowlist, it has no session cookie, and the browser is not in
   attach mode;
3. for a decision with no web origin: the separate non-web opt-in is on.

`backend: "auto"` uses Jev when it is permitted and local otherwise. `backend: "jev"` is Jev or a
refusal, never a quiet local answer. `backend: "local"` never reaches Jev. These are the TLA+
invariants in `formal/DecideEgress.tla`.

## Sidecar surface

- `POST /decide` `{llm: {baseUrl, bearer}, model, request, backend}` returns the decision. The
  local endpoint is validated like a session's (loopback http or https).
- `GET /decide/stats` returns the per-backend report: decisions, errors by kind, p50/p95 latency,
  mean confidence, bytes sent off-machine, tasks attempted and the task success rate.
- `POST /decide/outcomes` `{backend, suite, taskId, success}` records one task result. Suite and
  task ids are slugs; metering records never hold option labels, questions or context.

Env: `CITRATE_HERMES_JEV`, `CITRATE_HERMES_JEV_KEY_FILE`, `CITRATE_HERMES_JEV_ORIGINS`,
`CITRATE_HERMES_JEV_NON_WEB`, `CITRATE_HERMES_JEV_ENDPOINT` (https only), `CITRATE_HERMES_JEV_MODEL`,
`CITRATE_HERMES_DECIDE_LOG`. With none set, Jev is unreachable.

## The web subset and the first score

[`evals/web-subset-v1.json`](evals/web-subset-v1.json) holds 12 single-step, WebVoyager-style tasks
(search box, add to cart, star a repo, date field, random article, reject cookies, next page,
version picker, directions, filter, log in, captions), each a goal plus a ref-indexed snapshot and
the refs that count as correct. It measures one step of element picking; it is not the WebVoyager
benchmark, and it is easy on purpose (a smoke-level floor, not a ceiling).

Live run, 2026-10-01, local backend, the bundled llama-server (build 10909) serving
`gemma-4-E4B-it-Q4_0.gguf` (T0) on an Apple-silicon laptop:

| Backend | Tasks | Correct | Errors | Latency per decision | Mean confidence |
|---|---|---|---|---|---|
| local (Gemma 4 E4B, T0) | 12 | 12 (100%) | 0 | 270 to 537 ms | 0.999 |
| jev | not run (no key; opt-in) | | | | |

Reproduce with the command in `agent-sidecar/tests/decide_live.rs`. The next step is a harder
subset with distractors and multi-step tasks once the managed browser (HUP-S5.1) produces real
snapshots.

## Not done here

- The managed browser does not call `decide()` yet (HUP-S5.1 owns the browser loop).
- The metering report is served by the sidecar; the activity monitor in citrate-core does not
  render it yet.
- The Jev adapter has only been tested against a loopback stand-in.
