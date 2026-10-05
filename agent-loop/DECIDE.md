---
created: 2026-10-01
branch: hup/n4-search-decide (updated on hup/n6-web-browse, 2026-10-04)
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
   attach mode. A web origin must state `has_session_cookie` and `attach_mode` explicitly; a
   request that leaves either out is rejected, never read as "no cookie, not attached";
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

Reproduce with the command in `agent-sidecar/tests/decide_live.rs`.

## In the browser: multi-step tasks (web-subset-v2)

The managed browser now asks `decide()` for every move (`agent-browser/src/pick.rs`). Each step,
the live snapshot becomes a fixed set of moves, `click:eN`, `type:eN` (editable fields only),
`enter:eN` (an editable field holding a value), plus `done` and `blocked`; for `type`, a second
decision picks which of the task's values goes in (select, never generate). A control whose last
two clicks changed nothing is no longer offered. Sessions get the same picker as the
`browser_pick` tool, on the session's own model endpoint through the sidecar's metered slot
(`SessionPicker`), so each decision lands in `/decide/stats`.

[`evals/web-subset-v2.json`](evals/web-subset-v2.json) holds ten multi-step tasks over local
fixture sites served from 127.0.0.1 (search then open a result, shoe size then cart, sign in,
reject cookies then read an article, pagination, filters then apply, a three-field contact form,
a hidden settings tab, docs navigation, a version's changelog), with distractors on every page.
A task succeeds only when the picker says `done` and the page meets the end-state check at that
moment. A scripted picker finishes all ten with the offered moves on live Chrome
(`agent-browser/tests/web_subset_tests.rs`), which proves each task is solvable and each check is
right.

Live runs, 2026-10-04: `agent-sidecar/tests/browse_live.rs`, Chrome for Testing 154.0.8037.92 as
the managed browser, the bundled llama-server (build 10909) serving `gemma-4-E4B-it-Q4_0.gguf`
(T0) on an Apple-silicon laptop under heavy load; each task outcome recorded through
`POST /decide/outcomes` and read back from `/decide/stats`. Full records, including every live
snapshot the model saw: [`evals/runs/`](evals/runs/).

| Run | Backend | Tasks | Succeeded | Decisions | Errors | p50 / p95 per decision | Mean confidence |
|---|---|---|---|---|---|---|---|
| 1 | local (Gemma 4 E4B, T0) | 10 | 8 (80%) | 34 | 0 | 2361 / 8405 ms | 0.964 |
| 2 | local (Gemma 4 E4B, T0) | 10 | 9 (90%) | 38 | 0 | 487 / 756 ms | 0.962 |
| | jev | not run | | | | | |
| | local (T1) | not run | | | | | |

Run 1 lost one task to the machine, not the model: Chrome did not answer the DevTools handshake
within the fixed 10 s (now it waits as long as a command may, at least 10 s). In both runs the
model failed `filter-stock-price` the same way: it ticked both boxes and said `done` before
pressing "Apply filters". Run 1's latencies include a machine at load average 20 to 30 with swap
nearly full.

Not run: Jev, which stays unscored until the owner decides on the vendor and its terms and a key
exists; and the T1 model, whose llama-server on this machine was serving another lane's
evaluation at the time.

## Pending owner sign-off

These are conservative placeholders, built so the defaults change nothing for members:

- `read_url` caps (2 MiB body, 15 s, 5 redirects, 20k characters shown, 60k at most) and the
  SearXNG limits (30 s start, 12 s query, 3 failed starts, `safe_search: 1`).
- Jina and TypeSafe keys are member-chosen files passed by path; custody-vault storage is not built.
- The Jev endpoint and model (`https://api.typesafe.ai/v1/systemone`, `jev-latest`) come from the
  `system1-agents` adapter; the vendor and its terms need confirming before any member opts in.
- Retention and rotation of the decision metering log (`CITRATE_HERMES_DECIDE_LOG`).

## Not done here

- The metering report is served by the sidecar; the activity monitor in citrate-core does not
  render it yet.
- The Jev adapter has only been tested against a loopback stand-in; Jev is unscored (owner
  vendor and terms decision, A43).
- A T1 score on web-subset-v2.
