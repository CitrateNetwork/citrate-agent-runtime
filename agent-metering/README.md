---
created: 2026-10-01
branch: hup/n7-metering-d27
author: Larry Klosowski + Claude Opus 5.5
status: implemented and wired into sidecar sessions; D-27 measures added 2026-10-04 (record schema 2)
---

# citrate-agent-metering

Hermes measures itself: the runtime half of HUP-S7.5 (planset `2026-09-30-hermes-upskill`,
decision D-27, story US-7.3).

## What it does

| Piece | What it is |
|---|---|
| `MeteringSink` | An `EventSink` adapter for the agent loop. Wraps the session's sink, forwards every event unchanged, and keeps one `TurnRecord` per loop turn. |
| `TurnRecord` | Model, tokens in/out (only when the model client reports them, otherwise `null`), latency, steps, tool calls by name (ok / declined / error / needed explicit approval), verifier outcomes, the loop's outcome, and whether the turn tainted the session. |
| D-27 measures (schema 2) | Time to first token (the turn's first model call, llama-server `timings.prompt_ms`), generation tokens and time (tokens per second, `timings.predicted_ms`), CPU / GPU / RAM peaks and means from a host `ResourceSampler`, an energy figure labelled `estimate` (mean load x nominal watts x turn time; nothing measured power), and the self-review claim (PASS / FAIL / unclear) labelled `opinion`, never its text. Every field is optional: a version 1 line still reads, and an unknown measure is left out, never zero. |
| `ChainReceipt` / `ChainSpendSummary` | SALT spent and gas. citrate-core reports each mined Hermes transaction (hash, purpose, status, gas used, effective gas price, value) after its ceremony; the day sums distinct hashes: SALT spent = gas fee + value sent by successful transactions. |
| `MeteringLog` | A local append-only JSONL file of records. A bad line is an error naming the line, never skipped. |
| `DailyReport` | One UTC day aggregated: outcomes, verified passed / failed / unverified, verified success rate, latency p50 / p95 / max, tokens, tool and verifier tallies, models. JSON and markdown. |
| `build_benchmark_payload` | Opt-in only. Turns a daily report into unsigned calldata for `BenchmarkRegistry.record(uint256,bytes32,bytes32,uint256)`. |

```rust
use citrate_agent_metering::{MeteringSink, SystemClock, DailyReport};
use std::sync::Arc;

let metering = Arc::new(
    MeteringSink::new(session_id, model, tool_names, Arc::new(SystemClock::new()))
        .forwarding_to(sse_sink),
);
// run_turn(..., metering.as_ref(), ...); the model client calls metering.record_usage(in, out)
let report = DailyReport::build("2026-10-01", &metering.records())?;
println!("{}", report.to_markdown());
```

## Rules it keeps

- **Answered is not success.** Only verifier verdicts make a turn "verified". A turn no verifier
  judged is "unverified" and is excluded from the success rate (neither a success nor a failure).
- **No conversation content.** Records never hold prompts, answers, tool arguments, tool output or
  error text. Tool names the session does not offer are pooled as `(unknown tool)`, because a
  model can invent a "tool name" out of conversation text. Verifier failure details are dropped
  (they can quote the answer). Tests plant canaries in every field and check none survive.
- **Unknown is not zero.** Tokens stay `null` unless the model client reports usage; the report
  says how many turns reported.
- **Keyless (Rule 3).** The benchmark builder returns calldata and stops. No key, no signing, no
  network. Submitting goes through citrate-core's SignatureCeremony, from the member's account.

## The BenchmarkRegistry payload

Shaped from `citrate-chain/contracts/src/cit_agent/BenchmarkRegistry.sol` (read 2026-10-01):

- `agent_id`: the member's AgentSBT id.
- `capsule_id`: `keccak256("citrate.hermes.agent-loop.v1")` (the loop is not a capsule; the slot
  names the producer).
- `metric_name`: `keccak256(name)` for each name in `METRICS` (`hermes.daily.turns`,
  `hermes.daily.verified_pass`, ..., `hermes.daily.tokens_out`).
- `value`: the integer aggregate. Rates are basis points. Metrics that are undefined for the day
  (no verified turns, no reported tokens) are left out, not sent as zero.

The selector (`0xfce25138`), the capsule id and one full calldata vector are pinned in tests
against `cast sig`, `cast keccak` and `cast calldata` (Foundry 1.5.1).

The contract records `msg.sender` and `block.timestamp` itself. Two things follow:

- The series belongs to whichever account submits it. Consumers pick whose series they trust.
- Nothing stops the same day being submitted twice. The nightly batch (HUP-S7.3) owns
  "once per day".

BenchmarkRegistry is **not in the 40204 address book yet** (D-24 deploys it in the next
redeploy). The registry address is always a caller input.

## D-27 in the benchmark payload

Eleven more per-metric calls (26 at most a day; core accepts 32): `ttft_p50_ms`, `ttft_p95_ms`,
`tokens_per_s_milli`, `cpu_peak_bps`, `gpu_peak_bps`, `ram_peak_mib`, `energy_estimate_uwh`,
`self_review_opinion_pass`, `self_review_opinion_fail`, `gas_used` and `salt_spent_wei` (all under
`hermes.daily.`). Each is omitted on a day nothing measured it. The submission shape (one card per
metric) and the energy model's nominal watts (30 W CPU, 30 W GPU) are pending owner sign-off.

## Not done here

- Live sharing needs an AgentSBT on 40204 and BenchmarkRegistry in the address book.
- Refunds a member claims back from the InferenceRouter are not subtracted from SALT spent.
