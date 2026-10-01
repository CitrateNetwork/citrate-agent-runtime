---
created: 2026-10-01
branch: hup/n3-metering-trajectories
author: Larry Klosowski + Claude Opus 5.5
status: implemented (library only; not yet wired into sidecar sessions)
---

# citrate-agent-metering

Hermes measures itself: the runtime half of HUP-S7.5 (planset `2026-09-30-hermes-upskill`,
decision D-27, story US-7.3).

## What it does

| Piece | What it is |
|---|---|
| `MeteringSink` | An `EventSink` adapter for the agent loop. Wraps the session's sink, forwards every event unchanged, and keeps one `TurnRecord` per loop turn. |
| `TurnRecord` | Model, tokens in/out (only when the model client reports them, otherwise `null`), latency, steps, tool calls by name (ok / declined / error / needed explicit approval), verifier outcomes, the loop's outcome, and whether the turn tainted the session. |
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

## Not done here

- Wiring into sidecar sessions (`/sessions`): no session creates a `MeteringSink` yet.
- Usage reporting from the model client (`record_usage` exists; nothing calls it yet).
- The core half of S7.5: activity monitor, journal surface, opt-in UI, ceremony submission.
- D-27 measures not derivable from the event stream: TTFT, tokens/sec, SALT spend, gas, CPU / GPU /
  RAM peak, the energy estimate and the model's labelled self-review.
