---
created: 2026-10-01
branch: hup/n4-process-split
author: Larry Klosowski + Claude Opus 5.5
status: active
---

# Journal: HUP-S1.9, the process split (fan-out 4 lane)

**What shipped on the branch.** A new crate, `agent-workers`, that supervises a child process
over a line-delimited JSON wire: startup ping, periodic health pings, a bounded restart policy,
clean shutdown, and a status report. The sidecar now runs its toolchain tools in such a child
(the same binary started with `--worker toolchain`) and reaches them through a `RemoteToolHost`.
`GET /workers` reports both worker kinds; the browser slot says `not_built` until HUP-S5.1.
SIGTERM to the sidecar now shuts the workers down before it exits.

**What the tests prove.** Kill the worker with `kill -9`: the call that was in flight returns a
tool error naming the signal and saying the run was not retried; the session finishes its turn;
the worker comes back with `restarts: 1`; the control plane never stopped serving. That last
part runs against the real binary, not a harness. Five mutants of the supervisor (restart bound,
crash delivery, health kill, restart count, env scrub) were each killed by the suite.

**Non-obvious.** Two traps worth remembering. libtest prints `test name ... ` with no newline
before a re-executed test body runs, so the first protocol line was glued to it; the child now
ends that line first. And the shell runner scrubs `PATH`, so a stand-in script that calls
`sleep` silently does nothing; test scripts use absolute paths.

**Where the loop lives.** The loop process is the sidecar itself, which citrate-core already
supervises with backoff and `/health`. Splitting the loop out of the sidecar again would have
added a hop without a new isolation boundary, so the split is loop (sidecar) versus tools
(workers). `harness.ts` stays: retiring it waits on the owner's turn-cap call (6 vs 8).

**Not done.** Grandchildren of a killed worker (a forge run) are not reaped by the supervisor;
they end at their own timeout. No OS sandbox (separate work item).
