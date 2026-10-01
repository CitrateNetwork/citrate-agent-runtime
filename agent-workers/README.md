---
created: 2026-10-01
branch: hup/n4-process-split
author: Larry Klosowski + Claude Opus 5.5
status: active
wp: HUP-S1.9
---

# citrate-agent-workers

The supervisor that runs Hermes's tool workers as separate child processes of the agent sidecar.

```text
citrate-core ── supervises ──> sidecar (agent loop; restarted by core's own supervisor)
                                 ├── toolchain worker  (`citrate-agent-sidecar --worker toolchain`)
                                 └── browser worker    (reserved for HUP-S5.1; not built, reported as `not_built`)
```

- **Wire.** One JSON object per line over the child's stdin/stdout: `ping`, `call`, `shutdown`.
  Calls carry ids and run concurrently in the worker; `ping` is answered by the reading thread
  even while calls run. The child's stderr is inherited as the operator log.
- **Restart policy.** On an unplanned exit (or a kill after `health_failures_to_kill` missed
  pings), every call in flight fails with `Crashed("<how it ended>")`, the supervisor backs off
  (doubling from `backoff_base` to `backoff_max`) and starts a new child. More than
  `max_restarts` inside `window` and the worker is `failed` until the sidecar restarts.
  Defaults: 5 restarts per 60 s, 250 ms to 10 s backoff, ping every 5 s with a 2 s timeout,
  10 s to answer the first ping, 3 s shutdown grace. These values are conservative placeholders,
  pending owner sign-off.
- **Clean shutdown.** `shutdown` request, stdin closed, grace period, then kill. A worker also
  exits when its stdin closes, so it does not outlive a sidecar that died abruptly.
- **Status.** `Worker::status()` (state, healthy, pid, restarts, last exit, last error), served
  by the sidecar on `GET /workers` (bearer) with one entry per worker kind.
- **Honest scope.** Process isolation only, not a sandbox: a worker runs as the sidecar's user.
  Programs a worker started itself (a forge run) live in their own process group and can outlive
  a killed worker until their own wall-clock timeout. Nothing here holds a key or signs.

Tests: `cargo test -p citrate-agent-workers` (re-executes the test binary as the child) and
`cargo test -p agent-sidecar --test process_split_tests` (the real sidecar binary end to end).
