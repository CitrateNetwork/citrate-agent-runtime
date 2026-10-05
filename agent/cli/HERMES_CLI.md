---
created: 2026-10-04
branch: hup/n6-session-reattach
author: Larry Klosowski + Claude Opus 5.5
status: current
---

# `citrate-agent hermes`: the terminal client for the Hermes sidecar

HUP-S1.8. The binary is **`citrate-agent`** and the command group is **`hermes`**, so every
command below starts with `citrate-agent hermes`. The planset's US-1.1 text says `citrate hermes`;
there is no separate `citrate` binary, and this document is the record of the shipped name.

The CLI talks to the agent sidecar the desktop app started, on its loopback control address
(default `127.0.0.1:19700`, `--addr` or `CITRATE_HERMES_ADDR`), with the bearer the app wrote to
its data directory (`--token-file` or `CITRATE_HERMES_TOKEN_FILE` to override). It refuses any
address that is not loopback.

## Commands

| Command | What it does |
|---|---|
| `status` | The sidecar's running state, skills and pending approvals. |
| `sessions` | The open sessions, the app's included: id, model, busy or idle, last sequence number, persona, and how many app tool calls it is waiting on. |
| `events --session <id> [--after N] [--follow]` | Print a session's events. Streamed assistant text is printed as it arrives; the final answer is never printed twice. |
| `send --session <id> "<text>"` | Start one turn in a session. |
| `stop --session <id>` | Stop a session's current turn. |
| `run <workflow> (--session <id> \| --model <m>) [--follow]` | Start a workflow and, with `--follow`, print its events until the sidecar has a verdict. |
| `open --model <m>` / `chat --model <m>` | A headless session of your own (sidecar capsules only). |
| `brief [--track <id>] --goal "…" [--defaults] [--json]` | The track interview the app runs. |

### `run`

`<workflow>` is either a catalog workflow id (the sidecar's `GET /workflows`), started with
`POST /sessions/:id/track_workflows`, or the path of a workflow JSON file, started with
`POST /sessions/:id/workflows`. The run's state comes from `GET /sessions/:id/workflows/:run`.

- `--session <id>` runs it in an open session, for example the app's (find it with `sessions`).
  App-hosted tools in that run execute in the app, behind the app's approvals.
- `--model <m>` opens a headless session first. A headless session offers only the sidecar's
  installed capsules, so a catalog workflow that needs app tools is refused with the tools named.
- Without `--follow` it prints the run id and returns. With `--follow` the exit code is 0 only for
  a verified run.

## The same session from every client

The app (chat view), this CLI and an MCP client of the node's MCP server
(`hermes_session_list`, `hermes_session_events`, `hermes_session_send`, `hermes_session_stop`)
all read and drive the same sidecar session store. Sending or stopping over MCP asks the member
first, in the app.
