---
created: 2026-10-01
branch: hup/n3-mcp-host
author: Larry Klosowski + Claude Opus 5.5
status: implemented and wired into sidecar sessions behind CITRATE_HERMES_MCP (default off); base protocol only
---

# citrate-agent-mcp-host

Hermes's MCP host (HUP-S4.1, planset `2026-09-30-hermes-upskill`, epic E4). The sidecar
runs one MCP client per server named in an allowlist file and offers those servers'
tools to agent sessions. With `CITRATE_HERMES_MCP` unset (the default), none of this
runs and session behaviour is unchanged.

## Configure

`CITRATE_HERMES_MCP=/path/to/mcp.toml` (or a `.json` file with the same shape):

```toml
[[servers]]
name = "scan"                          # a-z 0-9 _ -, at most 24 chars, no "__"
transport = "http"
url = "https://scan.example/api/mcp"   # https, or http to a loopback host only

[[servers]]
name = "mem"
transport = "stdio"
command = "/opt/citrate/bin/mem-mcp"   # absolute path; no PATH lookup
args = ["--tenant", "personal"]
env = { MEM_TENANT = "personal" }      # explicit per-server environment
timeout_ms = 30000                     # per call (default 60000)
init_timeout_ms = 15000                # initialize + tools/list (default 15000)
max_response_bytes = 1048576           # largest single response (default 1 MiB)
max_output_chars = 16000               # longest output handed to the model
allow_write_tools = false              # default: only read-only-annotated tools are offered
```

Unknown keys are refused (a typo never silently changes behaviour). An invalid file
disables MCP and is logged to stderr; the sidecar still starts. A server that fails to
start is listed as `failed` and offers no tools; the others are unaffected.

`GET /mcp/servers` (bearer-gated) returns `{configured, servers}` with each server's
state (`ready`, `failed`, `exited`), negotiated protocol version, recorded capabilities,
offered tool count, skipped tools with reasons, and counters. It never returns the URL,
the environment, or the server's `instructions` text.

## What the host does

| Area | Behaviour |
|---|---|
| stdio | Child process from an absolute path with `env_clear()`, then only the base allowlist (`PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`, `TMPDIR`, and the Windows process basics) plus the server's explicit `env`. Nothing else from the sidecar's environment reaches it. stderr is discarded so a chatty server can never block. Requests are written by a dedicated writer thread; responses are read by a bounded line reader. The child is killed when the host is dropped. |
| HTTP | Streamable HTTP: one POST per message, `Accept: application/json, text/event-stream`, JSON or SSE answers (SSE parsed incrementally until the matching response). `Mcp-Session-Id` from `initialize` and `MCP-Protocol-Version` are sent on later requests. Redirects are refused; loopback requests bypass proxies. The blocking HTTP client always runs on its own thread, never on an async runtime thread. |
| Lifecycle | `initialize` asks for `2025-06-18` and accepts `2025-06-18`, `2025-03-26` or `2024-11-05`; any other answer is refused. Capabilities, server name and version are recorded. Then `notifications/initialized`. Servers are connected in parallel at start, so a server that never answers delays startup by its own init deadline once. |
| Tools | `tools/list` only when the server declared `tools`; paginated (at most 32 pages, 256 tools). Each tool becomes an agent-loop `ToolSpec` with host `sidecar` and name `mcp__<server>__<tool>` (other characters mapped to `_`, at most 64 chars), so MCP tools cannot collide with core or sidecar tools. While MCP is configured the `mcp__` prefix is reserved: a session that offers its own tool in that namespace is refused. Descriptions are labelled, stripped of control characters and capped at 1024 chars; input schemas must be objects of at most 16 KiB. |
| Annotations | Hints, mapped with the spec defaults: `readOnlyHint: true` gives effect `none`; anything else gives effect `write` (`destructiveHint` defaults true, `openWorldHint` defaults true, `idempotentHint` defaults false). Trust is always `untrusted`, whatever the server says. |
| Calls | `tools/call` with the per-server deadline, the response cap, and cancellation: on timeout or when the session's stop flag rises (session stop or e-stop), the server is sent `notifications/cancelled` and the call ends at once. Arguments must be a JSON object. Text content is passed through; images and audio are described, never inlined; resource links are listed; embedded text resources are included; with no content blocks, `structuredContent` is shown as JSON. Output is fenced as untrusted data and truncated to `max_output_chars`. |
| Robustness | A non-JSON line is skipped and counted. An oversized line is attributed to its request when the id can be read (else every pending request fails) and the connection survives. A server that exits fails its pending calls at once and is marked `exited`. Server-to-client requests get JSON-RPC `-32601` (no client capabilities are advertised), except `ping`. `notifications/tools/list_changed` is recorded only. |

## Safety properties

- **Keyless (Rule 3).** Nothing here holds a key or signs.
- **Taint.** Every MCP result is `ToolOutcome::Untrusted` and every MCP spec is
  `trust: untrusted`, so the first MCP result taints the session (HUP-S2.7). After
  that, the loop gives effectful tools to a host only if it can put the call in front
  of a person; the MCP host cannot, so effectful MCP calls are declined, not run.
- **Write tools off by default.** A server offers only read-only-annotated tools
  unless its entry sets `allow_write_tools = true`.
- **Frozen tool list.** Tools are listed once at sidecar start. A server cannot add
  tools to a running session.

## Not implemented (honest scope)

- The 2026-07-28 revision (stateless requests with `_meta`, `Mcp-Method`/`Mcp-Name`
  headers, `input_required` round trips). No copy of that specification text is
  available locally, so it was not implemented against guesses; a server that only
  speaks it is refused at `initialize`.
- The Tasks extension and URL-mode elicitation (same reason; no client capabilities
  are advertised, so a conforming server will not use them).
- Resources, prompts, completions, and OAuth authorization for remote servers (no
  `Authorization` header is ever sent).
- Automatic reconnect after a stdio server exits, re-initialising an expired HTTP
  session (a 404 is reported as an error), and acting on `tools/list_changed`.
- A member-facing review screen for adding servers (HUP-S4.4).

## Servers citrate-core configures (HUP-S4.3)

citrate-core writes this file (`hermes/mcp.json`, JSON) from the member's settings and sets
`CITRATE_HERMES_MCP` only while it exists; both entries default off. `mem` is a stdio entry
naming the citrate-core executable with `--citrate-mem-mcp-stdio <socket>`, a read-only bridge
to the local mem-mcp daemon that lists only its read tools, annotated `readOnlyHint: true`.
`scan` is CitrateScan's HTTP endpoint, whose tools carry the same annotation. A server whose
tools are not annotated read-only offers nothing here unless `allow_write_tools` is set, which
core never sets.

## Tests

`cargo test -p citrate-agent-mcp-host`: 17 unit tests (config validation, env
filtering, naming, annotation mapping, rendering, the bounded line reader), 22 tests
against a real stdio MCP server (`fixtures/stdio_server.rs`, built as the
`citrate-mcp-fixture-server` test binary), and 9 against a real axum streamable-HTTP
server. `agent-sidecar` adds 7 session tests over a real HTTP MCP server (offered
tools, untrusted result and taint, namespace reservation, decline after taint, stop
cancels an in-flight call, the status route, config loading).

Mutation checks (each mutant made a test fail, then was reverted): removing
`env_clear()`, marking MCP output trusted, ignoring `allow_write_tools`, skipping the
cancel notification on timeout, accepting any protocol version, and disabling the
line-size cap.
