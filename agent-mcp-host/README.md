---
created: 2026-10-01
branch: hup/n3-mcp-host (S4.4 additions on hup/n4-user-mcp, 2026-10-01; 2026-07-28 revision, Tasks, URL elicitation, reconnect, list_changed and approval cards on hup/n6-mcp-host, 2026-10-04)
author: Larry Klosowski + Claude Opus 5.5
status: implemented and wired into sidecar sessions behind CITRATE_HERMES_MCP (default off); dual-era (2026-07-28 stateless plus the handshake versions); S4.4 user-entry validation + dry-run probe implemented
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
task_timeout_ms = 600000               # longest a call that became a task is polled (default 10 min)
```

Unknown keys are refused (a typo never silently changes behaviour). An invalid file
disables MCP and is logged to stderr; the sidecar still starts. A server that fails to
start is listed as `failed` and offers no tools; the others are unaffected.

`GET /mcp/servers` (bearer-gated) returns `{configured, servers}` with each server's
state (`ready`, `failed`, `exited`), protocol version and era (`modern` or `legacy`),
recorded capabilities, whether it offers the Tasks extension, offered tool count, skipped
tools with reasons, reconnect and re-list counters, the time to the next reconnect attempt,
and message counters. It never returns the URL, the environment, or the server's
`instructions` text.

## What the host does

| Area | Behaviour |
|---|---|
| stdio | Child process from an absolute path with `env_clear()`, then only the base allowlist (`PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`, `TMPDIR`, and the Windows process basics) plus the server's explicit `env`. Nothing else from the sidecar's environment reaches it. stderr is discarded so a chatty server can never block. Requests are written by a dedicated writer thread; responses are read by a bounded line reader. The child is killed when the host is dropped. |
| HTTP | Streamable HTTP: one POST per message, `Accept: application/json, text/event-stream`, JSON or SSE answers (SSE parsed incrementally until the matching response). `Mcp-Session-Id` from `initialize` and `MCP-Protocol-Version` are sent on later requests. Redirects are refused; loopback requests bypass proxies. The blocking HTTP client always runs on its own thread, never on an async runtime thread. |
| Lifecycle (dual-era) | The host first sends `server/discover` with the 2026-07-28 `_meta` (protocol version, client info, client capabilities). A `DiscoverResult` listing `2026-07-28` makes the server **modern**: every later request carries that `_meta`, nothing is negotiated, and no session is kept. A recognized modern error (`-32020..-32099`, or `UnsupportedProtocolVersion` `-32022`) is reported and never falls back. Anything else (stdio: another error or no answer within 3 s; HTTP: a 4xx without a modern error body) makes it **legacy**: `initialize` asks for `2025-06-18` and accepts `2025-11-25`, `2025-06-18`, `2025-03-26` or `2024-11-05`, then `notifications/initialized`. `init_timeout_ms` bounds the whole connect (probe plus handshake). Servers are connected in parallel at start, so a server that never answers delays startup by its own init deadline once. |
| Modern requests | Results are read by `resultType`: absent or `complete` is a result; `input_required` is a multi round-trip request (at most 3 retries, each echoing `requestState` and carrying `inputResponses`); `task` is the Tasks extension (below); any other value is refused. HTTP POSTs carry `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` (tool name, or `taskId` for `tasks/*`), with the `=?base64?...?=` encoding when a value is not plain visible ASCII, and `Mcp-Param-<name>` for every `x-mcp-header` argument. A tool whose `x-mcp-header` annotations break the rules (not a string/integer/boolean, not reachable through `properties` alone, an invalid or duplicate name) is withheld and listed as skipped. A server whose capabilities say `tools.listChanged` gets one `subscriptions/listen` for `toolsListChanged` (stdio: on the shared channel; HTTP: a long-lived POST re-issued with backoff when the server ends it). |
| Tasks extension | `io.modelcontextprotocol/tasks` is declared on every modern request. A `CreateTaskResult` is polled with `tasks/get` at the server's `pollIntervalMs`, clamped to 100 ms..10 s, until it completes (its `result` is rendered like any tool result), fails (its JSON-RPC error), or is cancelled. A stop or `task_timeout_ms` sends `tasks/cancel` and ends the call. `input_required` entries are answered once each (keys are de-duplicated across polls) through `tasks/update`. |
| URL-mode elicitation | Declared (`elicitation: {url: {}}`) only on a request where a person can be asked, which in the sidecar means a session whose client confirmed it routes `hic: "required"` to the member. The request is checked first (http/https only, no credentials in the address, at most 2048 characters, no control characters), its host is extracted, and warnings are added for plain http, punycode and raw IP addresses. It then goes to the member as an approval card; the host never fetches or opens the URL. Accept, decline or cancel is sent back on the retry (or `tasks/update`). Form mode, sampling and roots are never declared; a server that asks for them anyway ends the call with an error. |
| Tools | `tools/list` only when the server declared `tools`; paginated (at most 32 pages, 256 tools). Each tool becomes an agent-loop `ToolSpec` with host `sidecar` and name `mcp__<server>__<tool>` (other characters mapped to `_`, at most 64 chars), so MCP tools cannot collide with core or sidecar tools. While MCP is configured the `mcp__` prefix is reserved: a session that offers its own tool in that namespace is refused. Descriptions are labelled, stripped of control characters and capped at 1024 chars; input schemas must be objects of at most 16 KiB. |
| Annotations | Hints, mapped with the spec defaults: `readOnlyHint: true` gives effect `none`; anything else gives effect `write` (`destructiveHint` defaults true, `openWorldHint` defaults true, `idempotentHint` defaults false). Trust is always `untrusted`, whatever the server says. |
| Calls | `tools/call` with the per-server deadline, the response cap, and cancellation: on timeout or when the session's stop flag rises (session stop or e-stop), the server is sent `notifications/cancelled` and the call ends at once. Arguments must be a JSON object. Text content is passed through; images and audio are described, never inlined; resource links are listed; embedded text resources are included; with no content blocks, `structuredContent` is shown as JSON. Output is fenced as untrusted data and truncated to `max_output_chars`. |
| Robustness | A non-JSON line is skipped and counted. An oversized line is attributed to its request when the id can be read (else every pending request fails) and the connection survives. A server that exits fails its pending calls at once and is marked `exited`. Legacy server-to-client requests get JSON-RPC `-32601` (no legacy client capabilities are advertised), except `ping`. Cancellation: `notifications/cancelled` on stdio and legacy HTTP; on modern HTTP the request's stream is closed instead (checked between SSE lines; a plain JSON answer in flight ends at the per-call deadline). |
| Reconnect | A server that failed to start, whose process exited, or whose HTTP endpoint ended the legacy session or refused connections is reconnected by the maintenance pass with exponential backoff (1 s doubling to 60 s), then re-listed. The sidecar runs the pass every 2 s on a background thread. A call to a server that is down is answered at once ("reconnecting"), never blocked. |
| Tool-list changes | `notifications/tools/list_changed` (legacy: unsolicited; modern: on the listen stream) makes the next maintenance pass re-list that server and apply the write-tool policy again. New or changed tools reach new sessions only. |

## Safety properties

- **Keyless (Rule 3).** Nothing here holds a key or signs.
- **Taint.** Every MCP result is `ToolOutcome::Untrusted` and every MCP spec is
  `trust: untrusted`, so the first MCP result taints the session (HUP-S2.7). After
  that, the loop gives effectful tools to a host only if it can put the call in front
  of a person. With an `McpApprover` (the sidecar's per-session approval cards, present
  only for an HIC-aware client) the exact call goes to the member: server, tool, the
  canonical arguments that will be sent (at most 8 KiB, else declined as too large to
  review), the server's hints and the reason. It runs only on an explicit allow, with
  those arguments. Without an approver, effectful MCP calls after taint are declined, as
  before. Untainted calls and read-only calls are unchanged.
- **Write tools off by default.** A server offers only read-only-annotated tools
  unless its entry sets `allow_write_tools = true`.
- **A running session's tools never widen.** A session keeps the specs it was offered.
  A call to a tool whose spec has since changed or been withdrawn is refused, so a
  server cannot add tools to a running session or make an offered tool more effectful.

## User-added servers (HUP-S4.4)

citrate-core's Settings > MCP servers lets a person add their own servers. Two pieces
live here:

- **`user::validate_user_entry`** checks one entry (the `[[servers]]` shape, as JSON)
  with stricter rules than the allowlist file, and reports every problem against its
  field (`name`, `transport`, `command`, `args`, `cwd`, `url`, `env.<KEY>`, `entry`):
  names of built-in servers are reserved (`RESERVED_SERVER_NAMES`); env names are plain
  identifiers; env names that change which code a process loads (`LD_*`, `DYLD_*`,
  `NODE_OPTIONS`, `PYTHONPATH`, `BASH_ENV`, ...) are refused; env values are explicit, so
  a value that refers to another variable (`$X`, `${X}`, `%X%`) is refused (nothing is
  expanded, and nothing beyond the process basics in `BASE_ENV_ALLOWLIST` is inherited).
  What passes is then read by the allowlist parser itself, so it is exactly what the
  sidecar loads. Messages never contain an env value.
- **`probe::probe`** (and the sidecar route `POST /mcp/probe`, bearer-gated) starts or
  reaches the server, runs `initialize` and `tools/list`, and stops it. Nothing is
  registered with sessions. The report lists every tool with the server's raw hints
  (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`, `title`), the
  effective annotations after the spec defaults, `trust: "untrusted"`, and whether a
  session would be offered it (with the reason when not). It never carries the URL, the
  environment, or the server's `instructions` text. The answer is bounded by
  `PROBE_TIMEOUT` (20 s): past it the caller gets a failed report, while the probe's own
  worker keeps going until the server stops answering within the per-request cap (also
  20 s) or the listing ends, and only then stops the server. The sidecar runs one probe at a time (429 otherwise) and answers
  422 `{errors: [{field, message}]}` for an invalid entry. The reserved names and the
  loader env denylist are placeholders pending owner sign-off.

The sidecar still reads only the allowlist file named by `CITRATE_HERMES_MCP` at start;
core writes that file with the enabled, reviewed entries.

## Specification (revision 2026-07-28)

Implemented against the published text, read from the specification repository
(`modelcontextprotocol/modelcontextprotocol` at `3098fe9`, 2026-10-01) and the Tasks
extension repository (`modelcontextprotocol/ext-tasks` at `5246bc3`, 2026-09-30):

- Key changes: <https://modelcontextprotocol.io/specification/2026-07-28/changelog>
- Versioning and era detection: <https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning>
- `_meta`, `resultType`, error codes: <https://modelcontextprotocol.io/specification/2026-07-28/basic>
- `server/discover`: <https://modelcontextprotocol.io/specification/2026-07-28/server/discover>
- stdio (backward-compatibility probe): <https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio>
- Streamable HTTP (standard headers, `x-mcp-header`, cancellation): <https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http>
- Multi round-trip requests: <https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr>
- `subscriptions/listen`: <https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions>
- Elicitation (URL mode, safe URL handling): <https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation>
- Tasks extension: <https://modelcontextprotocol.io/extensions/tasks/overview> and
  <https://github.com/modelcontextprotocol/ext-tasks/blob/main/specification/2026-07-28/tasks.md>

No official MCP conformance suite was run (none is published for this revision that
this repo vendors); conformance is shown by the fixture tests below, which play both a
modern-only and a dual-era server.

## Not implemented (honest scope)

- Resources, prompts, completions, form-mode elicitation, sampling and roots (never
  declared in client capabilities), `notifications/tasks` (polling is used), and
  persisting task ids across a sidecar restart.
- OAuth authorization for remote servers (no `Authorization` header is ever sent).
- Response caching by `ttlMs`/`cacheScope` (lists are re-read only on `list_changed`).
- Closing a modern HTTP request whose answer is a single JSON body while it is still in
  flight: it ends at the per-call deadline (SSE answers are closed at once).

## Servers citrate-core configures (HUP-S4.3)

citrate-core writes this file (`hermes/mcp.json`, JSON) from the member's settings and sets
`CITRATE_HERMES_MCP` only while it exists; both entries default off. `mem` is a stdio entry
naming the citrate-core executable with `--citrate-mem-mcp-stdio <socket>`, a read-only bridge
to the local mem-mcp daemon that lists only its read tools, annotated `readOnlyHint: true`.
`scan` is CitrateScan's HTTP endpoint, whose tools carry the same annotation. A server whose
tools are not annotated read-only offers nothing here unless `allow_write_tools` is set, which
core never sets.

## Tests

HUP-S4.1 completion (2026-10-04, `hup/n6-mcp-host`): 4 client unit tests (`x-mcp-header`
rules and value encoding, URL-elicitation checks, `resultType` handling) and 1 host unit
test (backoff); 17 tests against the stdio fixture in its modern and dual modes
(`tests/modern.rs`: discover and `_meta`, dual-era preference, legacy fallback, a modern
server without our version refused without fallback, task polling, cancel on stop and on
the task deadline, URL elicitation inside a task asked once, a task needing input with no
one to ask, MRTR URL elicitation accept and decline, form refused, legacy and modern
tool-list changes re-listed with the policy applied again, a changed tool refused to an
old session, reconnect after exit in both eras, exponential backoff, background
maintenance); 7 more HTTP tests (standard and `Mcp-Param-*` headers checked by the server,
an invalid `x-mcp-header` tool withheld, tasks routed by `taskId`, `-32022` reported not
retried as legacy, list changes over the listen stream, an ended legacy session
reconnected, modern cancellation without a notification). `agent-sidecar` adds 3
`mcp_approvals` unit tests and 7 session tests (a card after taint that runs exactly what
was shown, decline, untainted and read-only calls never carded, route auth, the decision
recorded for the anchor, a URL elicitation put to the member, no URL elicitation without
an HIC-aware client). Mutation checks (each made a test fail, then was reverted):
declaring URL elicitation on every request, skipping the offered-spec check, ignoring
`list_changed`, not sending `tasks/cancel` on stop, an MCP host that never honors
approvals, and not sending `Mcp-Param-*` headers.

`cargo test -p citrate-agent-mcp-host`: 17 unit tests (config validation, env
filtering, naming, annotation mapping, rendering, the bounded line reader), 22 tests
against a real stdio MCP server (`fixtures/stdio_server.rs`, built as the
`citrate-mcp-fixture-server` test binary), and 9 against a real axum streamable-HTTP
server. `agent-sidecar` adds 7 session tests over a real HTTP MCP server (offered
tools, untrusted result and taint, namespace reservation, decline after taint, stop
cancels an in-flight call, the status route, config loading).

HUP-S4.4 adds 4 unit tests (`user.rs`), 10 user-entry tests (`tests/user_entry.rs`),
5 probe tests against the real stdio fixture and a stalled loopback endpoint
(`tests/probe.rs`), and 5 sidecar route tests (`mcp_probe_tests.rs`: bearer, field
errors, a probe that registers nothing, an unreachable server, the single probe slot).
Mutation checks for S4.4 (each made a test fail, then was reverted): accepting env
references, accepting loader env names, accepting reserved names, ignoring
`allow_write_tools` in the shared offer decision, and reporting a tool as trusted.
Two survivors, kept as defence in depth: dropping the probe's outer `recv_timeout`
(the per-request deadline is also capped at the probe deadline, so the stall test
still passes) and dropping the redaction of a base-rule message (no input reaches
that path with an env value after the user rules pass; the function has its own
unit test).

Mutation checks (each mutant made a test fail, then was reverted): removing
`env_clear()`, marking MCP output trusted, ignoring `allow_write_tools`, skipping the
cancel notification on timeout, accepting any protocol version, and disabling the
line-size cap.
