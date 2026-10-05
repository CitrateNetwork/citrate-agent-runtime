---
created: 2026-10-01
branch: hup/n4-browser (updated on hup/n6-web-browse, 2026-10-04)
author: Larry Klosowski + Claude Opus 5.5
status: implemented and wired into sidecar sessions behind CITRATE_HERMES_BROWSER (default off; core's Settings switch sets it); installing the managed Chromium waits for the signed component manifest (HUP-S5.5)
---

# citrate-agent-browser

Hermes's browser worker (HUP-S5.1 + S5.6, planset `2026-09-30-hermes-upskill`, epic E5
"Eyes on the web"). With `CITRATE_HERMES_BROWSER` unset (the default) none of this runs and
sessions are unchanged.

## What it does

- **Finds a Chromium.** The managed one at `CITRATE_BROWSER_CHROMIUM` when that file exists,
  else a Chromium-family browser already installed (Chrome, Chrome for Testing, Chromium, Edge,
  Brave). When neither exists, status and every tool say "not installed" with the places that
  were checked. Downloading and updating the managed Chromium is the signed component
  updater's job (HUP-S5.5), not this crate's.
- **Launches it headless** with a fresh profile in a private temporary folder (never the
  member's profile), DevTools on loopback only. The browser is killed and the profile removed
  when the worker stops.
- **Speaks CDP** (`src/cdp.rs`): one WebSocket, flat sessions, replies routed by id, events to
  one handler, every command bounded by a deadline, loopback addresses only.
- **Snapshots** (`src/snapshot.rs`): the accessibility tree as a short outline in which every
  interactive element has a ref (`[e3] button "Continue"`). Bounded: 150 refs, about 6000
  characters, 80 characters per name. Control characters are stripped.
- **Acts by ref**: click, or type (optionally clearing the field first and pressing Enter).
- **Screencast**: JPEG frames for the Browser pop-out, plus an outline of the element Hermes is
  about to act on (`pending`) or just acted on (`acted`).
- **Console and network** (02 §5): Chrome's own console, exception, log and request events on
  the worker's tab are kept (the latest 200 of each, `src/pagelog.rs`): level and text, or method,
  address without its query string, fragment or user info, type and status or failure. Never
  bodies, headers or cookies. Read through two read-only tools.
- **Picks the next move with `decide()`** (S5.3, `src/pick.rs`): the snapshot becomes a fixed set
  of moves (`click:e3`, `type:e5`, `enter:e5`, `done`, `blocked`) and the `decide()` slot picks
  one (the local grammar backend unless the member opted into Jev for the origin). `browser_pick`
  only suggests; Hermes then acts with `browser_act`, so approvals are unchanged. `run_task` is
  the multi-step scoring harness for `agent-loop/evals/web-subset-v2.json`.
- **Attach to my Chrome** (S5.6): Hermes opens its own tab in a Chrome the member started with
  remote debugging on, after the member consents for this session. Every origin then needs
  per-origin consent; origins in `data/sensitive-origins.toml` (banking, email, health by
  default) are refused even with consent unless the member includes that one origin explicitly.
  Frames of an origin without consent are withheld. Detach closes Hermes's tab, forgets every
  consent, and never closes the member's browser.

## Tools

| tool | effect | output |
|------|--------|--------|
| `browser_navigate {url}` | write | untrusted |
| `browser_snapshot {}` | none | untrusted |
| `browser_act {ref, action: click/type, text?, clear?, submit?}` | write | untrusted |
| `browser_screenshot {}` | none | untrusted |
| `browser_console_messages {level?, limit?}` | none | untrusted |
| `browser_network_requests {problems_only?, limit?}` | none | untrusted |
| `browser_pick {goal}` | none | untrusted |

Every page is untrusted: output is fenced as data and taints the session (HUP-S2.7). After
taint, `browser_navigate` and `browser_act` wait for the member's explicit decision
(`src/approvals.rs`): one at a time, denied on timeout (120 s), on Stop, or on session stop.
The member decides through the sidecar's control routes, which citrate-core calls; the agent
loop cannot reach them.

## Sign-in bridge (HUP-S2.3, managed browser only)

`src/signin.rs`. In the managed browser, Hermes's tab gets a minimal EIP-1193 provider (also
announced through EIP-6963 as "Citrate (Hermes)") in its **top frame only**. `eth_chainId`,
`net_version`, `eth_accounts` and `wallet_switchEthereumChain` (to 40204 only) are answered in the
page; `eth_requestAccounts` and `personal_sign` become requests that wait here for citrate-core;
every other method is refused with EIP-1193 code 4200. The provider reaches the worker through a
CDP binding that the provider script removes from the page's global scope before any page script
runs, so embedded frames and page scripts cannot call it directly.

For each request the worker records, from Chrome's own events and never from the page: the
execution context that asked, whether it is the default context of the tab's top frame, and that
context's origin. Requests wait at most 120 s (then the page is told no), at most 4 at a time.
citrate-core reads them over `GET /browser/sign-in`, attests the page origin with its own read of
this browser's loopback DevTools endpoint, decides through its signature ceremony and answers over
`POST /browser/sign-in/answer`; the answer must fit the request (one address, or a 65-byte
signature, or a refusal) and is delivered only to the context that asked. The worker also keeps
the set of origins whose page content reached the model, which the sidecar folds into the session
taint core checks. The member's own Chrome (attach mode) gets no provider and no binding.

Keyless: the worker never sees a key, never signs and never decides.

## Sidecar control routes (bearer-gated)

`GET /browser/status`, `GET /browser/frame?after=N` (204 when nothing newer),
`POST /browser/stop` (latches), `POST /browser/resume`, `POST /browser/attach {port, consent}`,
`POST /browser/detach`, `POST /browser/origins {origin, allow, includeSensitive}`,
`POST /browser/actions/decide {id, allow}`, `GET /browser/sign-in`,
`POST /browser/sign-in/answer {id, accounts | signature | refused}`. The global e-stop
(`POST /stop`) also stops the browser.

## Tests

- `tests/scope_tests.rs`, `tests/snapshot_tests.rs`, `tests/tools_tests.rs`, unit tests in
  `src/service.rs`: run anywhere.
- `tests/cdp_replay_tests.rs`: the CDP layer against a local WebSocket server replaying
  message shapes recorded from Chrome 154; runs anywhere.
- `tests/live_chrome_tests.rs` and the last test in `tests/tools_tests.rs`: a real headless
  Chromium on pages served from 127.0.0.1. They skip, saying so, when no Chromium is installed.
  On Linux they pass `--no-sandbox` (tests only; production never does).
- `CITRATE_RECORD_FIXTURES=1 cargo test -p citrate-agent-browser --test live_chrome_tests`
  re-records `tests/fixtures/ax-login-form.json`.
- `tests/web_subset_tests.rs`: the web-subset-v2 fixture checks (anywhere), and live: a scripted
  picker finishes every task with the offered moves, early or wrong stops are not successes, a
  control whose clicks change nothing is withheld, the console and network tools read a real
  page, and `browser_pick` suggests without acting.
- Set `CITRATE_BROWSER_CHROMIUM` to run the live tests against a managed Chromium (for example
  an unpacked Chrome for Testing) instead of a system one. On 2026-10-04 all of them passed against
  Chrome for Testing 154.0.8037.92 (macos-arm64), run with `--test-threads=1`: in parallel, on a
  heavily loaded machine, Chrome can take more than the launch timeout to start (A51).
- The scored run with a real model is `agent-sidecar/tests/browse_live.rs` (see
  `agent-loop/DECIDE.md`).

## Third-party patterns

`src/pick.rs` adapts ideas (no code) from `ThinkFlowLab/system1-agents` (Apache-2.0,
`s1a/browser/action_space.py`) and `typesafe-ai/skills` (MIT, `skills/typesafe-ai/SKILL.md`), with
attribution in the module header. The TypeSafe skill itself is not vendored as a Hermes skill: it
is an integration guide for TypeSafe's hosted API that tells the agent to read the vendor's live
documentation, and the Jev vendor and terms decision is still open.

## Not done here

- Installing or updating the managed Chromium: the bundle entry is measured
  (`citrate-core/components/toolchain-bundle.json`, `chromium`), but the component key ceremony
  and a signed manifest are external, and the updater does not unpack zip yet.
- The architecture's `siwe_sign` is served by the sign-in bridge above: the page asks, core
  decides.
- The default sensitive-origins list is pending owner sign-off.
