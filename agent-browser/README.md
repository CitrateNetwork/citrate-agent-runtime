---
created: 2026-10-01
branch: hup/n4-browser
author: Larry Klosowski + Claude Opus 5.5
status: implemented and wired into sidecar sessions behind CITRATE_HERMES_BROWSER (default off); managed Chromium install is HUP-S5.5
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

Every page is untrusted: output is fenced as data and taints the session (HUP-S2.7). After
taint, `browser_navigate` and `browser_act` wait for the member's explicit decision
(`src/approvals.rs`): one at a time, denied on timeout (120 s), on Stop, or on session stop.
The member decides through the sidecar's control routes, which citrate-core calls; the agent
loop cannot reach them.

## Sidecar control routes (bearer-gated)

`GET /browser/status`, `GET /browser/frame?after=N` (204 when nothing newer),
`POST /browser/stop` (latches), `POST /browser/resume`, `POST /browser/attach {port, consent}`,
`POST /browser/detach`, `POST /browser/origins {origin, allow, includeSensitive}`,
`POST /browser/actions/decide {id, allow}`. The global e-stop (`POST /stop`) also stops the
browser.

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

## Not done here

- Installing or updating the managed Chromium (HUP-S5.5 component updater).
- `console`, `network` and `siwe_sign` browser tools from the architecture table (SIWE is the
  HIC-2 budget path, HUP-S2.3).
- The `decide()` System-1 element picker (HUP-S5.3).
- The default sensitive-origins list is pending owner sign-off.
