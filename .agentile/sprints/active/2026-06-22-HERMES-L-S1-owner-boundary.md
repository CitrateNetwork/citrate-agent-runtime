---
created: 2026-06-22T00:00:00Z
branch: feat/hermes-local-hardened
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: review
sprint: HERMES-L-S1
---

# HERMES-L-S1 — local daemon, gateway, and the owner boundary

The security core: stand up Hermes as a local daemon connected to Discord, with the
owner-only command boundary fail-closed and anti-injection structural — *before* it has
any power that can hurt the server or the machine. Nothing destructive exists at the end
of S1; what exists is a boundary you can trust. Planset: `.agentile/planset/hermes/04,05,06,10`.

## Work packages (red-test-first)

| WP | Subject | Deliverable |
|----|---------|-------------|
| **WP-S1.1** | Gateway adapter | `hermes-discord` crate: serenity gateway + HTTP client; typed internal event bus; minimal intents (GUILDS, GUILD_MESSAGES, MESSAGE_CONTENT, GUILD_MEMBERS). Transport only — makes no decisions. |
| **WP-S1.2** | Daemon + hardening | `citrate-agent-cli daemon`: tokio host; hardened systemd unit (ADR-H6: non-root, NoNewPrivileges, ProtectSystem=strict, scoped workspace); `doctor` preflight (token valid, LLM reachable, owner-id set, guard fail-closed) — refuses to accept traffic until green. |
| **WP-S1.3** | Ingress guard + two planes | `authorize(author_id) -> Owner \| Other` as the single chokepoint (05). Owner-id auth by immutable id; fail-closed on unset/malformed/webhook/system. **Self-events (`author_id == bot_id`) dropped at the adapter** (T17). **Interactions re-run the guard on `interaction.user.id`** (T15). Command plane reachable only by Owner; `Other` gets the fixed refusal string, addressed-only, per-user cooldown, no owner-id oracle. Moderation plane stub exists but takes no commands. |
| **WP-S1.5** | Per-message principal binding | Command-plane actions bind to a single owner-authored message id; any thread/agenda context window is filtered to owner-authored messages before reaching the planner (ADR-H9). Closes the two-plane back door. |
| **WP-S1.4** | Trail | Every auth decision + action recorded (RecorderClient) + anchored (agent-chain); non-owner command attempts captured as security signal. |

## Threat gate (must be green to merge — `06`)

- **T1 prompt injection** — the refusal is a fixed string with no LLM round-trip; no read
  content reaches a tool-bound path. (Full T1 coverage continues in S2/S3.)
- **T2 owner impersonation** — nickname/username/webhook spoof fails to gain command access.
- **T12 refusal-spam** — addressed-only + per-user cooldown; ambient ignored; no owner-id oracle.
- **T15 interaction auth** — buttons/slash re-run the guard on the interacting user's id.
- **T17 self-event loop** — `author_id == bot_id` dropped at the adapter.

`hermes-redteam` scenarios for T1/T2/T12/T15/T17 + the per-message-binding back-door
(ADR-H9) written failing-first, turned green.

## Owner inputs (needed to run S1)

- `OWNER_DISCORD_ID` — **the linchpin; needed before WP-S1.3 can be tested live.**
- The guild id.
- Confirm the bot is in the server (done) and the local LLM endpoint (for S2; S1 needs
  only token + owner id).

## Out of scope (named)

- Any member-facing power (moderation actions), server changes, content/publish — all
  later sprints. S1 ships read + the boundary + the refusal only.
- The full anti-injection suite for tool-executing paths (S2/S3, where tools come online).

## REPORT (2026-06-22)

**Delivered.** The owner boundary is built, tested, and live on the server.

| WP | Status |
|----|--------|
| WP-S1.1 gateway adapter | ✅ `hermes-discord` (serenity 0.12); **live-verified** — authenticated as `citrate-hermes`, gateway connected, `guilds=1`. |
| WP-S1.2 daemon + doctor + hardening | ✅ `hermesd` bin; `doctor` preflight fail-closed (verified: no owner id ⇒ refuses to start with the reason); hardened unprivileged systemd unit `deploy/citrate-hermes.service`. |
| WP-S1.3 ingress guard + two planes | ✅ `hermes-core::guard` — owner-only command plane, self-event drop (T17), interaction auth (T15), channel default-deny (H-A17). |
| WP-S1.4 trail | ✅ append-only `Trail` seam + live `TracingTrail` records every decision; non-owner attempts flagged as security signals. **On-chain decision anchoring** (`RecorderClient`) deferred to S2 by design — the decision registry is for the approval queue's Approved/Rejected decisions, which arrive in S2; anchoring every message on-chain is neither desirable nor its purpose. The `Trail` trait is the seam. |
| WP-S1.5 per-message binding | ✅ command bound to one owner-authored message id; `owner_authored_context` filter closes the ADR-H9 back door. |

**Tests:** 31 (hermes-core 25 + hermes-discord 6), clippy-clean. The threat rows
T1/T2/T12/T15/T17 + fail-closed config + the ADR-H9 back-door are covered by unit tests
in `hermes-core` (the security core is pure, so the assurance is real, not mocked).

**What's true now:** the boundary is enforced end to end — the owner reaches the command
plane; everyone else who addresses the bot gets exactly the refusal (rate-limited);
webhooks/system messages can't impersonate the owner; self-events and unmodeled channels
are denied; the daemon won't start without a valid owner id. Running hardened + unprivileged.

**What S1 deliberately does *not* do:** respond to the owner (that's S2's command plane /
research room), any moderation action (S3), any server change (S4). It logs
`command-plane message accepted (owner)`; the response is S2.

**Honest scope note:** the per-sprint `hermes-redteam` integration crate named in `06`
is, for S1, satisfied by the in-crate unit tests above; a standalone red-team crate with
the full T1–T22 scenario families is built out at the HARDEN-A checkpoint before S3.

## Close-out
- Status `review` → this PR. On merge, move to `completed/`. Next: S2 (research-room
  command plane + local-LLM responses + the approval queue, where the on-chain trail
  anchoring also lands).
