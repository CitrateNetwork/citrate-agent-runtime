---
created: 2026-06-22T00:00:00Z
branch: feat/hermes-general-purpose
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: active
program: HERMES-GP
---

# Hermes fresh-install runbook

There is an unfinished, unconfigured Hermes already in the owner's Discord. This program
replaces it with a fresh deploy of `citrate-agent-runtime` carrying the capsule catalog.
Steps marked **[OWNER]** require the owner's accounts/secrets and cannot be done by an
agent — they are flagged, not performed.

## Phase 0 — inventory the old install (before touching anything)

1. **[OWNER]** Locate the running Discord Hermes: host (droplet? local? a PaaS?),
   process/unit, and what it has access to (bot token scopes, any stored data).
2. Record what it can currently do, so nothing capability-wise regresses silently.
3. Snapshot any data worth keeping (config, logs, any corpus/work it produced).

> Rationale: per the house rule, before deleting/overwriting something you did not
> create, look at it first — if what you find contradicts "unfinished and unconfigured",
> stop and surface that instead of proceeding.

## Phase 1 — decommission the old bot (security first)

4. **[OWNER]** In the Discord Developer Portal, **rotate/reset the old bot token** so the
   stale deploy cannot act after cutover (same rotation discipline as the KEYSAFE key
   rotation — revoke before redeploy, never leave two live credentials).
5. **[OWNER]** Remove the old bot from the server *or* strip its roles to none until
   cutover is verified.
6. Stop and disable the old process/unit. Keep the snapshot from Phase 0; do not delete
   it until the fresh install is verified.

## Phase 2 — provision the fresh runtime

7. Deploy `citrate-agent-runtime` as the Hermes host (build on the target arch — note the
   federation arch gotcha: the dev box is aarch64). Bring up `agent/cli` as the operator
   entry point and `agent-cron` as the daily-loop daemon.
8. Load the capsule catalog (`01_CAPSULE_CATALOG.md`): start with the capsules whose host
   functions already exist (`discord-read`, `discord-digest`, `journal-write`,
   `sprint-open/close`, `work-anchor`, `corpus-normalize`) — certify those first.
9. Set the per-domain policy profiles (`02_GUARDRAILS.md`): Operator for Research/Data,
   Guided Builder for Discord, Guided Builder for CMS/socials, Operator-authoring for
   skill-acquisition.
10. Wire the audit trail: RecorderClient on, on-chain anchoring via `agent-chain`, Logseq
    journal projection on.

## Phase 3 — wire the external surfaces  **[OWNER]** (agent cannot do these)

11. **[OWNER]** Create a *new* Discord bot application; grant the **minimum** scopes the
    catalog needs (read, messages.write, guilds.members for onboard; moderation scope
    only if `discord-moderate` is wanted and only into its queued path). Invite it.
12. **[OWNER]** Provide the CMS API base + credentials (for `cms-publish`,
    `content-calendar`, `asset-organize`) — scoped to a content workspace, not admin.
13. **[OWNER]** Provide per-network social API credentials for `social-schedule` — each
    scoped to post-on-behalf, nothing account-administrative.
14. **[OWNER]** Confirm the host/compute for the daily loop and any training smokes.

> All four are owner-gated by nature (they are the owner's accounts, secrets, and
> hosting). Store them the way the rest of the stack stores secrets (the canonical
> keystore pattern), never inline in a capsule.

## Phase 4 — verify against the finished-feature bar

For each domain, confirm the capability is **seen → configured → monitored → paused →
audited**:

15. **Seen** — every loaded capsule shows in the Agent Center with its capability surface.
16. **Configured** — each domain's profile is set and visible.
17. **Monitored** — a test action in each domain appears live in the action trail.
18. **Paused** — pausing Hermes mid-action actually halts it.
19. **Audited** — the test actions are on the append-only trail + anchored on-chain.

Only after Phase 4 passes: delete the Phase-0 snapshot and close the cutover.

## Cutover smoke (per domain)

- **Data:** hand Hermes "vet + normalize this PD source" → it runs `source-vet` →
  `corpus-fetch` → `corpus-normalize`, and a non-allowlisted license is refused.
- **Discord:** hand it "post a digest to #general" → `discord-digest` runs auto; "timeout
  user X" → `discord-moderate` *queues* and does nothing until approved.
- **CMS/socials:** hand it "draft + schedule a post" → `content-draft` runs auto, the
  schedule step *queues* until approved.
- **Skill-acquisition:** hand it an agenda needing a missing skill → it `capsule-author`s
  a candidate in the sandbox, and `capsule-certify` *queues* for owner sign-off.

If each domain's auto path runs and each gated path queues, Hermes is live and inside the
boundary.
