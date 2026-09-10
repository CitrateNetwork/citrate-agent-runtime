---
created: 2026-06-22T00:00:00Z
branch: feat/hermes-general-purpose
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: active
sprint: HERMES-GP-S1
---

# HERMES-GP-S1 — general-purpose Hermes: skills out of the box

Turn `citrate-agent-runtime` into the general-purpose operator agent Hermes: a curated
capsule catalog across Research/Data, Discord, and CMS/socials, plus the skill-acquisition
and agentile packs, under per-domain guardrails — and a fresh install over the unfinished
Discord bot. Planset: `.agentile/planset/hermes/00..03`.

This sprint establishes the **architecture and the starting catalog**; it does not flesh
out every domain feature (that is each domain's own later sprint). The bar for "done
here" is: Hermes can be *handed an agenda, plan it, find-or-acquire the skill, act within
the boundary, and record it* — for at least one capsule per domain, with the rest specced.

## Work packages

| WP | Subject | Deliverable | Status |
|----|---------|-------------|--------|
| **WP-H1** | Capsule catalog specs | `manifest.toml` + `wit/` + `gherkin/` + `procedure.md` skeletons for every catalog row (capability surface declared, no live wasm yet) | planned |
| **WP-H2** | First live capsules | Certify the capsules whose host fns already exist: `corpus-normalize` (wraps `nat-corpus`), `journal-write`, `sprint-open/close`, `work-anchor`, `discord-read`, `discord-digest` | planned |
| **WP-H3** | Guardrail enforcement | Policy-profile + approval-queue wiring: per-domain profiles, the "outward/destructive/capability-granting → queue" rule, scoped+expiring+revocable grants | planned |
| **WP-H4** | Skill-acquisition loop | `capsule-author` (scaffold via `agent-code`) + `capsule-certify` (gates → `content_hash` → sign → register), with certify always owner-gated | planned |
| **WP-H5** | Daily loop SOP | `agent-cron` SOP that runs the research-loop intent, digests Discord, and surfaces the approval queue — the "manage it daily, add intent" cadence | planned |
| **WP-H6** | Fresh install | Execute `03_FRESH_INSTALL.md` Phases 2 & 4; Phases 0,1,3 are **[OWNER]** | gated (owner) |

## Dependencies / gating

- **[OWNER]** Discord bot (new token, scoped), CMS API creds, social API creds, host —
  all in `03_FRESH_INSTALL.md` Phase 3. The agent cannot provision these.
- The signer for `capsule-certify` reuses the bundled-tier signing already in the repo
  (`[signing] tier = "bundled"`); the operator/KMS signer path mirrors the gateway's.
- `corpus-normalize` depends on the `nat-data` pipeline (cross-repo; wrap the
  `nat-corpus` CLI rather than vendoring).

## Out of scope (named so it is not silently assumed done)

- Full Discord moderation feature set, full CMS integration, full social scheduling — each
  is a domain sprint after the catalog exists. This sprint ships the *skills and the
  boundary*, plus one working capsule per domain, not the finished products.
- The operator/KMS production signer migration (custody path) — separate, mirrors gateway.

## Close-out

- REPORT.md: which capsules are live vs specced, the cutover smoke results
  (`03_FRESH_INSTALL.md` §cutover), and the owner-gated items still open.
- Journal: the durable lesson (likely "the capsule manifest *is* the guardrail — skills
  and their limits ship together").
- Move to `completed/` once WP-H1..H5 land and the fresh install (WP-H6) is owner-verified.
