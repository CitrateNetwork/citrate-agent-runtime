---
created: 2026-06-22T00:00:00Z
branch: feat/hermes-general-purpose
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: active
program: HERMES-GP
---

# Hermes — the general-purpose Citrate operator agent

> **Local hardened build (HERMES-L).** The concrete, owner-only, locally-run build of
> Hermes — Discord daemon, owner-auth boundary, threat model, server rebuild, moderation,
> subagents, and the end-to-end roadmap with adversarial gates — is specified in
> `04_LOCAL_DEPLOYMENT` · `05_OWNER_AUTH` · `06_THREAT_MODEL` · `07_SERVER_REBUILD` ·
> `08_MODERATION` · `09_SUBAGENTS_AND_RESEARCH_ROOM` · `10_ROADMAP` · `decisions.md`.
> Documents `00`–`03` below are the cross-domain vision and capsule catalog that build sits on.

Hermes is not a single-purpose bot. It is a **general-purpose operator agent** that
runs on this runtime and is handed *agendas* — "build the NAT corpus this week",
"keep the Discord healthy", "ship the social calendar" — and goes and does them,
acquiring whatever skills it lacks along the way, inside guardrails that make every
action scoped, auditable, and reversible.

This program does **not** build out each domain feature. It builds Hermes so that the
**skills are present out of the box**: a capsule catalog spanning the domains it will
serve, plus the self-extension path so it can *author new capsules* for agendas we
have not anticipated. The deliverable is the architecture, the catalog, the guardrails,
and the fresh-install runbook — the scaffolding a "very good general-purpose agent"
needs before any one domain is fleshed out.

## The three agendas it must serve out of the box

1. **Research & Data R&D** — gather, vet, normalize, and quality-score training corpora
   (the NAT data effort); run training smokes and eval reports. Permissive-license-only,
   provenance-immutable.
2. **Discord server management** — read/digest activity, onboard members, moderate, and
   announce on the owner's Discord.
3. **CMS & social content** — draft, organize, schedule, and publish content for the
   owner's socials through a CMS.

…plus the two cross-cutting packs that make it an *agent in our ecosystem*, not a script:

4. **Skill-acquisition (meta)** — when an agenda needs a capability Hermes lacks, it
   authors a new capsule, certifies it through the gates, and registers it. This is the
   "go gather what it needs" engine.
5. **Agentile work-discipline** — Hermes opens sprints, writes journals, anchors its
   work on-chain, and opens PRs like every other agent in the federation.

## How it maps onto this runtime (nothing new invented)

Hermes *is* `citrate-agent-runtime` plus a curated capsule catalog. Every part already
exists as a crate; Hermes is the composition.

| Need | Runtime substrate (this repo) |
|------|-------------------------------|
| Tool execution + audit trail | `agent/core` — `ToolRegistry`, `AgentTool`, `RecorderClient` |
| **Skills** (pluggable, sandboxed, least-privilege) | `capsules/` — WASM components with a `manifest.toml` capability surface |
| Autonomy / daily loop | `agent-cron` — `CronScheduler` + `SOPEngine` |
| On-chain anchoring of decisions | `agent-chain` |
| **Skill acquisition** (write/run/commit code) | `agent-code` — `file_write` / `shell_exec` / `git_ops` / `search_code` |
| Operator console / CLI | `agent/cli` |

The insight that makes this coherent: **a capsule's `manifest.toml` is already a
least-privilege skill spec.** It declares `[capability]` (network / filesystem /
chain_calls / subagent_spawn), `[data_class]` (what it reads/writes/emits), `[risk]`
(tier + `required_roles` + break-glass), and `[provenance]` (publisher DID, the
`agentile_sprint` that produced it, an optional TLA spec). So "give Hermes a skill"
means "add a capsule", and the guardrail for that skill is *in the skill*, declared and
signed. Hermes acquiring a new skill = authoring a new capsule (via `agent-code`) and
getting it certified — and certification, the moment a new live capability is granted,
is the one thing that is always owner-gated.

## The operating model (the boundary)

Hermes runs under the operating model in
`Citrate/.agentile/audits/2026-04/2026-04-01-ux-redesign-and-agent-ops-audit/03_AGENT_LOGSEQ_HERMES_OPERATING_MODEL.md`:
policy profiles (ReadOnly / Guided Builder / Operator / Maintainer), capability grants
that are **scoped, expiring, and revocable**, an append-only action trail, an approval
queue for anything outward-facing or hard-to-reverse, and a Logseq journal projection.
The formal boundary: **no uncapped transfer, filesystem, shell, or privilege
escalation** — ever, in any profile. A feature is "finished" only when it is
*seen → configured → monitored → paused → audited*.

The per-domain autonomy levels are in `02_GUARDRAILS.md`; the catalog in
`01_CAPSULE_CATALOG.md`; the fresh-install path (uninstall the unfinished Discord
Hermes, deploy fresh) in `03_FRESH_INSTALL.md`. The build order is the sprint
`.agentile/sprints/active/2026-06-22-HERMES-GP-S1-general-purpose.md`.

## What "out of the box" means, concretely

When Hermes is handed an agenda it has never seen, it should be able to:

1. **Plan** it (open a sprint, decompose into work).
2. **Find** it already has the skill (catalog lookup) — or **acquire** it (author a
   capsule, certify it through the gates, register it).
3. **Do** it within the domain's autonomy profile, queuing anything outward-facing.
4. **Record** it (journal + on-chain anchor) and **report** it (PR / digest).

Steps 1, 2, and 4 are the same for every agenda — that generality is the product. The
domain capsules in the catalog are the starting skills; the skill-acquisition pack is
why "starting" is enough.
