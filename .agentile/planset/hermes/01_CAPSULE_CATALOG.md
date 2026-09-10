---
created: 2026-06-22T00:00:00Z
branch: feat/hermes-general-purpose
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: active
program: HERMES-GP
---

# Hermes capsule catalog — the skills out of the box

Each row is a capsule Hermes ships with. The capability columns are the *declared*
`manifest.toml` surface (the guardrail lives in the skill). `network` is an allowlist,
never `"any"`. `risk` drives whether an action runs auto or queues for approval (see
`02_GUARDRAILS.md`). "Backs onto" names the runtime crate the capsule's host functions
bind to.

Legend — `data_class`: P=PUBLIC, I=INTERNAL, S=SENSITIVE. `risk`: low / med / high.
Approval column: **auto** = runs within profile, **queue** = goes to the approval queue.

## Domain A — Research & Data R&D (the NAT corpus engine)

| capsule | does | network | filesystem | risk | approval | backs onto |
|---------|------|---------|------------|------|----------|------------|
| `source-vet` | license + provenance check before any intake; fail-closed on the `ALLOWED_LICENSES` allowlist | none | read staging | high | auto (it *is* the gate) | nat-data |
| `corpus-fetch` | fetch a permissive/PD source (Gutenberg, arXiv, code repo, allowlisted web) → raw bytes | allowlist:[gutenberg.org, arxiv.org, raw.githubusercontent.com, …] | write staging | med | auto (vetted source) / queue (new domain) | agent-code + nat-data |
| `corpus-normalize` | run RawDocs through the nat-data pipeline (normalize → quality-score → JSONL); wraps `nat-corpus` | none | read/write corpus | low | auto | nat-data |
| `reading-list-curate` | propose reading-list additions for a research intent | none | read research-loop | low | queue (proposal) | agent/core (LLM) |
| `train-smoke` | launch a `nat-candle` training smoke + report metrics | none | read corpus | med | auto (bounded compute) | agent-code (shell, capped) |
| `eval-report` | run the eval battery; summarize H-01/H-02 deltas honestly | none | read artifacts | low | auto | agent-code |

## Domain B — Discord server management

| capsule | does | network | filesystem | risk | approval | backs onto |
|---------|------|---------|------------|------|----------|------------|
| `discord-read` | read channels / threads / member list | allowlist:[discord.com/api] (read scopes) | none | low | auto | agent/core |
| `discord-digest` | summarize activity → daily digest; emit to a channel or the owner | allowlist:[discord.com/api] | none | low | auto | agent-cron (SOP) |
| `discord-onboard` | welcome + role-assign new members per an onboarding SOP | allowlist:[discord.com/api] (guilds.members write) | none | med | auto (non-destructive) | agent-cron |
| `discord-post` | post announcements / replies | allowlist:[discord.com/api] (messages write) | none | med | auto within rate-limit; queue if @everyone | agent/core |
| `discord-moderate` | timeout / kick / ban / role-strip | allowlist:[discord.com/api] (moderation) | none | high | **queue always** (destructive, member-facing) | agent/core |

## Domain C — CMS & social content

| capsule | does | network | filesystem | risk | approval | backs onto |
|---------|------|---------|------------|------|----------|------------|
| `content-draft` | draft a post/article from a brief | none | read brief store | low | queue (draft for review) | agent/core (LLM) |
| `asset-organize` | tag + file generated assets in the content store | allowlist:[cms-api] | read/write asset store | low | auto | agent-code |
| `content-calendar` | maintain the editorial calendar | allowlist:[cms-api] | read/write calendar | low | auto | agent/core |
| `cms-publish` | publish / update content in the CMS | allowlist:[cms-api] (write) | none | high | **queue always** (outward-facing, hard to reverse) | agent/core |
| `social-schedule` | schedule a post across socials | allowlist:[per-network APIs] (write) | none | high | **queue always** (outward-facing, public, cached/indexed) | agent/core |

## Domain D — Skill-acquisition (meta) — "go gather what it needs"

This pack is why a starting catalog is enough: when an agenda needs a capability Hermes
lacks, it *builds* the capsule.

| capsule | does | network | filesystem | risk | approval | backs onto |
|---------|------|---------|------------|------|----------|------------|
| `capsule-author` | given a capability gap, scaffold a new capsule (manifest + `wit/` + `gherkin/` + `procedure.md` + wasm) | none | write `capsules/` | med | auto (sandboxed; not yet live) | agent-code |
| `tool-acquire` | research an external API/tool, generate a client, wrap it behind a capsule | allowlist:[docs hosts] | write `capsules/` | med | auto (authoring) → cert is gated | agent-code |
| `capsule-certify` | run the capsule's gherkin/TLA gates, compute `content_hash`, sign (bundled tier), **register it live** | none | read `capsules/` | high | **queue always** (granting a new live capability) | agent-chain + signing |
| `capability-request` | when a capsule needs a broader grant than its profile allows, file the request to the approval queue with justification | none | none | high | **queue always** | agent/core |

The discipline: **authoring is auto, certifying is gated.** Hermes can write as many
candidate skills as an agenda needs in its sandbox; it cannot grant itself a new *live*
capability without an owner approval. That is the escalation boundary made operational.

## Domain E — Agentile work-discipline pack (work like the other agents)

| capsule | does | network | filesystem | risk | approval | backs onto |
|---------|------|---------|------------|------|----------|------------|
| `repo-scaffold` | create a repo with the agentile structure (`.agentile/`, AUDIT_TIER, sprint dirs) | allowlist:[github.com/api] | write workspace | med | queue (creates a repo) | agent-code |
| `sprint-open` | open a sprint plan with Rule-12 frontmatter | none | write `.agentile/sprints/active` | low | auto | agent-code |
| `sprint-close` | write REPORT.md, update gates, move to `completed/` | none | write `.agentile` | low | auto | agent-code |
| `journal-write` | append a durable-lesson journal entry | none | write journal | low | auto | agent-code |
| `work-anchor` | record a decision/session hash on-chain | none | none | med | auto (anchor only) | agent-chain |
| `pr-open` | open a PR with the house conventions (co-author trailer, footer) | allowlist:[github.com/api] | none | med | queue (outward) | agent-code |

## Already-shipped capsules Hermes inherits

The repo's existing capsules are immediately part of Hermes's catalog: `provision-user`,
`revoke-role`, `verify-provenance-chain`, `anchor-session`, `query-decisions-by-tenant`,
`list-compliance-posture`, `query-supplier-status`, `hello`, `echo-chain`. These give it
identity/RBAC and provenance-audit skills for free.

## Build note

Most catalog rows are **specs to be authored** (the program does not flesh out each
domain). The ones that are real *today* via existing runtime crates — `discord-read`,
`discord-digest`, `journal-write`, `sprint-open/close`, `work-anchor`, `corpus-normalize`
(wrapping `nat-corpus`) — are the natural first capsules to certify, because their host
functions already exist. The sprint sequences this.
