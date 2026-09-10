---
created: 2026-06-22T00:00:00Z
branch: feat/hermes-local-hardened
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: active
program: HERMES-L
---

# Hermes-Local roadmap — end-to-end build order

The sequence is deliberately **security-first, power-last**: stand up the owner-only
boundary and the anti-injection architecture *before* Hermes is given any power that can
hurt the server or the machine. Each sprint is red-test-first against its threat rows
(`06`), journaled, and PR'd; the two dangerous milestones (S3 moderation, S4 rebuild) gate
on a full red-team run **plus** an independent adversarial review before any elevated
permission touches the guild.

Program prefix `HERMES-L` (local-hardened), building on the merged `HERMES-GP` catalog
(`00`–`03`).

## Sprints

### HERMES-L-S1 — Local daemon, gateway, and the owner boundary  *(security core)*
- **WP-S1.1** `hermes-discord` crate: serenity gateway + HTTP, typed event bus, minimal intents.
- **WP-S1.2** `daemon` subcommand: long-running tokio host; hardened systemd unit (ADR-H6); `doctor` preflight (token/LLM/owner-id/fail-closed).
- **WP-S1.3** The **ingress guard** + two-plane split (05): owner-id auth, fail-closed, the fixed refusal string, per-user cooldown, addressed-only response. No tools/LLM reachable by `Other`.
- **WP-S1.4** Trail wiring: every auth decision + action recorded (RecorderClient) and anchored (agent-chain).
- **Threat gate:** T1, T2, T12, **T15 (interaction auth), T17 (self-event drop)** green. **Owner input:** `OWNER_DISCORD_ID`, guild id.
- **Exit:** owner is served (with per-message principal binding, ADR-H9), everyone else gets exactly the refusal, fail-closed verified, nothing destructive exists yet.

### HERMES-L-S2 — Research room & owner command plane  *(owner I/O)*
- **WP-S2.1** Local LLM client (citrate-llama) + the agenda→thread loop in `#hermes-research` (09).
- **WP-S2.2** Approval-queue surface (`#approval-queue`) with provenance labels (T11); the agentile pack capsules live (sprint-open/close, journal-write, work-anchor).
- **WP-S2.3** Memory-graph persistence (citrate-memories) so agenda state survives restart/context-clear.
- **WP-S2.4** Read-only / Guided-Builder capsules: `discord-read`, `discord-digest` (digest target allowlisted, T13).
- **Threat gate:** T11, T13, **T20 (secret-in-memory), T21 (poisoned memory/supply chain), T22 (research/digest injection)** green. **Owner input:** research/queue/log channel ids; LLM endpoint confirmed.
- **Exit:** owner hands Hermes agendas and it plans/works/reports; still no member-facing power.

### HERMES-L-HARDEN-A — Adversarial checkpoint before power
- Full `hermes-redteam` run over **all threat rows applicable to S1–S2 (T1–T5, T8–T13, T15, T17, T20–T22)**; independent adversarial review of the S1–S2 diff + boundary (round 1 logged in `11_HARDENING.md`). **No further sprint proceeds until green.**

### HERMES-L-S3 — Moderation plane  *(first member-facing power — heavily gated)*
- **WP-S3.1** Verification/onboarding gate (08): quarantine→challenge→verified; teammate path.
- **WP-S3.2** Anti-raid (join-rate raid mode, owner alert).
- **WP-S3.3** Spam/scam auto-mod — **high-precision only**, structured-classification-no-tools (T1/T6); strike ledger; owner/mod/teammate allowlist.
- **WP-S3.4** Audit + appeals (`#audit-log`, reversible, on-chain).
- **Threat gate:** T1, T6, T7, **T16 (edit-after-clear), T18 (DoS fail-closed)** green + HARDEN-A passed. **Owner input:** approve the moderation Discord scopes (ModerateMembers, ManageMessages, KickMembers) — invited only now.
- **Exit:** the door is gated and raids/spam handled, with the innocent biased-protected.

### HERMES-L-S4 — Server rebuild  *(structural power — heaviest gate)*
- **WP-S4.1** `server-spec.toml` schema + reader; the current-guild reader/backup.
- **WP-S4.2** Diff engine → human-readable plan; per-item approval; destructive-item confirm.
- **WP-S4.3** Idempotent apply; safety invariants (never delete owner/bot role; escape hatch; T14).
- **WP-S4.4** Authored target spec for the owner's server (roles, channels, flows from 07).
- **Threat gate:** T14, **T19 (TOCTOU diff→apply)** green + a second adversarial review. **Owner input:** elevated rebuild invite (Manage Channels/Roles/Guild), windowed; approve the spec + each destructive item.
- **Exit:** the server is rebuilt to the approved spec, reversibly, with a backup.

### HERMES-L-S5 — Subagents, skill-acquisition, scale  *(maximal capability)*
- **WP-S5.1** Supervisor + scoped subagents (09): moderation-watch, research, content, server-ops (windowed).
- **WP-S5.2** Skill-acquisition loop live: `capsule-author` (auto) → `capsule-certify` (owner-gated).
- **WP-S5.3** Broaden agendas: NAT data R&D (domain A) + CMS/socials (domain C, publish queued).
- **WP-S5.4** Optional remote-LLM escalation (off by default; never on private content without opt-in).
- **Threat gate:** T4, T9 green; per-subagent capability-surface tests. **Owner input:** CMS/social creds (queued-publish only).
- **Exit:** Hermes runs multiple agendas with bounded subagents and can acquire new skills under the owner gate.

## Cross-cutting (every sprint)

- **Red-test-first** against the sprint's threat rows; **HARDEN** checkpoints before S3 and S4.
- **Finished bar** per capability: seen→configured→monitored→paused→audited (02).
- **Journal** the durable lesson each sprint; **PR** with house conventions; high-audit-tier review.

## Owner inputs (the full list — agent cannot supply these)

1. `OWNER_DISCORD_ID` (S1) — **needed first**.
2. Guild id + the channel ids for research / approval-queue / audit-log / verify (S1–S2).
3. Local LLM endpoint confirmation (S2; citrate-llama assumed).
4. Approve moderation Discord scopes (S3) — invited only at S3.
5. Approve the elevated, windowed rebuild invite + the `server-spec.toml` + each
   destructive diff item (S4).
6. CMS / social API creds, publish-only scope (S5).
7. Production secret rotation at cutover (the current dev token gets replaced).

## Dependency notes

- Net-new: the `hermes-discord` adapter (no Discord lib in-tree today).
- Reuses in-tree: agent-cron (SOPs), agent-chain (anchor), agent-code (skill acquisition),
  agent/core (ToolRegistry/RecorderClient), capsule runtime (wasmtime + manifests).
- Cross-repo: citrate-memories (MCP, durable memory), nat-corpus (domain A), citrate-llama
  (local LLM).
