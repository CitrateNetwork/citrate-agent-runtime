---
created: 2026-06-22T00:00:00Z
branch: feat/hermes-local-hardened
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: active
program: HERMES-L
---

# Hermes-Local — architecture decision records

Concise ADRs for the load-bearing choices. Each is revisitable, but the rationale is the
reason it's the default.

## ADR-H1 — Discord library: serenity
Use **serenity** for the gateway + HTTP adapter. Mature, batteries-included (gateway,
cache, HTTP, builders), large community, async/tokio-native (matches the workspace).
Twilight is more modular/lower-overhead but pushes more wiring onto us; for a single
local daemon, serenity's ergonomics win. Revisit only if cache memory or fan-out
becomes a problem (not at one guild).

## ADR-H2 — LLM backend: local-first, optional escalation
Hermes reasons on the **local citrate-llama** (128k ctx, on the DGX) by default —
private, always-on, no data leaves the box. A stronger remote model is an *optional,
owner-configured* escalation for hard agendas, **off by default**, and **never** applied
to private-channel content without explicit owner opt-in. "Maximally capable" is served by
on-box capability + subagents, not by defaulting to sending data off-machine.

## ADR-H3 — Two-plane architecture (the central security decision)
The **command plane** (owner-only, fail-closed, can execute) and the **moderation plane**
(autonomous over all members, can never execute a command) are separate code paths joined
only by the single ingress guard. A non-owner message can be *moderated* but never
*obeyed*. This is what makes "maximally capable but owner-only" safe: power lives behind a
principal check no member can pass.

## ADR-H4 — Read content is data, never instructions *(scope: ALL ingested content)*
Any content Hermes ingests — guild messages, **fetched web pages, digests, research
sources, and restored memory-graph state** — is treated as **data**, never instructions.
Moderation/classification runs as **structured output on an LLM call with no tools bound**;
the output schema is **strictly validated** (label enum + numeric confidence range), and a
deterministic policy maps label→action — the model never issues an action directly and its
free-text `reason` is never rendered into an action or unescaped into a channel. The
research/content loops follow the same rule: the LLM emits **typed intents → the owner
queue**, never a direct action, even though those loops have downstream tools. Owner
commands arrive only via the command plane and are parsed into typed intents, never
executed verbatim. This is the structural defense against prompt injection across *every*
ingestion path (T1, T22; H-A5/H-A13).

## ADR-H5 — Server changes are declarative, dry-run, approved, backup-first
No imperative destructive Discord operations. The server is a `server-spec.toml`;
changes go reconcile → diff → human-readable plan → owner approval (destructive items
per-item) → backup → idempotent apply → record. The owner sees exactly what changes before
it changes (T14).

## ADR-H6 — Run hardened and unprivileged
Hermes runs as a **dedicated non-root unix user** under a hardened systemd unit
(`NoNewPrivileges`, `ProtectSystem=strict`, scoped read-write workspace, `PrivateTmp`, no
sudo). `agent-code` shell is argv-vector, allowlisted, timeout-bounded, workspace-scoped.
Because it runs locally with shell access, the blast radius of a compromise is contained
to an unprivileged sandbox, not the machine (T5/T10).

## ADR-H7 — Owner authority is necessary but not sufficient for irreversible actions
Even the owner's command does not *immediately* execute an irreversible/mass action
(mass-ban, channel/role deletion, spec apply, capsule-certify, value transfer): those
require a **second factor that is not the Discord account** (a local-machine confirmation
or out-of-band signed token), because the queue/confirm/delay are otherwise circular —
the compromised credential is the same Discord account that would approve them (H-A4).
The pending-action + delay state lives **off the Discord plane and persists across daemon
restart**, so a kill-and-restart cannot skip a delay (H-A19). Plus anomaly detection and a
local kill-switch. This bounds owner-account-compromise damage (T3) without narrowing what
the owner can ultimately do from the machine.

## ADR-H9 — Per-message principal binding
Every command-plane action derives from exactly **one owner-authored message id**, and the
agenda/research context window is **filtered to owner-authored messages only** before it
reaches the LLM/planner. Authorization on `author_id` alone is insufficient once a *thread*
of messages is aggregated into context — a non-owner message in the thread would otherwise
become a command. This closes the back door around the two-plane model (ADR-H3); it also
governs **interactions** (buttons/slash), which re-run the guard on the interacting user's
id rather than trusting channel visibility (T15, H-A1/H-A2).

## ADR-H10 — Fail-closed backpressure
Under load the system fails **closed**, never open. Global ingress and classification
rate-limits bound throughput; overflow routes to quarantine/queue, never to auto-allow. A
spam flood can never starve moderation into letting content through unmoderated (T18).

## ADR-H11 — Supply-chain pinning + untrusted resumed state
`serenity` and all deps are **pinned, vendored, and gated** by `cargo-audit` / `cargo-vet`,
because they run inside the process holding the token and signer. Restored **memory-graph**
state is re-validated as **data through the guard** on resume, never trusted as resumed
intent — a poisoned store cannot replay attacker actions on restart (T21).

## ADR-H8 — Least-privilege Discord permissions, staged by sprint
The bot is invited with the **minimum** permissions each stage needs, added only when that
capability ships: read+post for S1–S2; moderation scopes at S3; elevated manage-* only for
the windowed S4 rebuild, then reduced. No "Administrator forever" convenience grant.
