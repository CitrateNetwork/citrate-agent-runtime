---
created: 2026-06-22T00:00:00Z
branch: feat/hermes-local-hardened
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: active
program: HERMES-L
---

# Hermes local deployment — a maximally-capable agent on the owner's machine

Hermes runs **locally on the DGX** (this dev box), not on a droplet. Local is the whole
point: the bot's reasoning runs against the **local LLM** (`citrate-llama`, 128k ctx —
private, always-on, no prompt ever leaves the machine), it has direct (sandboxed) access
to the workspace for real work, and the owner keeps physical custody of the agent and its
secrets. "Maximally capable" and "owner-only + local" are reconciled by making capability
broad but the *command surface* singular (see `05_OWNER_AUTH.md`).

## Process model

A single long-running daemon — `citrate-agent-cli daemon` (the `main.rs` TODO already
names it) — that owns three loops on one tokio runtime:

```
┌────────────────────────── hermes daemon (1 process, dedicated unix user) ──────────────────────────┐
│  Discord gateway (WebSocket, serenity)  ──▶  ingress guard ──▶ { command plane | moderation plane } │
│  agent-cron SOP scheduler               ──▶  daily research-loop, digest, queue-surfacing           │
│  capsule host runtime (wasmtime)        ──▶  skills (catalog 01) under capability manifests         │
│        │                                                                                            │
│        ├─ local LLM client  ──▶ citrate-llama @ 127.0.0.1 (reasoning, classification, drafting)     │
│        ├─ agent-code        ──▶ file/shell/git, scoped to a workspace dir (skill acquisition)       │
│        ├─ agent-chain       ──▶ on-chain anchoring of decisions (append-only trail)                 │
│        └─ subagents         ──▶ scoped per-agenda workers (09)                                      │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

The two planes (command = owner-only conversation/agendas; moderation = autonomous watch
over all members) are dispatched by the **single ingress guard** and never share an
execution path. That separation is the load-bearing security decision (ADR-H3).

## The Discord gateway adapter (net-new — the S1 core)

The repo has no Discord library. Add a `hermes-discord` crate using **serenity**
(ADR-H1): a gateway client (intents: GUILDS, GUILD_MEMBERS, GUILD_MESSAGES,
MESSAGE_CONTENT, GUILD_MODERATION) that turns gateway events into typed internal events,
and an HTTP client for actions (post, role, channel, mod) routed through capsules. The
adapter is *transport only* — it makes no decisions; every event passes the ingress guard
before anything else looks at it.

## Local LLM wiring

Hermes reasons against `citrate-llama` over `127.0.0.1` (the existing service, 128k ctx,
per the DGX llama context note). Default is **local-first** (ADR-H2): all routine
reasoning, moderation classification, and drafting stay on-box. An *optional, owner-
configured* escalation to a stronger remote model exists for hard agendas, off by default
and never used on private-channel content without owner opt-in. No secret and no
private-channel content is ever placed in a remote model's context.

## Secrets & config

- `.env.hermes` (gitignored) holds `DISCORD_BOT_TOKEN`, `OWNER_DISCORD_ID`, the guild id,
  the local LLM endpoint, channel ids (verify/research/log), and feature flags. Loaded at
  startup; never logged, never entered into LLM context, never readable by a capsule
  (filesystem capability excludes it).
- The on-chain signer reuses the repo's bundled signing tier; production swaps in the
  operator/KMS signer (mirrors the gateway).

## Host hardening (ADR-H6)

Because Hermes runs locally *with shell access*, a compromise of Hermes is a foothold on
the DGX — so it runs as a **dedicated unprivileged user**, never root, under a systemd
unit with `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome` with an explicit
read-write workspace path only, `PrivateTmp`, and no `sudo`. The `agent-code` shell
capability is bounded to that workspace, an argv-vector exec (never a shell string), with
a timeout and a command policy. There is no path from a Discord message to an
unsandboxed shell (T5/T10 in `06_THREAT_MODEL.md`).

## Supervision & lifecycle

- `systemctl --user` unit `citrate-hermes.service`, `Restart=on-failure`, journald logs.
- Health: a `doctor` subcommand (the cli already has `doctor_cmd.rs`) verifies token
  validity, gateway connectivity, LLM reachability, owner-id set, and that the ingress
  guard is fail-closed before the daemon accepts traffic.
- **Kill-switch**: an owner command and a local signal that immediately drops the gateway
  connection and freezes all action capsules (T3 — owner-account-compromise containment).
