---
created: 2026-06-22T00:00:00Z
branch: feat/hermes-local-hardened
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: active
program: HERMES-L
---

# Hermes subagents & the research room — where the owner hands off agendas

## The research room (the owner's I/O surface)

`#hermes-research` is a private channel (owner + Hermes only, per the server spec). It is
the primary command-plane surface:

- The owner posts an **agenda** ("build the NAT philosophy shard", "draft this week's
  socials", "rebuild #community"). Hermes opens a **thread per agenda**, and works there.
- In the thread Hermes plans (opens a sprint via the agentile pack), reports progress,
  posts intermediate artifacts, and **surfaces the approval queue inline** — anything
  gated shows up as an approve/deny right where the work is.
- The owner adds **intent and direction** any day; the thread is the running record. This
  is the "manage it daily, add thoughts and intent" loop the owner wanted.
- Durable memory: each agenda's state persists via the **citrate-memories** knowledge
  graph (the MCP), so a fresh context — or Hermes after a restart — picks up exactly where
  it left off. The planset + memory is how "once we clear context, you know what to do"
  holds. **Restored memory is re-validated as data through the guard** on resume, never
  trusted as resumed *intent* — a poisoned store cannot replay attacker actions (T21,
  ADR-H11).
- Only **owner-authored** messages in a research thread enter the agenda context window
  (ADR-H9); non-owner content (if any drifts in) is quotable data, never instruction.

`#approval-queue` and `#audit-log` are supporting private channels. Queue entries show the
**full concrete effect** — exact role/channel/user snowflake ids and the exact permission
delta, not a label or summary — so the owner approves the *effect*, not a description an
injection could have shaped (T11, H-A12). Only **owner-principal interactions** can
approve/deny (the buttons re-run the guard, T15); mods get a **read-only** appeal view, not
the action surface (resolves the queue-visibility tension, H-A18). The `#audit-log` is
append-only.

## Subagent topology

Hermes is a **supervisor** that routes agendas to scoped subagents. A subagent is a
capsule with `subagent_spawn` and a **narrow capability surface** matched to its job — it
gets the access it needs and nothing more. The supervisor aggregates results and owns the
owner conversation.

```
                       ┌─────────── Hermes supervisor (command plane, owner I/O) ───────────┐
                       │  routes agendas · aggregates · owns the approval queue & trail       │
                       └───────┬───────────────┬───────────────┬───────────────┬────────────┘
                               ▼               ▼               ▼               ▼
                    moderation-watch     research          content         server-ops
                    (always-on)          (NAT data R&D)    (CMS/socials)   (rebuild/reconcile)
   caps:  read guild + mod actions   read+fetch+corpus   draft+schedule    manage chan/role
          (08, high-precision auto)  (01 domain A)       (01 domain C,     (07, elevated,
                                                          publish queued)   owner-gated, windowed)
```

- **moderation-watch** — always-on, narrow: read events + the high-precision auto-mod
  actions from 08; everything else to the supervisor's queue.
- **research** — the NAT corpus engine (domain A capsules); broad read + corpus-staging
  write, no Discord-action caps.
- **content** — drafting + calendar; publish/schedule **queued** (domain C).
- **server-ops** — the reconcile engine (07); elevated Discord caps, **spawned only during
  an owner-approved rebuild window**, then torn down. It does not run steady-state.

Each subagent's grant is **scoped, expiring, and revocable** (guardrails 02): a subagent
cannot exceed its capsule manifest, cannot spawn beyond its own grant, and is visible /
pausable in the Agent Center. The supervisor is the only component on the command plane;
subagents act under delegated, bounded authority and report back.

## Skill acquisition in the loop

When an agenda needs a skill no subagent has, the supervisor runs the meta loop (01
domain D): `capsule-author` scaffolds a candidate in the sandbox (auto), then
`capsule-certify` **queues** for the owner before the new capability is live. So Hermes
can take on genuinely new agendas without a human pre-building every tool — but it can
never grant *itself* a new live power unattended.

## Acceptance

- The owner posts an agenda in `#hermes-research`; Hermes opens a thread, plans it, and
  drives it, surfacing any gated step in `#approval-queue`.
- A subagent cannot act outside its capsule's declared capability surface (tested).
- `server-ops` exists only inside an approved rebuild window and is torn down after.
- Agenda state survives a daemon restart (memory-graph persistence).
