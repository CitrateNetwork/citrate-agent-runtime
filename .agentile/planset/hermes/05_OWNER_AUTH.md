---
created: 2026-06-22T00:00:00Z
branch: feat/hermes-local-hardened
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: active
program: HERMES-L
---

# Hermes owner authorization — the command plane is singular and fail-closed

Hermes serves **exactly one principal on the command plane: the owner** (Saul). Everyone
else, when they address it, gets one response and nothing else:

> **"I don't work for you respectfully, I work for the company and Saul specifically."**

This document fixes *how* that is true so it cannot be bypassed, spoofed, or spammed.

## Two planes — do not conflate them

| | **Command plane** | **Moderation plane** |
|--|------------------|----------------------|
| who | the owner only | all members (autonomous watch) |
| what | agendas, queries, requests, tool/capsule execution | spam/raid detection, the verification gate, mod actions |
| trigger | owner addresses Hermes (DM / @mention / reply / slash) | any message/join event, no addressing needed |
| on non-owner | the refusal string, then stop | normal moderation (a non-owner is *moderated*, never *obeyed*) |

A non-owner can never make Hermes *do* anything (command plane is closed to them), but
Hermes still *watches and moderates* them (moderation plane is open over everyone). The
adversarial failure to prevent is a non-owner's message being treated as a command; the
two-plane split makes that structurally impossible — moderation never invokes a command
(ADR-H3, ADR-H4).

## The ingress guard (single chokepoint)

Every gateway event hits one function before anything else:

```
authorize(author_id) -> Principal::Owner | Principal::Other
```

- `OWNER_DISCORD_ID` (config, set at deploy) is the **only** owner identity. Authorization
  is by the immutable Discord **user id** — never username, nickname, display name, or
  role (those are attacker-controlled; ids are not). (T2 owner-impersonation.)
- **Fail-closed**: if `OWNER_DISCORD_ID` is unset, malformed, or the event lacks a
  verifiable author id (webhook, system message, integration), the principal is `Other`.
  Hermes serves *no one* until the owner id is validly configured.
- The guard runs *before* the LLM, before any tool, before any capsule. No reasoning
  path is reachable by an unauthorized principal.
- **Self-events are dropped at the adapter** (`author_id == bot_id`) before either plane,
  so Hermes never ingests or re-acts on its own posts (T17 — loops / self-injection).
- **Interactions are guarded too.** Buttons (approval-queue approve/deny), slash commands,
  and context menus re-run the guard on `interaction.member.user.id`. Channel *visibility*
  never implies authority — a non-owner who can see `#approval-queue` still cannot click
  approve (T15, ADR-H9).
- **Channel-type default-deny.** The command plane is allowed only in enumerated channel
  types (DM, guild text, thread); forums/ephemeral/unknown types default-deny until
  explicitly modeled (T-M9).
- Every decision is recorded (RecorderClient + on-chain anchor): who, when, channel, and
  the request text for owner events; the attempt metadata for `Other` events (non-owner
  command attempts are security signal).

## Per-message principal binding (closes the context back-door)

The guard on `author_id` is necessary but **not sufficient** on its own: the research-room
loop (`09`) aggregates a *thread* of messages into agenda context, and any non-owner
message that ever reaches that thread (permission drift, a mod with access, a webhook,
relayed content) would otherwise become planner input — a non-owner commanding Hermes
through the back door, bypassing the two-plane model (ADR-H3). So:

- **Every command-plane action derives from exactly one owner-authored message id.** The
  action's provenance is that single message, not "the conversation".
- **The agenda context window is filtered to owner-authored messages only** before it
  reaches the LLM/planner. Non-owner content in a command-plane thread is *data the owner
  may quote*, never instruction. (ADR-H9.)

This is the structural guarantee that the two-plane split actually holds end to end.

## Command-plane response policy (anti-spam, anti-weaponization)

The bot must not become a spam amplifier or a tool to flood a channel with refusals
(T12). So on the command plane:

- Hermes only *responds* when **directly addressed** — a DM, an @mention, or a reply to
  one of its messages. Ambient channel chatter is ignored by the command plane (still
  seen by moderation).
- A non-owner who directly addresses it gets the refusal **once per cooldown window**
  (e.g. 1 / user / 10 min); repeats within the window are silently dropped.
- The refusal is a plain message — no buttons, no tool calls, no LLM round-trip (a fixed
  string, so it cannot be prompt-injected; T1).
- In a DM, the refusal may be slightly warmer but identical in substance; the owner-only
  boundary is the same in DMs, guild channels, and threads.
- **No owner-id oracle.** Owner messages must not produce a distinguishable *public*
  side-channel — an observer must not be able to identify `OWNER_DISCORD_ID` by noticing
  who *doesn't* get refused. Owner handling that differs from non-owner handling stays in
  private surfaces (DM / the private research room) (H-A16).

## Owner-account-compromise resilience (T3)

Authorization by user id is sound against Discord-API spoofing, but not against the
owner's *account* being compromised. So owner authority is necessary but not *sufficient*
for the dangerous actions:

- **Irreversible / mass actions** (mass-ban, channel/role deletion, server-spec apply,
  capsule-certify, value transfer) require a **second factor that is not the Discord
  account** — a local-machine confirmation (terminal / a touch on the DGX) or an
  out-of-band signed token. A purely-Discord approval is *not enough*, because the
  compromised credential *is* the Discord account (the queue + delay are otherwise
  circular). The pending-action + delay state lives **off the Discord plane** and
  **persists across a daemon restart**, so an attacker cannot kill-and-restart to skip a
  delay (ADR-H7, H-A4/H-A19).
- **Anomaly detection**: a sudden burst of destructive commands, or commands at an unusual
  time/pattern, raises the bar (re-confirm) and alerts via an out-of-band channel.
- **Kill-switch**: a local signal (and a passphrase command) immediately freezes all
  action capsules and drops the gateway — recoverable only from the local machine, which
  the attacker (remote) does not have.

The principle: the owner can do anything, but the *blast radius* of a single compromised
message is bounded, and anything irreversible has a second gate.

## Delegation (post-v1, explicitly out of scope for the command plane v1)

v1 command plane is **strictly single-owner**. Later, a delegated-command roster (trusted
teammates granted *scoped, expiring, revocable* command subsets — never destructive) can
be added per the guardrails model; until then, teammates are managed entirely on the
moderation plane and have zero command authority. This is called out so "teammates" in
the server-rebuild work is never mistaken for command access.

## Acceptance (red-test-first; expanded in 06)

- A message from `OWNER_DISCORD_ID` reaches the command plane; an identical message from
  any other id returns *exactly* the refusal string and never reaches a tool/LLM.
- Unset/malformed owner id ⇒ everyone (including the real owner) is `Other` (fail-closed).
- A nickname/username change to "Saul", a webhook posting as the owner, and a role grant
  all fail to gain command access.
- The refusal is rate-limited per user; ambient (non-addressed) messages get no response.
- An irreversible owner command does not execute without the approval/confirm step.
