---
created: 2026-06-22T00:00:00Z
branch: feat/hermes-general-purpose
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: active
program: HERMES-GP
---

# Hermes guardrails — autonomy you can hand the keys to

The owner's intent is **operator with broad autonomy**. The way to make broad autonomy
safe is not to narrow it everywhere — it is to make the boundary *crisp and per-domain*,
so Hermes moves fast where mistakes are cheap and reversible, and stops to ask where they
are not. This document fixes that boundary.

## Policy profiles (from the operating model)

| profile | can | typical use |
|---------|-----|-------------|
| **ReadOnly** | observe, summarize, propose | first-touch on any new domain |
| **Guided Builder** | act on non-destructive, reversible things within an allowlist | drafting, digesting, corpus building |
| **Operator** | act broadly within a domain; destructive/outward actions queue | the steady-state for a trusted domain |
| **Maintainer** | manage other agents / capsules | reserved to the owner-supervised path |

A profile is assigned **per domain**, not globally. Hermes can be Operator for the
corpus and Guided Builder for Discord at the same time.

## The invariant boundary (true in every profile)

These are not tunable. They are the formal boundary from the operating model:

- **No uncapped value transfer.** Every `chain_calls` grant is to a specific
  method+address with a cap; there is no "send arbitrary value" capability.
- **No uncapped filesystem.** `filesystem` is an explicit path list per capsule; no
  capsule gets the whole disk.
- **No uncapped shell.** `shell_exec` (via `agent-code`) is bounded by timeout and a
  command policy; it is never an open root shell.
- **No self-escalation.** A capsule cannot grant itself or another capsule a broader
  capability. New live capabilities come only through `capsule-certify` /
  `capability-request`, which always queue for the owner.
- **Append-only trail.** Every action is recorded (RecorderClient + on-chain anchor);
  Hermes cannot edit or delete its own history.
- **Scoped, expiring, revocable grants.** Every capability grant has a scope and a TTL
  and can be revoked from the Agent Center mid-flight.

## Per-domain autonomy

The principle, straight from the house rules: *for actions that are hard to reverse or
outward-facing, confirm first.* Outward-facing publication is the sharpest case — once a
social post or a CMS page is live, it may be cached or indexed even if deleted. So:

| domain | default profile | auto (no approval) | always queues |
|--------|-----------------|--------------------|----------------|
| **Research & Data** | Operator | fetch *vetted* sources, normalize, quality-score, train-smoke, eval-report | intake of a source whose license is **not** on the allowlist (fail-closed); any compute beyond the smoke budget |
| **Discord** | Guided Builder → Operator (after trust) | read, digest, onboard, post within rate-limit | **moderation** (timeout/kick/ban), `@everyone`, anything destructive to a member |
| **CMS & socials** | Guided Builder | draft, organize assets, maintain the calendar | **publish** and **schedule-to-live** — every outward-facing action, always |
| **Skill-acquisition** | Operator (authoring) | author candidate capsules in the sandbox, research APIs | **certify/register** a new live capability; any `capability-request` |
| **Agentile** | Operator | open/close sprints, journal, anchor work | opening PRs / creating repos (outward) |

The pattern repeats on purpose: **inward, reversible, bounded → auto; outward,
hard-to-reverse, or capability-granting → queue.** A new contributor would read this
table the same way Hermes enforces it.

## The approval queue

Anything that queues lands in the Agent Center approval queue with: the agenda it serves,
the capsule + its declared capability surface, a human-readable diff of the effect ("post
this text to #announcements", "publish this page", "grant `discord-moderate` live"), and
a one-click approve / deny / approve-with-edit. Denials are recorded with reason and feed
back into the profile (a repeatedly-denied action class can be demoted).

## Risk → required roles

A capsule's `[risk]` block already carries `required_roles`. Hermes honors them: a `high`
capsule (`discord-moderate`, `cms-publish`, `capsule-certify`) requires the owner role on
the approval; a `med` capsule may be pre-authorized within a domain's Operator grant. This
is the same RBAC the rest of the ecosystem uses (AUTHSPINE) — Hermes does not invent a
parallel permission system.

## The finished-feature bar

A Hermes capability is not "done" when it runs. It is done when it is
**seen → configured → monitored → paused → audited**: visible in the Agent Center, its
profile configurable, its actions monitored live, pausable mid-flight, and its trail
auditable after. Every capsule in the catalog is held to this bar before it is certified
live. That is what makes "broad autonomy" a position the owner can actually take.
