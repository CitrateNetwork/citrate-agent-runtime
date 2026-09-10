---
created: 2026-06-22T00:00:00Z
branch: feat/hermes-local-hardened
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: active
program: HERMES-L
---

# Hermes server rebuild — Discord as declarative, reviewable infrastructure

Hermes will rebuild and harden the server. Rebuilding a live Discord by imperative,
one-off API calls is how servers get accidentally destroyed. So the server is treated as
**infrastructure-as-code**: a declarative spec, a dry-run diff, an owner approval, an
idempotent apply, and a backup taken first (ADR-H5). Nothing destructive happens without
the owner seeing exactly what will change.

## `server-spec.toml` — the desired state

A single owner-owned spec describing the target server:

```toml
[guild]
verification_level = "high"          # Discord native gate (verified email/phone)
explicit_content_filter = "all"
default_notifications = "mentions"

[[role]]                              # ordered = hierarchy
name = "owner"   ; color = "#E0A100" ; hoist = true ; permissions = ["Administrator"]
[[role]]
name = "admin"   ; permissions = ["ManageChannels","ManageRoles","KickMembers","BanMembers","ModerateMembers"]
[[role]]
name = "mod"     ; permissions = ["ModerateMembers","ManageMessages","KickMembers"]
[[role]]
name = "teammate"; permissions = ["SendMessages","ReadMessageHistory","Connect"]
[[role]]
name = "verified"; permissions = ["SendMessages","ReadMessageHistory"]
[[role]]
name = "quarantine"; permissions = []   # sees only #verify

[[category]]
name = "ops (private)"
[[category.channel]]
name = "hermes-research" ; type = "text" ; private = true   # owner + hermes only (09)
[[category.channel]]
name = "approval-queue"  ; type = "text" ; private = true
[[category.channel]]
name = "audit-log"       ; type = "text" ; private = true

[[category]]
name = "gateway"
[[category.channel]]
name = "verify" ; type = "text" ; overwrite = "quarantine:view+react-only"

# ... public categories, each channel with least-privilege overwrites ...
```

## Reconcile loop (the only way changes happen)

```
read current guild  ──▶  diff(current, spec)  ──▶  human-readable PLAN
                                                      │
                          owner reviews in #approval-queue (per-change approve/deny)
                                                      │
                              backup current guild structure to audit-log + disk
                                                      │
                                   apply approved changes idempotently
                                                      │
                                      record result on the trail + on-chain
```

- **Dry-run first, always.** The plan reads like a migration: `+ create role "verified"`,
  `~ channel #general overwrite @everyone -SendMessages`, `- delete channel #old` (deletes
  flagged in red, requiring explicit per-item confirm).
- **Snapshot + rehash (no TOCTOU).** The diff is computed against a pinned snapshot of the
  guild (hashed); immediately before apply, the live guild is re-read and the hash
  re-checked — **any drift aborts the apply** (T19). The guild can change between approval
  and execution, and a stale diff must never apply (H-A7).
- **Idempotent.** Re-applying a satisfied spec is a no-op; the spec is the source of truth
  and can be re-run after drift.
- **Backup-first, off-Discord.** The current structure (roles, channels, overwrites) is
  exported to **disk / the off-box secret store** before any apply — never into a Discord
  channel, which the very destruction it guards against would erase (H-A15).

## Safety invariants (T14)

- Never delete or de-permission the **owner role** or the **bot's own role**; never remove
  the owner from any role that retains their access. These invariants are bound to
  **immutable snowflake ids**, not role names or positions (which an attacker can collide
  or reorder to mis-target a destructive op) (T19, H-A7).
- Always preserve an **admin escape hatch** (the owner keeps `Administrator` out-of-band).
- Destructive diffs (delete channel/role, mass-overwrite) require explicit per-item owner
  confirm — they never ride along with additive changes on a single "approve all".
- The reconcile runs under elevated Discord permissions that are **invited only for the
  rebuild window** and matched to the spec's needs (Manage Channels/Roles/Guild), not the
  steady-state Guided-Builder set. Elevated invite = a separate, owner-approved step.

## Permission-flow design (the hardened target)

A clean hierarchy and least-privilege overwrites: `owner > admin > mod > teammate >
verified > quarantine > @everyone`. `@everyone` cannot post anywhere except `#verify`
until they pass the gate (08); verified members get the public channels; teammates get the
collaboration channels; ops channels are owner+hermes only. Native Discord
`verification_level = high` + `explicit_content_filter = all` are set as a baseline before
the custom gate even runs.

## Acceptance

- A dry-run produces a correct, readable diff and changes nothing.
- Apply is idempotent (second run = no-op).
- A spec that would delete the owner role or all channels is refused with the reason; a
  backup exists before any apply; the owner never loses access (T14 green).
