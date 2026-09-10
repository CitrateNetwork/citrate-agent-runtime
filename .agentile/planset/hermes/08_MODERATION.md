---
created: 2026-06-22T00:00:00Z
branch: feat/hermes-local-hardened
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: active
program: HERMES-L
---

# Hermes moderation — gate the door, bias toward not punishing the innocent

Moderation is the moderation plane (05): autonomous over **all** members, never taking
commands from them. Its governing bias: **auto-act only on high-precision signals; queue
everything ambiguous.** A false positive bans a real member — costlier than a missed
borderline case that a human reviews. The owner and mods are never actionable by auto-mod.

## Onboarding / verification gate

```
member joins
   │
   ├─ assign  quarantine  (sees only #verify; no other channel)
   │
   ├─ risk score: account age, avatar/default, join velocity, prior-ban lists
   │      low  ──▶ challenge: react-to-agree-rules OR a button captcha
   │      high ──▶ stricter: button captcha + short hold + owner/mod approve
   │
   ├─ pass  ──▶ assign verified, drop quarantine, post a welcome, log
   └─ fail/timeout (e.g. 24h) ──▶ stays quarantined; owner/mod can purge stale quarantine
```

Teammates: the owner (or an admin) grants the `teammate` role; teammate onboarding is a
lighter, owner-initiated path (no captcha), but teammates are **not** exempt from raid
lockdown or spam heuristics — trust reduces friction, it does not disable safety.

## Anti-raid

A join-rate above a threshold trips **raid mode**: every new join is auto-quarantined
regardless of risk score, the `#verify` gate tightens, the owner is alerted out-of-band,
and (optionally, owner-pre-authorized) the guild's native verification level is raised for
the duration. Raid mode never touches *existing* members.

All thresholds (`raid_joins_per_window`, `raid_window_secs`, `mass_action_user_count`,
`strike_escalation_counts`, the auto-mod precision cutoffs) are **explicit config
parameters with documented defaults and rationale**, not hardcoded examples — otherwise an
attacker tunes activity to just under a hidden line (H-A14). Raid mode has explicit
**de-escalation criteria** (join-rate back under threshold for a cool-down window) and a
manual owner override, because raid mode *is itself a verification-DoS* against legitimate
new joiners — a named residual risk (H-A14): triggering it on purpose locks the door on
real users, so its duration is bounded and owner-visible.

## Spam / scam handling

| signal | precision | action |
|--------|-----------|--------|
| known scam string / malicious link (allowlist+denylist), **untrusted sender, not quoted/reported/code-blocked** | high | auto-delete + auto-timeout, log |
| mass-mention (@everyone / many users) by non-mod | high | auto-delete + strike, log |
| repeated identical message across channels, **excluding replies/quotes** | high | auto-timeout, log |
| new account + first message has links | medium | **queue** for review (don't auto-ban) |
| heuristic "looks off" / borderline toxicity | low/med | **queue**; never auto-ban |

**Context-awareness is mandatory (T6, H-A8).** A denylist string that is *quoted*,
*code-blocked*, or part of a *report/warning* ("don't click scam-domain.com") is **not
actionable** — auto-timeout requires `signal AND untrusted-sender AND not-quote/report`.
Otherwise an attacker weaponizes auto-mod against the innocent by baiting them into
quoting or reposting. **Re-classify on `MESSAGE_UPDATE`** so an edit-after-clear (benign →
pass → edited to scam) is caught as a fresh event (T16, H-A9). Classification is
strict-validated structured output (label enum + numeric confidence); the model's free
text is never rendered into an action (H-A13).

A per-user **strike** ledger escalates repeat offenders (warn → timeout → queue-for-kick),
all recorded. Auto-actions stop at **timeout/delete**; **kick** is queued unless raid mode;
**ban** is always queued for the owner unless it's a denylist-confirmed scam account.

## Hard invariants (T6)

- Auto-mod **never** actions the owner or any `mod`/`admin`/`teammate` (allowlist check
  before any action).
- Every auto-action is **reversible**, **logged** (append-only + on-chain anchor), and has
  an **appeal** path (a member can contest in `#verify`; the owner sees it in the queue).
- Mass-actions (touching many users at once) always require owner approval — no auto path
  can punish a crowd.
- Classification runs as **structured output with no tools bound** (T1): the model returns
  `{label, confidence, reason}`, and a deterministic policy maps label→action. The model
  never directly issues a moderation action.

## Audit & transparency

Every moderation event lands in `#audit-log` (human-readable) and on the trail
(machine/auditable): member, signal, action, reversibility, appeal status. The owner can
ask Hermes in the research room for a moderation summary at any time.

## Acceptance

- A clean new member completes the gate and gets `verified`; a quarantined member sees
  only `#verify`.
- A burst of joins trips raid mode; existing members are untouched (T7 green).
- Crafted scam/spam is auto-handled at timeout/delete level; borderline content queues;
  owner/mods/teammates are never auto-actioned; a report-bomb does not produce an auto-ban
  (T6 green).
- Every action is logged, reversible, and appealable.
