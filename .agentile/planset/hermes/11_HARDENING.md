---
created: 2026-06-22T00:00:00Z
branch: feat/hermes-local-hardened
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: active
program: HERMES-L
---

# Hermes hardening log — adversarial review round 1

An independent adversarial review was run over `04`–`10` + `decisions.md` before any code.
This log records every finding, its severity, and the adopted resolution (which doc/ADR/
threat-row/sprint now carries it). The threat table in `06` is the canonical list; the new
rows **T15–T22** below come from this round. Findings are kept even after resolution so the
reasoning is traceable.

## Critical — fix before any code

| id | finding | resolution | lands in |
|----|---------|-----------|----------|
| **H-A1** | **Command-plane context contamination.** The ingress guard checks `author_id`, but the research-room loop (`09`) aggregates a *thread of messages* into the agenda context. Any non-owner message that reaches that thread (permission drift, a mod with access, a webhook, Hermes's own relayed posts) becomes planner input — command execution by a non-owner through the back door. The two-plane model (ADR-H3) is the load-bearing decision and this bypasses it. | **Per-message principal binding:** every command-plane action derives from exactly one owner-authored message id. The research-thread context window is **filtered to owner-authored messages only** before it reaches the LLM/planner. (ADR-H9.) | `05`, `09`, ADR-H9 |
| **H-A2** | **Interaction buttons aren't principal-checked.** The approval-queue approve/deny are Discord component interactions; "owner+hermes-only channel" implies authority by *visibility*, which is wrong. `05` lists "slash" but interactions are a separate auth surface (interaction tokens, ephemeral). | Every interaction (button/slash/context-menu) **re-runs the ingress guard on `interaction.member.user.id`**; channel visibility never implies authority. | `05`, T15 |
| **H-A3** | **Self-event loop / self-injection.** With MESSAGE_CONTENT the bot receives its own posts; the research loop ingests its own thread posts; moderation could classify its own output — loops + re-entry of summarized injection as data. | **Hard-drop events where `author_id == bot_id` at the adapter**, before either plane. | `04`, `05`, T17 |

## High

| id | finding | resolution | lands in |
|----|---------|-----------|----------|
| **H-A4** | **Owner-account compromise gate is circular** (T3/ADR-H7): the approval queue + delay are operated *in Discord by the owner principal*, which is the compromised credential. | Irreversible/mass actions require a **second factor that is not the Discord account** — a local-machine confirmation (terminal/touch) or out-of-band signed token. Kill-switch/delay state lives **off the Discord plane**. | ADR-H7 (rev), `05` |
| **H-A5** | **Injection via fetched/digested/research content**, which *do* reach tool/queue/publish-capable loops (T1/ADR-H4 only scoped the no-tools rule to moderation). | "**Data, never instructions**" extended to *all* ingested content (read, fetch, digest, research, restored memory). Research/content reasoning emits **typed intents → owner queue**, never direct action. | ADR-H4 (rev), T22, `09` |
| **H-A6** | **Secret exfil via process env/memory, not the file path** (T8 guarded the `.env` *path* only). Token sits in `serenity` in-process; a "print the env" agenda or a `/proc/self/environ` read surfaces it. | **Zeroize the token out of the process environment after load** (hold in a non-env secret cell); capsule manifests block `/proc/self/environ` + process-memory; an **outbound redaction filter** scrubs all LLM- and channel-bound strings. | T20, ADR-H6 (rev), `04` |
| **H-A7** | **TOCTOU: diff→apply gap** in server-rebuild (`07`) and **author→certify→run gap** in skill-acquisition (`09`). Guild/artifact state mutates between approval and execution; name/position-based role targeting mis-fires. | **Snapshot + rehash** guild/artifact state immediately before apply; **abort on drift**. Bind every safety invariant to **immutable snowflake ids** (not names/positions) and certify a **content hash** of the exact artifact. | T19, `07`, ADR-H5 (rev) |
| **H-A8** | **Moderation auto-action weaponization** (T6): "known-scam string" and "repeated identical message" auto-timeout the *innocent* — a user quoting/reporting a scam string, or baited into reposting. Verified members (not on the allowlist) are the target. | Auto-timeout requires **signal AND untrusted-sender AND not-a-quote/report/code-block context**; quoted/code-blocked denylist strings are non-actionable; the repeated-message signal excludes replies/quotes. | `08` (rev), T6 |
| **H-A9** | **Message-edit-after-clear** (M1): classify on CREATE, author edits to scam after passing. | **Re-classify on `MESSAGE_UPDATE`**; post-clear edits are fresh events. | `08`, T16 |
| **H-A10** | **Daemon DoS / fail-open under flood** (M5): one local-LLM classification per message saturates the DGX; moderation falls behind and effectively fails open. | **Global ingress + classification rate-limit** with explicit **fail-closed backpressure** (overflow → quarantine/queue, never → allow). | T18, ADR-H10 |

## Medium

| id | finding | resolution | lands in |
|----|---------|-----------|----------|
| **H-A11** | **Supply chain** (M7): `serenity` + transitive deps sit inside the process holding token+signer; a poisoned **memory-graph** replays attacker intent on restart. | Pin + vendor + `cargo-audit`/`cargo-vet` gate on `serenity` and deps; **restored memory-graph state is re-validated as data through the guard**, not trusted resumed intent. | ADR-H11, `09` |
| **H-A12** | **Confused deputy in the queue** (T11/M10): owner approves a well-labeled item whose *parameters* came from injected data. | Queue entries show the **full concrete effect** (exact role/channel/user snowflake ids + exact permission delta), not a label/summary; approval is over the effect. | `09`, T11 (rev) |
| **H-A13** | **Structured-output trust** (M6): model can emit a valid label with manipulated confidence, or free-text `reason` rendered to a human carries injection; shared model state between command + moderation reasoning. | Strict-validate the output schema (label enum + numeric confidence range); **never render model free-text into an action or unescaped to a channel**; isolate moderation-model state from command-model state. | `08`, ADR-H4 (rev) |
| **H-A14** | **Threshold values undefined** (U2/U3): "mass-action", strike escalation, and raid `N joins/M sec` are examples not values; an attacker tunes just under. **Raid mode is itself a DoS** (locks out real new joiners) with no de-escalation. | Thresholds are **explicit config parameters with defaults + rationale**; add **raid-mode de-escalation criteria**; add **raid-mode-as-verification-DoS** as a named residual risk. | `08`, T7 (rev) |
| **H-A15** | **Discord-channel "backup" is theater** (U7): backing guild structure into `#audit-log` is destroyed by the destruction it guards. | The **only** backup is **off-Discord** (disk/off-box, with the secret store); the channel copy is dropped. | `07` (rev) |
| **H-A16** | **Refusal oracle** (B6): "absence of refusal" identifies the owner id by elimination in shared channels. | Owner messages produce **no distinguishable public side-channel**; refusal/no-refusal must not let observers identify `OWNER_DISCORD_ID`. | `05` |
| **H-A17** | **Channel-type quirks** (M9): forums, ephemeral, thread auto-archive confuse principal attribution. | Enumerate channel types; **default-deny the command plane** in any channel type not on an allowlist. | `05` |
| **H-A18** | **Mod queue visibility contradiction** (U6): queue is "owner+hermes only" (`07`) but mods need appeal visibility (`08`); if mods can see it, H-A2 bites. | Appeals get a **separate mod-visible view** that is **read-only**; only owner-principal interactions can approve/deny (H-A2). The queue's *action* surface stays owner-only. | `07`/`08`/`09` reconciled |
| **H-A19** | **Kill-switch / restart semantics** (U5): can an attacker kill+restart to skip the irreversible-action delay? In-flight reconcile rollback undefined. | Pending destructive actions + their delays **persist across restart** (off-Discord state); a restart never advances or skips a delay; in-flight reconcile apply is transactional/resumable or rolls back. | ADR-H7 (rev), `04` |

## New threat rows (added to `06`)

- **T15** interaction-token auth (buttons/slash not principal-checked) → H-A2
- **T16** message-edit-after-classification → H-A9
- **T17** self-authored-event loop / self-injection → H-A3
- **T18** daemon DoS → fail-open under flood → H-A10
- **T19** TOCTOU diff→apply / author→certify→run → H-A7
- **T20** secret exfil via process env/memory (not file path) → H-A6
- **T21** supply chain + poisoned restored memory → H-A11
- **T22** injection via fetched/digested/research content into tool-bound loop → H-A5

## Process

Round 1 complete (this log). The `HERMES-L-HARDEN-A` checkpoint (`10`) re-runs the full
`hermes-redteam` suite over T1–T22 + an independent review of the S1–S2 diff before any
member-facing power ships; a second review gates S4. New rounds append here.
