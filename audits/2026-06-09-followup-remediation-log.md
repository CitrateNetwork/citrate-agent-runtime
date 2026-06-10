---
created: 2026-06-10T00:00:00Z
branch: audit/secrem02-capsule-bomb
author: Fable 5 (Claude Code)
sprint: SECREM-02-followup-remediation
status: active
repo: citrate-agent-runtime
baseline_test_count: 225
---

# citrate-agent-runtime — SECREM-02 Remediation Log

> Coverage matrix: `citrate-security/planset/2026-06-10-followup-remediation.md`.
> Protocol: re-verify → red test → fail-closed fix → suite green → mutation pass.

## Phase 3 — WP 3.4 (capsule integrity)

| Finding | Sev | Red test(s) | Fix (file) | Suite (≥225?) | Mutation | Disposition |
|---|---|---|---|---|---|---|
| FUA-AGENT-RUNTIME-01 | Med | `capsule::archive::tests::read_archive_caps_decompression_bomb` | `read_archive` caps total DECOMPRESSED bytes (`MAX_DECOMPRESSED_BYTES` = 256 MiB) via `decoder.take(..)` before any hash/sig check — a `.cps` bomb fails closed instead of OOM. Injectable cap (`read_archive_capped`) for the test — `agent/core/src/capsule/archive.rs` | 226 ✓ | killed (remove cap → bomb test FAIL) | **FIXED** |

## Remaining WP 3.4 — the capsule-load CRITICAL re-open (DEFERRED, breaking change)

These three are a **coordinated breaking capsule-format change** and were
deliberately NOT attempted at the tail of a long session — rushing them risks
bricking the loader / leaving fixtures inconsistent. Scoped for a fresh pass,
in this order (per the sprint's "version + re-sign → enforce" rule):

1. **prior -003 (HIGH)** — fold `manifest.toml` into the signed `content_hash`
   (`pack.rs` / `tiers.rs` hash domain). Today a validly-signed capsule's
   capabilities / risk-tier / required-roles can be swapped post-signature.
2. **(b)** re-sign all test fixtures + **bump the capsule format version**.
3. **prior -001 (CRITICAL)** — close the loose-directory WASM fallback
   (`dispatch.rs:175-198`): require a publisher signature on *every* load path,
   not just the `.cps` archive path; delete the `content_hash`-only gate (the
   hash is attacker-computable).
4. **FUA-AGENT-RUNTIME-02 (Low)** — stop `cit-capsule-pack` minting + persisting
   a signing key to a working-tree dotfile (overlaps KEYSAFE).

## Notes
- Baseline (Phase 0): **225** → **226** (+1 bomb test, mutation-proven).
- `read_archive_capped(reader, max)` added so the cap is testable with a tiny
  fixture (a real bomb is a tiny zstd payload expanding to GBs).
- Branch: `audit/secrem02-capsule-bomb`.
