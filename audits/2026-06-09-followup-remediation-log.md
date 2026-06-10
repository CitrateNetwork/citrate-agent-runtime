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

## WP 3.4 — capsule-load CRITICAL re-open (DONE)

| Finding | Sev | Red test(s) | Fix | Mutation | Disposition |
|---|---|---|---|---|---|
| prior-003 | High | `archive::tests::content_hash_binds_manifest_fields` + both round-trip tests | `compute_content_hash` now binds `manifest.toml` (its self-referential `content_hash` field zeroed) under a **v2 domain tag**; `pack.rs` hashes the manifest too. A signed capsule's capabilities/risk-tier/roles can no longer be swapped post-signature — `archive.rs`, `pack.rs` | killed (drop manifest from hash → test FAIL) | **FIXED** |
| re-sign + version bump | — | `shipped_fleet_loads_verified_no_override`, `load_full_fleet` | v2 domain tag fails pre-v2 (body-only) hashes closed; the 10-capsule in-tree fleet re-packed with `cit-capsule-pack` (PUBKEY unchanged = `4a4a0c85…` = `BUNDLED_PUBLISHER_KEY`) | — | **FIXED** |
| prior-001 | **Crit** | `dispatch::tests::loose_dir_with_matching_hash_is_still_unverified` | The loose-dir fallback no longer runs unsigned WASM: a loose dir (no publisher signature) is **always** `unverified` and `call_raw` refuses it — even when its self-computed `content_hash` matches. Removed the attacker-controllable `capsule_body_verified`/`is_placeholder_content_hash` helpers — `dispatch.rs` | killed by the new test (old code → "verified") | **FIXED** |
| FUA-AGENT-RUNTIME-02 | Low | (behavior change) | `cit-capsule-pack` no longer mints a signing key into the working tree — it requires `CITRATE_CAPSULE_SIGNING_SEED` (env or pre-existing gitignored file) and exits with instructions otherwise — `bin/cit-capsule-pack.rs` | — | **FIXED** |

## Notes
- Baseline (Phase 0): **225** → **226** (+1 bomb test, mutation-proven).
- `read_archive_capped(reader, max)` added so the cap is testable with a tiny
  fixture (a real bomb is a tiny zstd payload expanding to GBs).
- Branch: `audit/secrem02-capsule-bomb`.
