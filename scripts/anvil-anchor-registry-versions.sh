#!/usr/bin/env bash
# HUP-S7.1: run the own-anchor check (AnchorRegistryClient::is_anchored_by_self) against the real
# AnchorRegistry bytecode of both versions on a local anvil. Nothing here touches 40204.
#
#   legacy: the version deployed on 40204 today (citrate-chain origin/main by default);
#   next:   the version the HUP registry redeploy ships (the citrate-chain checkout given, or
#           CITRATE_ANCHOR_NEXT_REF when set).
#
# Usage: scripts/anvil-anchor-registry-versions.sh [citrate-chain checkout]
#   default: ../citrate-chain next to this repo, or CITRATE_CHAIN. Needs forge + anvil and cargo.
#   Env: CITRATE_ANCHOR_LEGACY_REF (default origin/main), CITRATE_ANCHOR_NEXT_REF (default: the
#   checkout's working tree), CARGO_TARGET_DIR as usual.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
chain="${1:-${CITRATE_CHAIN:-$repo/../citrate-chain}}"
src=contracts/src/cit_agent/AnchorRegistry.sol
[[ -f "$chain/$src" ]] || { echo "AnchorRegistry.sol not found under $chain" >&2; exit 2; }
for bin in forge anvil cargo git; do
  command -v "$bin" >/dev/null || { echo "$bin not installed" >&2; exit 2; }
done
work="$(mktemp -d "${TMPDIR:-/tmp}/anchor-versions.XXXXXX")"
trap 'rm -rf "$work"' EXIT

build() { # <name> <source file>
  local d="$work/$1"
  mkdir -p "$d/src"
  cp "$chain/contracts/foundry.toml" "$d/"
  cp "$2" "$d/src/AnchorRegistry.sol"
  ( cd "$d" && forge build --out "$d/out" --cache-path "$d/cache" src/AnchorRegistry.sol >"$d/build.log" 2>&1 ) \
    || { cat "$d/build.log" >&2; exit 1; }
  echo "$d/out/AnchorRegistry.sol/AnchorRegistry.json"
}

legacy_ref="${CITRATE_ANCHOR_LEGACY_REF:-origin/main}"
git -C "$chain" show "$legacy_ref:$src" >"$work/legacy.sol"
grep -q "isAnchoredBy" "$work/legacy.sol" && { echo "$legacy_ref already has isAnchoredBy: not the deployed version" >&2; exit 2; }
if [[ -n "${CITRATE_ANCHOR_NEXT_REF:-}" ]]; then
  git -C "$chain" show "$CITRATE_ANCHOR_NEXT_REF:$src" >"$work/next.sol"
  next_from="$CITRATE_ANCHOR_NEXT_REF"
else
  cp "$chain/$src" "$work/next.sol"
  next_from="$(git -C "$chain" rev-parse --short HEAD 2>/dev/null || echo 'working tree')"
fi
grep -q "isAnchoredBy" "$work/next.sol" || { echo "the next version ($next_from) has no isAnchoredBy" >&2; exit 2; }

legacy_art="$(build legacy "$work/legacy.sol")"
next_art="$(build next "$work/next.sol")"
echo "built AnchorRegistry: legacy from $legacy_ref ($(git -C "$chain" rev-parse --short "$legacy_ref")), next from $next_from"

cd "$repo"
CITRATE_ANCHOR_REGISTRY_LEGACY="$legacy_art" CITRATE_ANCHOR_REGISTRY_NEXT="$next_art" \
  cargo test -p citrate-agent-core --test anchor_registry_versions -- --ignored --nocapture
