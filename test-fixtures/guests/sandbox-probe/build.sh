#!/usr/bin/env bash
# Rebuild the HUP-S2.5 sandbox probe fixture (capsule.wasm) from guest/.
# Needs the wasm32-wasip2 Rust target: rustup target add wasm32-wasip2
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here/guest"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$here/guest/target}" \
  cargo build --release --target wasm32-wasip2
cp "${CARGO_TARGET_DIR:-$here/guest/target}/wasm32-wasip2/release/sandbox_probe.wasm" "$here/capsule.wasm"
shasum -a 256 "$here/capsule.wasm"
