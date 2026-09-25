# citrate-agent-runtime

*Part of the **[Citrate Network](https://citrate.ai)** — own the means of computation. · [Docs](https://docs.citrate.ai) · [Run a node](https://citrate.ai/download) · [Contribute → free membership](https://github.com/CitrateNetwork/.github/blob/main/CONTRIBUTING.md)*

> The Citrate agent execution runtime — signed WASM "capsules" (skills), a cron/tripwire daemon, and a chain-anchored audit recorder. Hermes, the general-purpose operator agent, runs on it.

## What it is

citrate-agent-runtime is the Rust runtime that executes agent work: capsules (skills packaged as signed WASM components), a cron/tripwire daemon, and an audit recorder that can anchor every approve/deny decision on chain (chain **40204**). **Hermes** is the general-purpose operator agent that runs on it — a Discord-fronted, owner-gated agent (`hermesd`) whose transport layer only normalizes events while all authorization and routing decisions live in a fail-closed core.

Agents authenticate against [citrate-identity](https://github.com/CitrateNetwork/citrate-identity) (OIDC), call an LLM endpoint for inference, and anchor decisions to the on-chain decision registry for an auditable trail. Concept overview: https://docs.citrate.ai/apps.

## Prerequisites

Pure Rust / Cargo workspace — no Node, no Python.

```bash
# Rust stable (pinned by rust-toolchain.toml) + rustfmt/clippy
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup component add rustfmt clippy

# To build capsules (WASM components):
rustup target add wasm32-unknown-unknown
cargo install cargo-component

# Runtime: a local Ollama (or OpenAI-compatible llama-server) for inference;
# optional EVM RPC node for on-chain anchoring; Linux systemd for the deploy unit.
```

**SSH host-alias setup is a hard prerequisite**: `agent/core` pulls `citrate-wallet-core` from `CitrateNetwork/citrate-chain` via `ssh://git@github-citrate-chain/...`. `github-citrate-chain` is an alias, not a DNS host — map it to `github.com` with a deploy key, then verify:

```bash
scripts/setup-ssh-alias.sh [PATH_TO_KEY]     # default key ~/.ssh/id_ed25519 (idempotent)
ssh -T git@github-citrate-chain              # should authenticate to GitHub
```

`.cargo/config.toml` sets `git-fetch-with-cli = true` so cargo uses system git (which reads `~/.ssh/config`).

## Build from source

```bash
git clone git@github.com:CitrateNetwork/citrate-agent-runtime.git
cd citrate-agent-runtime

cargo build --release
```

Binaries land in `target/release/`:

| Binary | Crate | Purpose |
|---|---|---|
| `citrate-agent` | `agent/cli` | the CLI (`doctor`, `connect`) |
| `hermesd` | `hermes/discord` | the Hermes Discord daemon |
| `citrate-agent-sidecar` | `agent-sidecar` | keyless HTTP sidecar (loads capsules) |
| `citrate-tripwire-daemon` | `agent-cron` | cron/tripwire daemon |

Build capsules with `cargo component build --target wasm32-unknown-unknown`, then pack with `cit-capsule-pack`.

## Run locally

**CLI** — verify the build and run a preflight pass:

```bash
cargo run --release --bin citrate-agent -- --help
cargo run --release --bin citrate-agent -- doctor       # preflight/monitoring checks
```

**Sidecar** — the only HTTP server; it binds a required loopback address and needs a bearer-token file (fails closed if unset):

```bash
export CITRATE_HERMES_ADDR=127.0.0.1:19700
export CITRATE_HERMES_TOKEN_FILE=./hermes.token         # 0600 file containing the bearer token
export CITRATE_HERMES_CAPSULES=./capsules
cargo run --release --bin citrate-agent-sidecar
```

**Hermes daemon** — a Discord gateway client (it does not open a listening port):

```bash
cp .env.hermes .env.local        # then EDIT: set your own DISCORD_BOT_TOKEN + OWNER_DISCORD_ID
set -a && source .env.local && set +a
target/release/hermesd
```

> The committed `.env.hermes` is a template — replace its placeholder token with your own before use; never ship a real token.

## Connect it locally

Hermes is **owner-gated and fails closed**: with `OWNER_DISCORD_ID` unset it recognizes no one as owner and serves nobody until configured. To wire the runtime to a local stack:

1. **Inference (LLM)** — Hermes calls an OpenAI-compatible endpoint. Point it at a local Ollama:

   ```bash
   export HERMES_LLM_ENDPOINT=http://127.0.0.1:11434     # local Ollama (default)
   export HERMES_LLM_MODEL=qwen2.5:72b
   ```

2. **Identity / auth (memory gateway)** — the CLI `connect` flow mints a connect token via OIDC. Point it at local services:

   ```bash
   cargo run --release --bin citrate-agent -- connect \
     --issuer http://localhost:3000 \
     --gateway http://localhost:8090
   # defaults: --issuer https://auth.citrate.ai  --gateway https://mem-gateway.citrate.ai
   # writes ~/.config/citrate/memory.json (0600)
   ```

3. **Chain anchoring (chain 40204)** — build with `--features anchor` and point at a local node from [citrate-chain](https://github.com/CitrateNetwork/citrate-chain):

   ```bash
   export HERMES_RPC_URL=http://127.0.0.1:8545          # default
   export HERMES_DECISION_REGISTRY=<AgentDecisionRegistryV2 address on 40204>
   ```

   Every approve/deny decision is then anchored to the on-chain registry.

For the full multi-repo bring-up see `LOCAL_STACK.md` in [citrate-docs](https://github.com/CitrateNetwork/citrate-docs).

## Configuration

No `.env.example`; the committed template is `.env.hermes` (edit it, don't ship it). Key variables:

| Variable | Default | Purpose |
|---|---|---|
| `DISCORD_BOT_TOKEN` | — (required for Hermes) | Discord bot token |
| `OWNER_DISCORD_ID` | — (unset ⇒ no owner) | the single owner user id (owner-gating) |
| `HERMES_LLM_ENDPOINT` | `http://127.0.0.1:11434` | OpenAI-compatible LLM endpoint |
| `HERMES_LLM_MODEL` | `qwen2.5:72b` | model id |
| `HERMES_RPC_URL` | `http://127.0.0.1:8545` | EVM RPC for anchoring (chain 40204) |
| `HERMES_DECISION_REGISTRY` | — | `AgentDecisionRegistryV2` address |
| `CITRATE_HERMES_ADDR` | — (required) | sidecar loopback bind |
| `CITRATE_HERMES_TOKEN_FILE` | — (required) | 0600 bearer-token file for the sidecar |
| `CITRATE_HERMES_CAPSULES` | `./capsules` | capsule (skill) directory |

Chain id `40204` is compiled in. **Capsules = skills**: each is a directory under `capsules/` with a `manifest.toml` (declaring capabilities, data class, risk tier, provenance/publisher DID, signing tier), a signed `.cps` archive, a WIT world, and gherkin features. A signed capsule runs only if its `(name, version, content_hash)` is on the fleet allowlist compiled into the runtime (`agent/core/src/capsule/allowlist.rs`, with a per-capsule version floor); re-packing a capsule means adding its new hash there. Test-only capsules live under `test-fixtures/capsules/`, not in the shipped fleet.

## Links

- Docs: https://docs.citrate.ai/apps
- Depends on: [citrate-chain](https://github.com/CitrateNetwork/citrate-chain) (`citrate-wallet-core`, RPC, chain 40204) · [citrate-identity](https://github.com/CitrateNetwork/citrate-identity) (OIDC) · Consumed by: [citrate-studio](https://github.com/CitrateNetwork/citrate-studio) (agent-core seam)
- Contributing (DCO): CONTRIBUTING.md · Security: SECURITY.md · License: LICENSE

## License

Licensed under the Apache License, Version 2.0 (see [`LICENSE`](LICENSE)). This is the open-source infrastructure tier of Citrate's open-core model. The commercial application layer is source-available under BUSL-1.1. Licensor: Citrate Inc.
