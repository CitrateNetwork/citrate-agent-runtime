---
created: 2026-05-18T05:10:00Z
branch: main
author: monorepo-split
status: active
split-from-monorepo-at: b3ccd5c7
split-from-monorepo-tag: pre-split-v0.4.0
archived-monorepo: https://github.com/CitrateNetwork/citrate-monorepo-archive
agentile-archive: https://github.com/CitrateNetwork/citrate-agentile-archive
---

# citrate-agent-runtime

Citrate agent execution runtime — capsules, cron daemon, chain-anchored audit recorder, and the legacy agent surface.

## Crates

| Path | Crate | Role |
|---|---|---|
| `agent/cli` | `citrate-agent-cli` | Agent CLI entry-point |
| `agent/core` | `citrate-agent-core` | RecorderClient + audit + chain signing primitives |
| `agent-chain` | `citrate-agent-chain` | On-chain agent registry + decision recording |
| `agent-cron` | `citrate-agent-cron` | Cron daemon driving recurring agent jobs |
| `agent-code` | `citrate-agent-code` | Code-execution capsules + sandboxing |
| `agent-legacy` | `citrate-agent-legacy` | Legacy agent surface, kept for back-compat during transition |
| `capsules/` | (data) | Pre-built capsule manifests / payloads (not Rust crates) |

## Chain dependency

`agent/core` consumes `citrate-wallet-core` from `CitrateNetwork/citrate-chain` via SSH git dep:

```toml
citrate-wallet-core = { git = "ssh://git@github.com/CitrateNetwork/citrate-chain", branch = "main" }
```

Swap to crates.io semver dep when chain publishes after its first audited release.

### CI requires `CHAIN_DEPLOY_KEY` secret

A read-only SSH deploy key for `citrate-chain` is injected via `webfactory/ssh-agent`. The private key is stored as the `CHAIN_DEPLOY_KEY` repo secret.

## Quick start

```bash
cargo build --release
cargo run --release --bin citrate-agent-cli -- --help
```

## Repository context

Split from the Citrate monorepo on 2026-05-18 via `git filter-repo`, preserving 219 commits of per-file history.

- **Monorepo archive**: https://github.com/CitrateNetwork/citrate-monorepo-archive
- **Agentile archive**: https://github.com/CitrateNetwork/citrate-agentile-archive
- **Chain**: https://github.com/CitrateNetwork/citrate-chain

## License

[MIT](LICENSE).
