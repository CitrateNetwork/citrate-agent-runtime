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

`agent/core` consumes `citrate-wallet-core` from `CitrateNetwork/citrate-chain` via an SSH git dep that uses an **SSH host alias** (NOT a plain `github.com` URL):

```toml
# agent/core/Cargo.toml — actual declaration
citrate-wallet-core = { git = "ssh://git@github-citrate-chain/CitrateNetwork/citrate-chain", rev = "0f2d16b486a9ec1ed8a0394440dac480075d6942" }
```

The host part — `github-citrate-chain` — is an **alias**, not a real DNS hostname. It must be resolved in your `~/.ssh/config` to `github.com` with a dedicated deploy key. **This is the cause of the federation-split audit's F-14 finding** — a fresh-machine build will fail with `Could not resolve hostname github-citrate-chain` until the alias is configured.

Why an alias instead of a plain `github.com` URL: the deploy key is scoped to `citrate-chain` only (least-privilege), so cargo can't share the developer's main `github.com` key. The alias gives cargo a way to specify "use THIS key" without globally switching the developer's `github.com` identity.

Swap to crates.io semver dep when chain publishes after its first audited release; the alias will become unnecessary at that point.

### Local development setup (REM-22)

To build `citrate-agent-runtime` on a fresh machine, configure the SSH alias. Two paths:

**Path A — automated (recommended)**: run the bootstrap script in `citrate-federation`:

```bash
# From your citrate-labs workspace root
cd citrate-federation && ./scripts/bootstrap.sh
```

The bootstrap script handles the alias setup. See `citrate-federation/scripts/bootstrap.sh` for the exact behavior.

**Path B — manual**: configure the alias yourself.

1. **Obtain a read-only deploy key for `citrate-chain`**. If you're a CitrateNetwork org member, ask the federation lead. If you're an external contributor reading public code, you can use your own GitHub identity by mapping the alias to your default key (this works for anyone with GitHub access to the chain repo).

2. **Add the alias to `~/.ssh/config`**:

   ```sshconfig
   Host github-citrate-chain
       HostName github.com
       User git
       # If you have a dedicated deploy key:
       IdentityFile ~/.ssh/citrate_chain_deploy
       IdentitiesOnly yes
       # Or, to use your default ~/.ssh/id_ed25519 (works for any GitHub user
       # who has access to CitrateNetwork/citrate-chain):
       # IdentityFile ~/.ssh/id_ed25519
       StrictHostKeyChecking accept-new
   ```

3. **Verify**:

   ```bash
   ssh -T git@github-citrate-chain
   # Expected: "Hi <user>! You've successfully authenticated, but GitHub
   #            does not provide shell access."
   ```

4. **Build**:

   ```bash
   cargo build --release
   ```

If step 4 fails with `Could not resolve hostname github-citrate-chain`, recheck step 2. If it fails with `Permission denied (publickey)`, the alias is mapping to the wrong key.

`.cargo/config.toml` sets `git-fetch-with-cli = true` so cargo respects the SSH alias (cargo's bundled libgit2 does not read `~/.ssh/config`; system git does).

### CI: `CHAIN_DEPLOY_KEY` secret

CI (`.github/workflows/ci.yml`, `.github/workflows/cargo-audit.yml`) configures the alias from the `CHAIN_DEPLOY_KEY` repo secret at workflow runtime. The private key is injected into a temporary `~/.ssh/config` for the workflow's lifetime via the `webfactory/ssh-agent` action (or an inline ssh-config snippet).

When the repo is first cloned or the secret is rotated, the federation lead must update `CHAIN_DEPLOY_KEY` in the repo Secrets settings. The deploy key itself lives in `CitrateNetwork/citrate-chain` → Settings → Deploy keys.

## Quick start

```bash
# Once the SSH alias is configured (see "Local development setup" above):
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
