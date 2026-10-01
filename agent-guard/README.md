---
created: 2026-09-30
branch: hup/s2-default-deny
author: Larry Klosowski + Claude Opus 5.5
status: implemented (not yet wired into callers)
---

# citrate-agent-guard

The central default-deny list for agent filesystem access (HUP-S2.8, planset
`2026-09-30-hermes-upskill`, decision D-15). One function:

```rust
use citrate_agent_guard::{check_path, GuardContext};

let ctx = GuardContext::new(home, cwd).with_project_root(granted_folder);
match check_path("~/work/app/src/main.rs", &ctx) {
    Ok(canonical) => { /* do the I/O on canonical.as_path() */ }
    Err(denied) => { /* denied.category, denied.reason */ }
}
```

The list applies **regardless of grants**. Folder grants, the read-only
full-disk toggle and capsule preopens are layered on top by the caller; this
crate can only narrow access, never widen it.

## Status

Implemented and tested in this crate. **Not wired into any caller yet.** The
file tools (`agent-code`, `agent-legacy` sandbox), shell argument checks and
capsule WASI preopens (S2.5) still use their own checks until a follow-up WP
routes them through `check_path`.

## What is denied

Rules match folded path components (see "Matching"). "Anywhere" rules match
at any depth, so `~/.ssh`, `/root/.ssh` and another user's `/home/x/.ssh` are
all denied; "root" rules only match from the filesystem root.

| Category | Anchor | Locations |
|---|---|---|
| `Credentials` | anywhere | `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.config/gcloud`, `.docker/config.json`, `.netrc`, `_netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `.config/gh`, `.config/hub`, `.cargo/credentials(.toml)`, `.terraform.d/credentials.tfrc.json`, `.password-store` |
| `Keychain` | anywhere | `Library/Keychains` (covers `~/Library`, `/Library`, `/System/Library`), `.local/share/keyrings`, `.gnome2/keyrings`, `.local/share/kwalletd`, `.kde{,4}/share/apps/kwallet`, Windows `AppData/{Roaming,Local}/Microsoft/{Credentials,Protect,Vault}` |
| `BrowserProfile` | anywhere | macOS `Library/Application Support/{Google/Chrome{, Beta, Canary}, Chromium, BraveSoftware, Microsoft Edge, Firefox, Arc, Vivaldi, com.operasoftware.Opera}`, `Library/Safari`, `Library/Containers/com.apple.Safari`, `Library/Cookies`; Linux `.config/{google-chrome{,-beta}, chromium, BraveSoftware, microsoft-edge, vivaldi, opera}`, `.mozilla`, `snap/{chromium,firefox}`, Flatpak `.var/app/{org.mozilla.firefox, com.google.Chrome, com.brave.Browser}`; Windows `AppData/Local/{Google/Chrome, Chromium, BraveSoftware, Microsoft/Edge, Vivaldi, Mozilla}`, `AppData/Roaming/{Mozilla, Opera Software}` |
| `WalletStorage` | anywhere | Extension storage in any Chromium-family profile (`Local Extension Settings`, `Sync Extension Settings`, `Managed Extension Settings`, any component starting `chrome-extension_`), Firefox extension storage (`moz-extension+++*`); desktop keystores `.ethereum/keystore`, `Library/Ethereum/keystore`, `.foundry/keystores`, `.citrate-wallet`, `.electrum`, `Library/Application Support/Exodus`, `.bitcoin/wallets`, `Library/Application Support/Bitcoin/wallets` |
| `CitrateAppData` | anywhere | Any component starting `ai.citrate.core` (the Tauri app-data, local-data, config, cache, WebKit and preferences dirs on every OS, including the vault and `hermes/bearer.token`, plus `ai.citrate.core.custody`); node and CLI keys `.citrate/{noise,proposer,keystore,node}`. `.citrate/models` stays reachable. |
| `ShellHistory` | anywhere | `.zsh_history`, `.bash_history`, `.sh_history`, `.ksh_history`, `.history`, `fish_history`, `.zsh_sessions`, `.bash_sessions`, `.python_history`, `.node_repl_history`, `.psql_history`, `.mysql_history`, `.sqlite_history`, `.rediscli_history`, `.irb_history`, `.lesshst`, PowerShell `ConsoleHost_history.txt` |
| `DotEnv` | see below | `.env`, `.env.*`, `.envrc` outside every granted project root |
| `SystemPath` | root | `/etc/{shadow, shadow-, gshadow, gshadow-, master.passwd, sudoers, sudoers.d, ssh, ssl/private, krb5.keytab, security/opasswd}` and the macOS `/private/etc/...` spellings, `/private/var/db`, `/var/db`, `/root`, `/proc`, `/dev/{mem,kmem,port}`; anywhere: `Windows/System32/config` |
| `Malformed` | n/a | empty input, NUL byte, non-UTF-8, `~user/...` |
| `Unresolvable` | n/a | symlink loop (more than 40 links), any I/O error other than "not found" while resolving |

The tables live in `src/lib.rs` (`RULES`, `PREFIX_RULES`). Keep this README
in step when they change.

### Decision: `.env` files

A `.env`, `.env.<anything>` or `.envrc` file is **allowed only strictly
inside a project root the caller passed with `with_project_root`**, and
denied everywhere else, including when no project root is granted. Reason: a
project's own `.env` is part of the work the user granted (an agent fixing a
config bug needs to see variable names), while a `.env` anywhere else belongs
to some other project and almost always holds live secrets. Templates meant
to be committed (`.env.example`, `.env.sample`, `.env.template`, `.env.dist`,
`.env.defaults`) are allowed anywhere. A `.env` reached through a symlink is
judged by where it really lives.

## Resolution

1. Interpret: `\` becomes `/`; `~` and `~/...` expand to the context home;
   relative paths join the context cwd.
2. Lexical check of the request as written (catches a denied name even when
   it is a symlink to somewhere harmless).
3. Resolve like the kernel, component by component. A symlink is followed at
   the point it is met, so `link/..` is the parent of the link's *target*,
   not the directory holding the link. Relative and absolute link targets,
   chains and dangling links are all followed. Every location visited (each
   intermediate directory, each symlink, the final path) is checked, so
   walking through a denied directory with `..` is denied.
4. Components that do not exist yet (a write target) are appended to their
   nearest existing ancestor.
5. The result is returned as a `CanonicalPath`.

### Matching

Each component is folded before comparison: Unicode NFKD, lowercase, NFKC,
trailing dots and spaces trimmed (Windows ignores them), and anything after
a `:` dropped (NTFS stream syntax). This covers macOS case-insensitive and
normalization-insensitive lookups (`~/.SSH`, `~/.\u{212A}ube` with a KELVIN
SIGN) and Windows spellings. Folding only ever over-denies: on a
case-sensitive Linux disk `~/.SSH` is a different directory, and it is still
denied.

## Caller contract and limits

- Do the I/O on the returned `CanonicalPath`, not the original string.
- This is a point-in-time check. Open the leaf without following symlinks
  where the OS allows (`O_NOFOLLOW`), or re-check after opening.
- Recursive operations (tree copy, archive, recursive search) must check
  every entry they visit. Allowing `~` does not allow everything under it.
- Hard links cannot be detected from a path. Write grants must not let an
  agent create hard links into a granted folder.
- Windows 8.3 short names (`PROGRA~1`) are not expanded; the Windows rules
  are matched on the long names. A Windows build of the callers should
  resolve with `GetFinalPathNameByHandle` before calling the guard.

## Tests

- `tests/categories.rs`: red-green cases per category, the `.env` decision,
  and the path shapes (relative, `..`, `~`, trailing and doubled slashes,
  Windows separators, case, Unicode, NTFS suffixes, symlinks absolute,
  relative, chained, dangling, looping, and `..` after a symlink).
- `tests/traversal_fuzz.rs`: a fixed-seed generator builds 6,000 paths
  (3,000 bases, each also tried as the parent of a new file) from hostile
  pieces against a real tree with symlinks into denied directories. An
  oracle asks the OS (`std::fs::canonicalize`) where each lands. It asserts
  no path the OS resolves into a denied root is allowed, no allowed path is
  inside a denied root, and that guard and OS agree on the target whenever
  both resolve. It also asserts it is not vacuous (over 1,000 denied-root
  hits and over 1,000 allowed paths per run). Two mutants (lexical `..`
  before resolution; not following symlinks) are each caught by both files.
- proptest is not used: the workspace pins `proptest = "=1.5.0"` while the
  lockfile carries 1.11 for other crates, and adding the pinned version
  would have downgraded unrelated dependencies. The deterministic generator
  replays failures exactly.
