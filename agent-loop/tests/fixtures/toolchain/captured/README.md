---
created: 2026-10-04
branch: hup/n6-forge-wire
author: Larry Klosowski + Claude Opus 5.5
status: active
---

# Captured toolchain output (retro A29)

Real stdout of the toolchain programs, run with the exact argv the sidecar's toolchain tools use,
on a rendered `erc20` template (citrate-core `templates/`, tier T0, OpenZeppelin v5.7.0) on
2026-10-04, macOS arm64. The only edit: the scratch project path is replaced by `/work/erc20` and
the home folder by `/home/member`.

| file | program | project |
|---|---|---|
| `slither-erc20-clean.sarif` | slither 0.11.6 `. --sarif - --exclude-dependencies --disable-color --compile-force-framework foundry` | erc20 as rendered |
| `slither-erc20-suicidal.sarif` | the same | erc20 plus an injected `shutdown()` that anyone can call to `selfdestruct` |
| `aderyn-erc20-clean.txt` | aderyn 0.6.8 `. --output aderyn-report.sarif --stdout --skip-update-check` | erc20 as rendered |
| `aderyn-erc20-selfdestruct.txt` | the same | erc20 plus the injected `shutdown()` |
| `medusa-erc20-T0.txt` | medusa 1.5.1 `fuzz --no-color --test-limit 10000 --timeout 600` | erc20 as rendered |

The same bytes are in citrate-core `src-tauri/tests/fixtures/toolchain-captured/`, where the
deploy gate (the one source of truth for a deploy verdict) parses them. Both repos' tests must
agree on every verdict: clean is a pass for slither, aderyn and medusa; the injected
`selfdestruct` is High for slither (`0-0-suicidal`) and for aderyn (`selfdestruct`, level
`warning`).
