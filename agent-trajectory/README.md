---
created: 2026-10-01
branch: hup/n3-metering-trajectories
author: Larry Klosowski + Claude Opus 5.5
status: implemented (library only; not yet wired into sidecar sessions)
---

# citrate-agent-trajectory

Verified, redacted training data from Hermes sessions: HUP-S9.3 (planset
`2026-09-30-hermes-upskill`, story US-9.1 AC1, decisions D-22 and D-29).

## What it does

1. `TrajectoryRecorder` wraps the session's event sink, forwards every event unchanged, and
   remembers for each loop turn how it ended, what the workflow verifiers said, and whether the
   session ever read untrusted content.
2. `recorder.trajectories(&history)` pairs that with the session history (from when the
   recorder was attached) into one `TurnTrajectory` per turn. Each loop turn appends exactly one
   user message and emits exactly one `done`; if the two do not line up, it refuses.
3. `export_verified(&trajectories, &policy)` keeps a turn only when it ended in an answer and
   **every** verifier passed. It drops every turn of a tainted session unless the policy allows
   it with a reason. It redacts what it keeps and returns JSONL plus a `RedactionReport`.

```rust
use citrate_agent_trajectory::{export_verified, ExportPolicy, TrajectoryRecorder};

let rec = TrajectoryRecorder::new(session_id, model, taint.clone()).with_workflow("hello-mint");
// run_workflow(..., &rec, ..., &mut history, &wf);
let policy = ExportPolicy::new().with_granted_root(project_dir).with_home(home_dir);
let export = export_verified(&rec.trajectories(&history)?, &policy)?;
export.write_jsonl(&out_path)?; // never overwrites
```

Output lines use the OpenAI chat fine-tuning shape: `{"messages": [...], "metadata": {model,
workflow, step, verifiers}}`. The system prompt and the session id are not exported.

## Redaction (on by default, cannot be turned off)

| Category | Caught | Placeholder |
|---|---|---|
| secret | PEM private keys; 32-byte hex with or without `0x`; `sk-`, `ghp_`/`gho_`/..., `github_pat_`, `xox?-`, `AKIA`/`ASIA`, `AIza`, `sk_live_`/`rk_test_`, JWTs; values of `api_key=`, `password:`, `client_secret`, `token=`, `mnemonic:` and similar; secret URL query values | `[REDACTED:secret]` |
| bearer_token | the credential after `Bearer` / `Basic` (when it looks like one, so "basic idea" survives) | `Bearer [REDACTED:bearer_token]` |
| seed_phrase | 12 or more consecutive BIP-39 English words, across spaces, commas, newlines and list numbering | `[REDACTED:seed_phrase]` |
| path | absolute Unix, `~/`, `file://` and Windows paths outside every granted root (after resolving `..`, matched by whole path components) | `[REDACTED:path]` |
| address | `0x` + 40 hex, unless on the policy's allow list (case-insensitive) | `[REDACTED:address]` |
| email | `local@domain.tld` | `[REDACTED:email]` |

Paths inside a granted root are kept as `[root:N]/rest`, so the absolute prefix (and the
username in it) never leaves the machine.

Known trade-offs, chosen on the safe side:

- Transaction hashes and other 32-byte digests are redacted as secrets (they look like private
  keys).
- Redaction is pattern-based. The report says so and asks for a review before sharing.

The BIP-39 wordlist is vendored at `src/bip39_english.txt`. A test pins its SHA-256 to the
canonical English list.

## The report

`RedactionReport` counts considered, exported and excluded turns (tainted session, unverified,
verifier failed, not answered), redactions per category in total and per example, and the
member's reason when tainted sessions were allowed. It never contains a redacted value (tested).

## Not done here

- Wiring into sidecar sessions: no session attaches a `TrajectoryRecorder` yet.
- Per-round consent and sharing (D-29) and the FL worker that consumes the file (HUP-S9.2).
- Non-English seed-phrase wordlists.
