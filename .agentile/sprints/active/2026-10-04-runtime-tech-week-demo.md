---
created: 2026-10-04T00:00:00Z
branch: feat/runtime-tech-week-demo
author: OpenCode (implementation agent)
status: active
sprint: runtime-tech-week-demo
---

# Runtime Tech Week demo

[citrate-agent-runtime issue #61](https://github.com/CitrateNetwork/citrate-agent-runtime/issues/61)
is authoritative for scope, acceptance criteria, and exclusions. Under Rule 4, this sprint file
is authoritative for execution status: implementation and local verification are complete on
`feat/runtime-tech-week-demo`, and the branch is pending repository review.

## Demo story

The Tech Week path is deliberately small and repeatable:

1. `citrate-agent-runtime` runs a signed offline capsule and writes a local audit chain.
2. `citrate-sdk-js` proves read-only connectivity to chain 40204 without a private key.
3. The operator explains the boundary honestly: the Runtime evidence is local, unsigned, and
   unanchored; the SDK leg is live read-only RPC connectivity.

This is the viable demo lane. Do not expand it during rehearsal with funded-account flows,
private keys, model purchases, deployment transactions, signing ceremonies, Discord/Hermes
bring-up, or chain anchoring. Those are follow-up demos, not this Tech Week path.

## Runtime capsule demo

Prerequisites:

- Windows PowerShell or `cmd.exe`.
- A built `target\release\citrate-agent.exe` from this branch, or Rust toolchain support for the
  current dependency floor. On 2026-10-05, `cargo run --release --bin citrate-agent -- demo ...`
  failed on `rustc 1.94.1` because Wasmtime/Cranelift required `rustc 1.96.0`; use
  `cargo +1.96.0-x86_64-pc-windows-msvc build --release --bin citrate-agent` or a newer stable
  toolchain before relying on a fresh build.

Clean setup and run from the `citrate-agent-runtime` repository root:

```cmd
rmdir /s /q "%TEMP%\citrate-runtime-tech-week-demo" 2>nul
mkdir "%TEMP%\citrate-runtime-tech-week-demo\evidence"
target\release\citrate-agent.exe demo --capsules-dir capsules --evidence-dir "%TEMP%\citrate-runtime-tech-week-demo\evidence"
```

Expected terminal output:

```text
Hello, Tech Week
```

Expected evidence files:

```cmd
dir "%TEMP%\citrate-runtime-tech-week-demo\evidence"
type "%TEMP%\citrate-runtime-tech-week-demo\evidence\summary.json"
```

Key fields in `summary.json`:

```json
{
  "schema_version": "citrate-agent-demo-summary/v1",
  "command": "citrate-agent demo",
  "output": "Hello, Tech Week",
  "capsule_signature_verified": true,
  "evidence_signed": false,
  "chain_anchored": false,
  "external_network_used": false,
  "audit_chain_verified": true,
  "audit_record_count": 2
}
```

Narration:

> This capsule executes offline with no network capability and no filesystem capability declared
> by the capsule. The runtime verifies the signed capsule identity, runs it deterministically,
> and emits an append-only local audit chain plus a human-readable summary. This demo stops before
> chain anchoring so we can show the trust boundary clearly and avoid pretending local evidence is
> already on chain.

## SDK read-only connectivity demo

Use the companion `citrate-sdk-js` pull request
[#25](https://github.com/CitrateNetwork/citrate-sdk-js/pull/25) from the SDK repository root:

```cmd
npm ci
npm run build
set CITRATE_RPC_URL=https://rpc.citrate.ai
set CITRATE_CHAIN_ID=40204
npm run example:read-only
```

Expected terminal output:

```text
Connected: network=citrate-public chainId=40204 mode=read-only
```

Narration:

> The SDK leg is intentionally read-only. It does not need a private key, funded account, or local
> faucet. It proves that a developer can point at the public Citrate RPC, verify the expected chain
> ID, and stay out of signing paths during a demo.

Fallbacks:

- If public RPC is unavailable, query the intended local endpoint's `eth_chainId`, set
  `CITRATE_RPC_URL` and decimal `CITRATE_CHAIN_ID` to that endpoint, and rerun the same command.
- If the SDK build fails, stop and show the Runtime capsule demo only. Do not pivot into funded
  integration tests during Tech Week rehearsal.

## Rehearsal evidence

2026-10-05 Windows rehearsal:

- Runtime prebuilt binary path: `target\release\citrate-agent.exe`.
- Runtime binary SHA-256:
  `C2CF1B146494D374640A12674D452D8AE5FAACE489FF9E36C5B27895B5EE20CC`.
- Runtime output: `Hello, Tech Week`.
- Runtime summary output: `output=Hello, Tech Week`, `capsule_signature_verified=true`,
  `external_network_used=false`, `audit_chain_verified=true`, `audit_record_count=2`,
  `audit_head_sha256=e8f96ebdbb834ae78de095217ba94503c53271a050a7cd00ec1a7a4d96396842`.
- SDK command: `npm run build` then `CITRATE_RPC_URL=https://rpc.citrate.ai`,
  `CITRATE_CHAIN_ID=40204`, `npm run example:read-only`.
- SDK output: `Connected: network=citrate-public chainId=40204 mode=read-only`.

## Live speaker script

Target length: 4-6 minutes. The operator should keep terminal panes ready before starting:

- Pane 1: `citrate-agent-runtime` on `feat/runtime-tech-week-demo`.
- Pane 2: `citrate-sdk-js` on `feat/tech-week-read-only-quickstart`.
- Pane 3 or editor: this sprint file opened to the fallback packet.

### Opening, 20 seconds

> The goal of this demo is not to show a giant local stack. It is to show the smallest honest
> Citrate developer path: a signed agent capsule runs deterministically under the Runtime, and the
> SDK proves read-only connectivity to the public Citrate chain without needing a private key or a
> funded account.

### Step 1 — Runtime capsule, 90 seconds

Say:

> First, I am running the Runtime demo. This uses the signed `hello` capsule from the checked-in
> capsule fleet. The capsule declares no network capability, no filesystem capability, no chain
> calls, and no subagent spawning. The runtime verifies that capsule identity before executing it.

Run:

```cmd
rmdir /s /q "%TEMP%\citrate-runtime-tech-week-demo" 2>nul
mkdir "%TEMP%\citrate-runtime-tech-week-demo\evidence"
target\release\citrate-agent.exe demo --capsules-dir capsules --evidence-dir "%TEMP%\citrate-runtime-tech-week-demo\evidence"
```

Point at the output:

```text
Hello, Tech Week
```

Say:

> That line is the capsule output. The more important part is the evidence folder the runtime just
> wrote. It is local evidence only: not signed as a release artifact and not anchored on chain in
> this demo. That boundary is intentional so we do not overclaim.

Run:

```cmd
type "%TEMP%\citrate-runtime-tech-week-demo\evidence\summary.json"
```

Point at these fields: `capsule_signature_verified=true`, `external_network_used=false`,
`audit_chain_verified=true`, and `audit_record_count=2`.

### Step 2 — SDK read-only chain connectivity, 90 seconds

Say:

> Next, I am switching from local Runtime evidence to live chain connectivity. This SDK example is
> deliberately read-only. It does not require a private key, a faucet, or a funded test account.
> The only thing it proves is that the developer is talking to the expected Citrate chain ID.

Run from `citrate-sdk-js`:

```cmd
npm run build
set CITRATE_RPC_URL=https://rpc.citrate.ai
set CITRATE_CHAIN_ID=40204
npm run example:read-only
```

Point at the output:

```text
Connected: network=citrate-public chainId=40204 mode=read-only
```

Say:

> That gives us the live network leg without signing anything. If we want a later demo with funded
> accounts, deployments, or chain anchoring, that is a separate ceremony. This one is built to be
> repeatable under conference conditions.

### Close, 30 seconds

> The takeaway is that Citrate has a credible developer path in two parts: agent work can run under
> a signed-capsule runtime with local audit evidence, and application code can connect to the public
> Citrate chain in read-only mode without secrets. The boundary is explicit today: this is local
> verified evidence plus live read-only connectivity, not a claim that the demo evidence is already
> anchored on chain.

## Fallback packet

Use this packet if Wi-Fi, public RPC, Node, Cargo, or the local terminal environment fails during
the live slot. Read the narration as written and show the captured outputs below. Do not pivot into
funded integration tests or private-key flows as a fallback.

### Fallback A — Runtime terminal output

```text
target\release\citrate-agent.exe demo --capsules-dir capsules --evidence-dir "%TEMP%\citrate-runtime-tech-week-demo\evidence"
Hello, Tech Week
```

### Fallback B — Runtime summary evidence

Captured on Windows rehearsal, 2026-10-05:

```json
{
  "schema_version": "citrate-agent-demo-summary/v1",
  "command": "citrate-agent demo",
  "capsule": {
    "name": "hello",
    "version": "0.1.0",
    "content_hash": "sha256:88c703080488b4852035a4007351a6d4cd63a065771881385cd2d3e2ffaf34f9"
  },
  "input": {
    "name": "Tech Week"
  },
  "output": "Hello, Tech Week",
  "capsule_signature_verified": true,
  "evidence_signed": false,
  "chain_anchored": false,
  "external_network_used": false,
  "audit_chain_verified": true,
  "audit_record_count": 2,
  "audit_head_sha256": "e8f96ebdbb834ae78de095217ba94503c53271a050a7cd00ec1a7a4d96396842"
}
```

Runtime binary used for the rehearsal:

```text
target\release\citrate-agent.exe
SHA-256 C2CF1B146494D374640A12674D452D8AE5FAACE489FF9E36C5B27895B5EE20CC
```

### Fallback C — SDK read-only output

Captured on Windows rehearsal, 2026-10-05, after `npm run build` with
`CITRATE_RPC_URL=https://rpc.citrate.ai` and `CITRATE_CHAIN_ID=40204`:

```text
> @citratelabs/sdk@0.2.4 example:read-only
> node examples/read-only.cjs

Connected: network=citrate-public chainId=40204 mode=read-only
```

### Fallback D — if asked what failed live

Use only the line that matches the actual failure:

- Runtime fresh build failure on this Windows machine: the active `stable` toolchain was
  `rustc 1.94.1`, while Wasmtime/Cranelift required `rustc 1.96.0`; the documented fallback is
  `cargo +1.96.0-x86_64-pc-windows-msvc build --release --bin citrate-agent` or a prebuilt binary.
- SDK public RPC failure: the read-only script is designed to fail closed on chain-ID mismatch or
  unreachable RPC; use a local Citrate endpoint only after querying its `eth_chainId` and setting
  the matching decimal `CITRATE_CHAIN_ID`.
- Conference network failure: show Fallback A-C and state that the captured Runtime evidence is
  local and unanchored, while the SDK output was captured from public chain 40204 during rehearsal.
