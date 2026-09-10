---
created: 2026-08-29T00:00:00Z
branch: feat/hermes-s6.3-bridge-e2e
author: Saul + Claude Opus 4.8
status: accepted
adr: agent-sidecar-001
---

# ADR-001 (agent-sidecar) — how `runSkill` invokes a capsule (the S6.3 slice-2 decision)

> NB — `agent-sidecar` is the citrate-core agent sidecar (the keyless HTTP control plane citrate-core
> spawns), NOT the Discord `hermes/` bot. Different program.

## Context

`agent-sidecar` serves citrate-core's frozen `AgentHarnessDomain`. S6.2 (control plane) + S6.3
slice-1 (the ceremony-resolution bridge: `POST /approvals/approve|reject`) are merged, and the
**safety property is proven end to end** (a chain effect submitted through the `ApprovalQueue`
surfaces and is resolved by the same approve/reject the endpoints call — see
`agent-sidecar/src/tests.rs`). The remaining piece is `runSkill(name, argsJson) -> {ok}`: actually
**executing** a skill so its chain effects flow through that bridge.

Three facts from the codebase make this a real decision, not a wiring task:

1. **Skills must be capsules, not SOPs.** Only the `agent/core` capsule path traverses the
   ceremony-grade `ApprovalQueue` (via `ApprovalGate`); `SOPEngine` uses the *legacy* risk-tiered
   `ApprovalFlow` (`agent-cron/src/sop.rs:10`), which is a HITL prompt, not a ceremony. So "every
   chain effect → ceremony" (the gate's key property) requires running **capsules**.
2. **Capsules have bespoke WIT interfaces.** `list-compliance-posture` exports
   `query: func(framework: string, scope: string) -> result<posture-row, string>`
   (`capsules/list-compliance-posture/wit/world.wit`). There is **no uniform `run(bytes)->bytes`
   entry** and `CapsuleDispatch::call_raw(name, iface, func, &[wasmtime::component::Val])` requires
   the caller to know the interface, function, and **typed** args. There is no JSON facade.
3. **The approval gate blocks the calling thread** until a human resolves
   (`QueuedApprovalGate::request` → `block_in_place` → `submit_with_outcome`). So `runSkill` cannot
   run the capsule inline in the axum handler; it must dispatch on a background task and return
   `{ok:true}` = *accepted, effects pending approval*.

## The decision to make

**How does `agent-sidecar` turn `(skill name, argsJson)` into a typed capsule call?** Two viable
options; both keep the ceremony bridge unchanged.

- **Option A — a JSON-dispatch enabler in `agent-core` (recommended).** Add
  `CapsuleDispatch::call_json(name, argsJson) -> Result<serde_json::Value, AgentError>`: it
  instantiates the capsule (as `call_raw` does), resolves the single exported interface + function
  (or one named in the manifest), **introspects the function's param types** (`Func::params`), maps
  the JSON object → the typed `Val`s (string / u8 / u16 / u32 / u64 / bool / `list<u8>` / record),
  calls, and maps the `result<_, string>` back to JSON. `runSkill` then spawns `call_json` on a
  blocking task. Pros: skills stay declared purely by their WIT; one place owns JSON↔Val; keeps the
  mapping inside the audited core. Cons: an additive change to the T1 capsule execution path (needs
  its own tests + the manifest may need an `[entry]` interface/func field when a capsule exports more
  than one function).

- **Option B — a manifest `[skill]` contract + a positional mapper in the sidecar.** Each skill
  capsule declares `[skill] interface = "..."`, `func = "..."`, and an ordered `params = [{name,
  type}]` in its `manifest.toml`; `agent-sidecar` maps `argsJson` → `Val`s by that declared schema
  and calls `call_raw`. Pros: no `agent-core` change; the skill ABI is explicit + reviewable in the
  manifest. Cons: the schema is hand-maintained + can drift from the WIT (a mismatch is a runtime
  error); the mapping logic lives outside the core.

## Recommendation

**Option A.** The type source of truth is the WIT/component itself; introspecting it avoids a
hand-maintained schema that can drift, and centralizes JSON↔Val in the audited execution path (the
right place for a change that feeds the money/safety gate). The `[entry]` manifest field is only
needed for multi-function capsules; single-function skills need nothing new.

## Consequences

- `runSkill` spawns `call_json` on a blocking task, returns `{ok:true}`; the capsule's chain effects
  enqueue on the `ApprovalQueue` → surface via `/approvals` → resolved by the slice-1 endpoints →
  execute (or abort on reject). The e2e test already proves the resolve half; slice-2 wires the
  submit half through a real capsule.
- Then: S6.4 (the code-task sandbox — use WASM capsules for real isolation; `shell_exec` is
  path-policy only), citrate-core `hermes_*` command wiring + `Agent.tsx`, binary packaging, and the
  independent security sign-off (production requires a `SignerRoster` provisioned at spawn).

**DECISION (2026-08-29, owner): Option A** — the `call_json` JSON<->Val enabler in `agent-core`.
The capsule survey (every skill capsule is single-function; the whole arg-type surface is
string/list<u8>/u8/u32/u64/bool) makes `call_json` small + drift-free (the WIT is the type source of
truth). Slice-2 implements it + wires `runSkill`.
