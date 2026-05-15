---
created: 2026-05-15T16:35:00Z
branch: main
author: Saul + Claude Opus 4.7 (1M context)
sprint: CIT-AGENT-9c-shell-wire-prep
status: active
---

# Shell-Wire Cutover Guide

> Reference doc for the CIT-AGENT-9c-shell-wire-cutover sprint
> (visual-proof required, deferred from
> CIT-AGENT-9c-shell-wire-prep). Documents the exact code path
> change to replace `citrate-boeing-shell::tools::execute(...)`
> with capsule-based dispatch.

## Current state (Rust dispatch)

`citrate_v0.01.1/gui/citrate_boeing_shell/src/tools.rs:223-237`:

```rust
match call.name.as_str() {
    "list_compliance_posture"  => exec_list_compliance_posture(&call.args, &bindings).await,
    "query_decisions_by_tenant" => exec_query_decisions_by_tenant(&call.args, &bindings).await,
    "query_supplier_status"     => exec_query_supplier_status(&call.args, &bindings).await,
    "verify_provenance_chain"   => exec_verify_provenance_chain(&call.args, &bindings).await,
    "provision_user" => match recorder { Some(rec) => exec_provision_user(&call.args, rec).await, ... },
    "revoke_role"    => match recorder { Some(rec) => exec_revoke_role(&call.args, rec).await, ... },
    "anchor_session" => match recorder { Some(rec) => exec_anchor_session(&call.args, rec).await, ... },
}
```

Each `exec_*` (lines 279, 305, 341, 400, 418, 468, 498) calls
into `BoeingBindings` (read tools) or `RecorderClient`
(write tools) directly.

## Target state (capsule dispatch)

```rust
// At boeing-shell startup:
let dispatch = CapsuleDispatch::load_from_dir(
    Path::new("capsules"),
    Arc::new(RpcEthCallDispatcher::from_url(active_rpc_url())),
    Arc::new(RecorderEthSendDispatcher::new(recorder.clone())),
    Arc::new(QueuedApprovalGate::new(approval_queue.clone())),
);

// In tools::execute(...):
let capsule_name = match call.name.as_str() {
    "list_compliance_posture"  => "list-compliance-posture",
    "query_decisions_by_tenant" => "query-decisions-by-tenant",
    "query_supplier_status"     => "query-supplier-status",
    "verify_provenance_chain"   => "verify-provenance-chain",
    "provision_user"            => "provision-user",
    "revoke_role"               => "revoke-role",
    "anchor_session"            => "anchor-session",
    _ => return Err(...),
};
dispatch.call(capsule_name, &call.args).map(format_for_chat)
```

## Per-tool migration map

| Chat tool name | Rust `exec_*` | New capsule | Function export |
|---|---|---|---|
| list_compliance_posture | `tools.rs:279` | `capsules/list-compliance-posture/` | `citrate:list-compliance-posture/query@0.1.0::query` |
| query_decisions_by_tenant | `tools.rs:305` | `capsules/query-decisions-by-tenant/` | `citrate:query-decisions-by-tenant/query@0.1.0::query` |
| query_supplier_status | `tools.rs:341` | `capsules/query-supplier-status/` | `citrate:query-supplier-status/query@0.1.0::query` |
| verify_provenance_chain | `tools.rs:400` | `capsules/verify-provenance-chain/` | `citrate:verify-provenance-chain/query@0.1.0::query` |
| provision_user | `tools.rs:418` | `capsules/provision-user/` | `citrate:provision-user/action@0.1.0::provision` |
| revoke_role | `tools.rs:468` | `capsules/revoke-role/` | `citrate:revoke-role/action@0.1.0::revoke` |
| anchor_session | `tools.rs:498` | `capsules/anchor-session/` | `citrate:anchor-session/action@0.1.0::anchor` |

## What changes in main.rs

`citrate_v0.01.1/gui/citrate_boeing_shell/src/main.rs:2557-2580`:

Replace the construction of `BoeingBindings` + `RecorderClient` +
the executor closure with:

```rust
let approval_queue = Arc::new(cit_hitl::ApprovalQueue::new());
let recorder = recorder::RecorderClient::from_env(active_rpc_url())
    .map(Arc::new);

let dispatch = match recorder {
    Some(rec) => CapsuleDispatch::load_from_dir(
        capsules_dir(),
        Arc::new(citrate_agent_core::capsule::dispatcher::RpcEthCallDispatcher::from_url(active_rpc_url())),
        Some(Arc::new(citrate_agent_core::capsule::prod_impls::RecorderEthSendDispatcher::new(rec))),
        Arc::new(citrate_agent_core::capsule::prod_impls::QueuedApprovalGate::new(approval_queue.clone())),
    )?,
    None => /* read-only mode: build dispatch with eth_send_dispatcher=None */
};
```

## Risks + mitigations

| Risk | Mitigation |
|---|---|
| `tools::execute` callers (chat loop, test tools) break compile | Keep both paths until visual proof passes; remove old `exec_*` functions in a follow-on |
| ApprovalQueue receives entries from BOTH paths (old + new) | The cutover MUST be atomic in main.rs — either old or new wires the queue, not both |
| Capsule `.cps` archives not packaged with the boeing-shell binary | Add `include_dir!` macro or path-resolution at startup to point at `citrate_v0.01.1/capsules/` |
| Slint UI shows different result format from `exec_*` vs capsule | The `format_for_chat` function in tools.rs needs to format the new capsule return types (records, lists) the same as the old string returns |
| Capsule load latency hurts first-tool-call UX | Load all 7 at boeing-shell startup (eager); cache the `Capsule` structs |

## Test plan (for the cutover sprint)

1. Compile boeing-shell with both paths present.
2. Run `cargo test -p citrate-boeing-shell` — all 26 existing
   tests pass.
3. Run `scripts/run_gui_visual_proofs.sh` — all PNG goldens
   match.
4. Manual smoke: launch boeing-shell, ask the chat to call each
   of the 7 tools, verify the approval card surfaces for write
   tools, verify the chat response is informative.
5. Remove old `exec_*` functions in a follow-on commit once
   visual proof is green.

## Definition of done for the cutover sprint

- `tools::execute` dispatches via `CapsuleDispatch::call`
- The 7 `exec_*` Rust functions are deleted
- Visual proof regenerates without diffs
- `cargo test -p citrate-boeing-shell` 26 tests pass
- Manual smoke confirms each tool through the operator UI
