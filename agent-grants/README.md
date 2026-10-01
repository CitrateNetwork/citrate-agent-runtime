---
created: 2026-10-01
branch: hup/n3-folder-grants
author: Larry Klosowski + Claude Opus 5.5
status: implemented (not yet wired into sessions, file tools or core UI)
---

# citrate-agent-grants

Folder grants for agent filesystem access (HUP-S2.1, planset
`2026-09-30-hermes-upskill`, decision D-15 as amended on 2026-09-30). A member
grants Hermes a folder; Hermes cannot reach outside it.

```rust
use citrate_agent_grants::{Access, Decision, FolderGrants, GrantRequest, Op};

let mut grants = FolderGrants::new(home, cwd);
let id = grants.grant(
    GrantRequest::folder("~/work/app", Access::Write, member, "fix the build"),
    now,
)?;
match grants.check("~/work/app/src/main.rs", Op::Write, now) {
    Decision::Allowed { canonical, grant_id } => { /* I/O on canonical.as_path() */ }
    Decision::Denied { reason } => { /* show reason */ }
}
grants.revoke(&id, now)?;
```

## Status

Implemented and tested in this crate. Capsule WASI preopens (S2.5,
`citrate_agent_core::capsule::sandbox`) are scoped to these grants: a capsule
mount opens only a folder covered by live whole-folder grants, after every
entry below it passes `check`. **Not wired in yet:** the agent sessions
(`agent-sidecar`) and the file tools do not call it, the sidecar passes no
grants to its capsules (so they get no folder), and citrate-core has no Grants
screen or store for it. Those are later work packages. Until then nothing in a
member's experience changes.

## Model

A grant is `(root, access, scope, expiry, granted_by, reason)`, stored as a
[`Grant`](src/lib.rs) with an id, `granted_at` and `revoked_at`.

| Field | Meaning |
|---|---|
| `kind` | `folder`, or `full_access` (the 24 h toggle) |
| `root` | Absolute, canonical folder (symlinks resolved, on-disk spelling) as of the grant |
| `access` | `read` or `write`. Separate: a read grant never writes and a write grant never reads. A member who wants both grants both |
| `scope` | `subtree` (the root and everything below) or `shallow` (the root and its direct entries) |
| `expires_at` | Unix seconds; nothing is allowed at or after it. `null` means until revoked (folder grants only) |
| `granted_by` | The member who granted it |
| `reason` | Why, in the member's words; shown in the Grants list |
| `revoked_at` | Set once by `revoke`; a revoked grant allows nothing from that moment on |

Rules enforced when a grant is created **and** when stored grants are loaded:

- The root must pass the default-deny list (`citrate-agent-guard`). A grant
  cannot be rooted in `~/.ssh`, a keychain, and so on. At creation the root
  must also be an existing folder; a stored grant whose folder was deleted
  later still loads and simply covers nothing that exists.
- Write access to the filesystem root is refused.
- `granted_by` and `reason` must be non-empty.
- **Full access is read-only** and always expires, at most
  `FULL_ACCESS_MAX_TTL_SECS` (86,400 s) after it was granted. Writes only ever
  come from folder grants (D-15 amended, RT-5).
- A zero TTL is refused; folder grants may have a TTL or none.

## Check

`check(path, op, now)`:

1. **Folder grants.** The live folder grants for `op` (not revoked,
   `granted_at <= now < expires_at`) become the guard's project roots. The guard resolves the
   path the way the kernel does (each symlink followed where it is met, so
   `link/..` is the parent of the link's target) and checks every location it
   visits against the deny list. The existing part of the result is put in
   its on-disk spelling (`std::fs::canonicalize`, which matters on
   case-insensitive volumes) and checked again; the two answers must agree
   exactly. If a live folder grant covers the result, it is allowed, reporting
   the grant with the deepest root.
2. **Full access.** Otherwise the live full-access grants for `op` (only ever
   `read`) are tried, with the guard re-run **without** project roots, so a
   `.env` file is never readable through full access.
3. Otherwise `NoGrant`.

The deny list always wins: no grant of any kind reaches a location it
denies. Expiry is evaluated at the `now` the caller passes on every check, so a
grant stops working the second it expires; nothing has to sweep it.

### Relation to the `agent-legacy` path checks

The older path checks in `agent-legacy` (`adapters/sandbox.rs`,
`mcp_server.rs`) are not reused; moving them onto this crate or agent-guard
is a later work package. What this crate does instead:

- Resolution is the guard's kernel-order walk; `..` is never popped
  lexically before resolution. Test `dotdot_after_a_symlink_is_the_parent_of_the_target_not_of_the_link`
  and the fuzz both fail when a lexical-first order is put in.
- Containment is a component-wise prefix test on resolved paths
  (`/a/proj-old` is not inside `/a/proj`).
- Roots are stored canonical, so a granted folder later replaced by a
  symlink grants nothing new.

`CapabilityGrant` in `agent-legacy/src/canonical.rs` carries `allowed_paths`
inside a signed, tool-scoped grant for external MCP runtimes. That type and
its signature scheme are unchanged; this crate is the member-facing folder
grant the HUP sidecar will use.

## Persistence (for core)

`FolderGrants::to_json` / `from_json` (or `state()` / `from_state` with
serde) give the document core stores:

```json
{
  "version": 1,
  "next_id": 3,
  "grants": [
    {
      "id": "g-1",
      "kind": "folder",
      "root": "/Users/m/work/app",
      "access": "write",
      "scope": "subtree",
      "granted_at": 1790000000,
      "expires_at": null,
      "granted_by": "0x...",
      "reason": "fix the build",
      "revoked_at": null
    },
    {
      "id": "g-2",
      "kind": "full_access",
      "root": "/Users/m",
      "access": "read",
      "scope": "subtree",
      "granted_at": 1790000000,
      "expires_at": 1790086400,
      "granted_by": "0x...",
      "reason": "find last week's notes",
      "revoked_at": null
    }
  ]
}
```

Loading refuses the **whole** document on any broken rule (unknown version or
field, duplicate id, id not below `next_id`, relative or non-normalized root,
root in the deny list, write on `/`, empty member or reason, expiry not after
grant time, full access that is writable, unbounded or longer than 24 h).
Failing closed means a corrupted file grants nothing. Revoked and expired
grants stay in the document for the Grants list; `list(now)` returns each with
its status (`NotYetActive`, `Active`, `Expired`, `Revoked`) and
`remaining_secs`, the full-access countdown. A grant's window is
`[granted_at, expires_at)`: a stored grant dated ahead of the clock allows
nothing until then, so full access stays within 24 h of when it starts.

Core should store the document under its own app-data directory
(`ai.citrate.core*`), which agent-guard denies to the agent, so the agent
cannot edit its own grants. Grants are created and revoked by core on a member
action only; nothing in this crate lets an agent request one.

## Caller contract and limits

Inherited from agent-guard: do the I/O on the returned canonical path, open
the leaf without following a swapped-in symlink where the OS allows, check
each entry of a recursive operation, and do not let the agent create hard
links into a write grant (a hard link cannot be told apart by path). A check
is point-in-time: re-check at use, which is cheap.

## Tests

- `tests/grants.rs` (26): descendants only, string-prefix siblings, shallow
  scope, read and write apart, symlinks out of and into grants, `link/..`,
  dangling links, a root swapped for a symlink, case variants, the deny list
  inside a grant and through a planted symlink, `.env` inside a folder grant
  versus under full access, the shallow-grant `.env` case TLC found, expiry
  at use time (half-open), zero TTL, immediate and final revocation, full
  access read-only and at most 24 h, request validation, canonical stored
  root, list status and countdown, most specific grant.
- `tests/persistence.rs` (5): round trip, field names and version, 13
  tampered documents refused, loading from a `GrantState` value, a stored
  grant dated ahead of the clock staying inert until its `granted_at`.
- `tests/traversal_fuzz.rs` (2): a fixed-seed generator in agent-guard's
  style against a real tree with live, revoked and expired grants, deny
  locations and symlinks (out, in, `..` traps, relative, dangling, into the
  deny list). The OS (`std::fs::canonicalize`) is the oracle. Both reads and
  writes; a second world adds a read-only full-access grant and a shallow
  folder grant. It runs batches until each outcome (oracle-resolved, deny
  hits, outside-grant hits, revoked/expired hits, allowed, allowed writes) is
  reached a minimum number of times, so it is not vacuous on case-sensitive
  disks. About 50 s per world in a debug build.
- Unit tests (2): component-wise coverage and the half-open time window.

Rust mutants, each a single edit then restored (2026-10-01), each failing at
least one test: lexical `..` before resolution; guard denial ignored; expiry
ignored; revocation ignored; access ignored; string-prefix containment;
full access writable; `.env` unlocked by full access; inclusive expiry;
unbounded full-access TTL; full-access phase reusing folder project roots
(the TLC finding).

Formal model: [`formal/`](formal/README.md).
