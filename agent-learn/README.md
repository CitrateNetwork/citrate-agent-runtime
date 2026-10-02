---
created: 2026-10-01
branch: hup/n3-verified-learning
author: Larry Klosowski + Claude Opus 5.5
status: active
---

# citrate-agent-learn: verified self-learning (HUP-S3.4, runtime half)

Planset: citrate-core `.agentile/planset/2026-09-30-hermes-upskill/` (D-22, US-3.4,
02_ARCHITECTURE "Self-learning", 03_TLA_SPECS `SkillPersistence`). Formal model:
[`formal/`](formal/README.md).

## What it does

| Step | API | Rule |
|---|---|---|
| Run | `run_verified_workflow(session, ...)` | Same as `agent_loop::run_workflow`, plus a recorder that keeps every verifier verdict and forwards every event. Returns a `VerifiedRun` only when the workflow succeeded and the recorded verdicts confirm it: per step, the final judged attempt has one passing verdict per verifier, in order. `VerifiedRun` has no public constructor and does not deserialize. |
| Propose | `Learner::propose(&run, content, provenance, known_memories)` | Content is a full `SKILL.md` (validated by the agent-loop parser) or a `{key, value}` memory. The proposal carries the evidence (final verdicts, judged attempt count, a SHA-256 of the trajectory the workflow appended) and the provenance (its session must match the run). Nothing is written or recorded. |
| Accept | `Learner::accept(id, MemberAccept)` | Conflicts are re-checked. A blocking conflict refuses. Every other conflict must be named in `acknowledged_conflicts`. Then an HIC-1 `learn.skill` / `learn.memory` decision is written to the agent-records log (write-ahead), the item is persisted, and the outcome (completed or failed) closes the record. |
| Reject | `Learner::reject(id, member, reason)` | An HIC-1 denial is recorded. Final. |
| Publish | `Learner::prepare_publish(id, PublishApproval, PublishParams)` | Skills only, after persist, with an approval naming this proposal and content hash. The saved file is re-read and must still match. Builds `registerSkill` calldata and records an HIC-1 `skill.publish` decision. Never signs or sends. |

## Persisting

- **Skill:** staged in a hidden `.learn-<id>` directory (the loader skips hidden directories),
  `fsync`ed, renamed to `<user_skills_dir>/<name>/SKILL.md`, then loaded with
  `SkillLibrary::load` on the user directory. If the loader does not load it from that path
  with the same bytes (for example the folder already has the per-source maximum of 512 skills),
  the directory is removed and the accept fails as `persist_failed`. The member may accept again.
- **Memory:** the runtime does not store memories. It returns a `MemoryRecord`
  (`schema: citrate.learn.memory.v1`) with the evidence, the provenance, the member, and the
  decision `seq`, for core to store.

## Conflicts

| Kind | When | Blocking |
|---|---|---|
| `same_name_skill` | a skill with this name is anywhere in the user skills folder (the loader scans it recursively, so a second copy would make both ambiguous) | yes: never overwritten |
| `shadows_skill` | a skill with this name is in another configured source (bundled, team) | no: needs acknowledgement |
| `pending_proposal` | another undecided proposal for the same skill name or memory key | no: needs acknowledgement |
| `contradiction` | a known memory, or a memory accepted earlier from this learner (`proposal:<id>`), has the same key (case and spacing ignored) and a different value | no: needs acknowledgement; the record is stored as Belnap `both` with `contradicts` set, so core stops relying on either claim until the member resolves it |

An identical item already saved, known, or pending is refused as `already_known`.
Memory contradictions are found against the `known_memories` core passes at proposal time; at
accept time the learner re-checks pending proposals and the memories it has accepted itself
(so of two contradicting proposals accepted one after the other, the second is stored as
`both`), but not core's store, which the runtime does not hold.

## Publishing to SkillRegistry

The contract is citrate-chain `contracts/src/SkillRegistry.sol`:
`registerSkill(string name, string version, string manifestCID, string description, string[] tags)`,
with `skillHash = keccak256(abi.encodePacked(msg.sender, name, version))`.

- The encoding is pinned against `cast calldata` (`tests/fixtures/register_skill_cast.json`).
  On 2026-10-01 a local anvil run deployed `SkillRegistry.sol`, sent the first fixture's calldata
  from anvil account 0, and `getSkill(expected hash)` returned the registered skill with its tags.
- The contract has no content-hash field, so the payload adds two tags: `hermes-learned` and
  `sha256:<SKILL.md sha256>`. `manifestCID` is empty ("pending pin", which the contract allows)
  unless the caller passes a CID; pinning the skill bundle to IPFS is not done here.
- The registry address, chain id and owner come from the caller (core's address book and the
  member's wallet address). Nothing here hardcodes an address.
- Registry names are not unique: readers must resolve by `skillHash` against an owner they trust.
  The payload carries `expected_skill_hash` for that.

## Surviving a restart

`Learner::open(cfg, log, clock, path)` keeps the proposals in a file (`citrate.learn.proposals.v1`)
and rewrites it after every change (temporary file, flush, rename; `0600` on unix). Undecided
proposals are always kept; decided ones are kept up to `MAX_KEPT_DECIDED` (512), oldest dropped
first.

- **Propose** saves before it returns. If the save fails, the proposal is forgotten and the call
  fails with `store`, so nothing a caller was told about can be lost by a restart.
- **Accept, reject, publish** stand once they are in the decision log. If the save after them
  fails, the call still succeeds and `store_error()` says why until a later save succeeds.
- **On open** every stored proposal is re-checked (id, content hash, kind, evidence session and
  verdicts); one that fails is dropped and named in the `LoadReport`. A file that cannot be read
  as a proposals file is moved aside (`<name>.unreadable-<ms>`), never deleted.
- **Reconciling.** The log is written before every effect and the file after it, so the file can
  be one decision behind. On open the log moves such proposals forward: a recorded reject is
  final; a recorded, completed skill accept with the skill on disk is persisted; a recorded
  publish is prepared; a recorded memory accept is offered again (`persist_failed`), because its
  record may never have reached core (core keys memories by proposal id, so accepting again is
  not a duplicate). Model: `formal/LearnRestart.tla`.

## Wiring (HUP-S3.4 end to end)

- The sidecar (`agent-sidecar/src/learn.rs`) serves the learn routes and the `learn_propose` tool
  when `CITRATE_HERMES_LEARN_DIR` and `CITRATE_HERMES_LEARN_SKILLS_DIR` are both set. Verified runs
  come from `POST /sessions/:id/workflows` (`run_verified_workflow` in the session).
- citrate-core shows the proposal card, stores accepted memories, and routes the publish payload
  to its SignatureCeremony (core branch `hup/n4-learn-e2e`).

## Not done here

- Skills only: a proposal is one `SKILL.md`. Bundled `references/` or `scripts/` are not proposed.
- No IPFS pin of the skill bundle, so `manifestCID` is empty unless supplied.
- An accepted skill joins a running sidecar's skill index only after the sidecar restarts (the
  library is loaded at start).
