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
| `contradiction` | a known memory has the same key (case and spacing ignored) and a different value | no: needs acknowledgement; the record is stored as Belnap `both` with `contradicts` set, so core stops relying on either claim until the member resolves it |

An identical item already saved, known, or pending is refused as `already_known`.
Memory contradictions are found against the `known_memories` core passes at proposal time; at
accept time only pending proposals are re-checked, because the runtime does not hold the
memory store.

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

## Not done here

- **Not wired.** No sidecar route or session calls this crate yet; core has no proposal card,
  no accept/reject UI, no memory storage for `MemoryRecord`, and no ceremony hookup for the
  publish payload. Those are the core half of S3.4.
- Proposals live in memory: a sidecar restart drops undecided proposals (decisions already made
  are in the decision log).
- Skills only: a proposal is one `SKILL.md`. Bundled `references/` or `scripts/` are not proposed.
- No IPFS pin of the skill bundle, so `manifestCID` is empty unless supplied.
