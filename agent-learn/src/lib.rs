//! # HUP-S3.4 (runtime half): verified self-learning
//!
//! Hermes may learn a skill or a memory from its own work, under three rules (planset D-22,
//! US-3.4):
//!
//! 1. **Only verified work is learnable.** A [`Proposal`] can only be made from a
//!    [`VerifiedRun`], and the only way to get one is [`run_verified_workflow`], which runs a
//!    workflow and returns it only when every verifier of every step passed. The recorded verdicts
//!    are cross-checked against the workflow, and the proposal carries them, plus a digest of the
//!    trajectory they judged, as its evidence. The model's own claim of success never counts.
//! 2. **Nothing persists without the member.** [`Learner::accept`] writes an HIC-1 decision to the
//!    local decision log (write-ahead), then persists: a skill becomes a `SKILL.md` in the user
//!    skills directory (validated by the agent-loop loader after the write), a memory becomes a
//!    typed [`MemoryRecord`] that core stores. [`Learner::reject`] is recorded too.
//! 3. **Conflicts are surfaced, never merged.** A same-name skill already in the user directory
//!    blocks the proposal (it is never overwritten). A same-name skill in another source, a pending
//!    proposal for the same thing, or a memory that contradicts a known one must be acknowledged
//!    by the member, and a contradicting memory is stored as Belnap `both` (reliance halts).
//!
//! Publishing a persisted skill to the on-chain SkillRegistry is HIC-1:
//! [`Learner::prepare_publish`] requires an explicit [`PublishApproval`] for that exact proposal
//! and content, re-reads the saved file, and builds calldata only ([`registry`]). Nothing in this
//! crate holds a key, signs, or sends (Rule 3); core's SignatureCeremony does the signing.
//!
//! The state machine is model-checked in `formal/SkillPersistence.tla`.
//!
//! Not wired yet: no sidecar route calls this crate today (see `README.md`).

mod evidence;
mod learner;
pub mod registry;

pub use evidence::{
    run_verified_workflow, sha256_hex, trajectory_digest, Evidence, TrajectoryRef, Unverified,
    VerifiedRun, VerifierVerdict,
};
pub use learner::{
    Belnap, Conflict, ConflictKind, KnownMemory, LearnConfig, LearnError, Learner, MemberAccept,
    MemoryRecord, Persisted, Proposal, ProposalContent, ProposalKind, ProposalState, Provenance,
    PublishApproval, PublishParams, SkillPublishPayload, MAX_MEMORY_KEY_LEN, MAX_MEMORY_VALUE_LEN,
    MAX_PENDING, MAX_USER_TAGS, MEMORY_SCHEMA,
};
