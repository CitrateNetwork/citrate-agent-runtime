//! Proposals, the member's decision, persistence, and the publish payload.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use citrate_agent_loop::skills::{parse_skill_md, SkillLibrary, SkillSource, MAX_SKILL_FILE_BYTES};
use citrate_agent_records::{
    Actor, Clock, Decision, DecisionEvent, DecisionLog, EvidenceRef, HicTier, Outcome,
    OutcomeEvent, SystemClock, MAX_EVIDENCE,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::evidence::{sha256_hex, Evidence, VerifiedRun};
use crate::registry;
use crate::store::{self, LoadReport, StoreFile, MAX_KEPT_DECIDED, MAX_RECONCILE_RECORDS};

/// Longest memory key, in bytes.
pub const MAX_MEMORY_KEY_LEN: usize = 256;
/// Longest memory value, in bytes.
pub const MAX_MEMORY_VALUE_LEN: usize = 4096;
/// Most proposals awaiting a decision at once.
pub const MAX_PENDING: usize = 256;
/// Most member-supplied tags on a publish (two more are always added).
pub const MAX_USER_TAGS: usize = 8;
/// The schema tag of a [`MemoryRecord`].
pub const MEMORY_SCHEMA: &str = "citrate.learn.memory.v1";
/// The schema tag of a [`Resolution`].
pub const RESOLUTION_SCHEMA: &str = "citrate.learn.resolve.v1";
/// The decision-log kind of a contradiction resolution.
const RESOLVE_KIND: &str = "learn.memory.resolve";
/// The prefix of a memory core holds that was not learned here (a [`KnownMemory`] id).
pub const KNOWN_MEMORY_PREFIX: &str = "memory:";
/// Longest known-memory id accepted in a resolution, in bytes (after the prefix).
const MAX_KNOWN_MEMORY_ID: usize = 128;
/// Longest reject reason kept, in characters (in the proposal and in the decision log).
const MAX_REASON_CHARS: usize = 1000;
/// Tag added to every publish so readers can tell learned skills apart.
const LEARNED_TAG: &str = "hermes-learned";
const PROPOSAL_DOMAIN: &[u8] = b"citrate.learn.proposal.v1\n";
const MEMORY_DOMAIN: &[u8] = b"citrate.learn.memory.v1\n";

// ---------------------------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    Skill,
    Memory,
}

/// What Hermes proposes to keep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProposalContent {
    /// A complete agentskills.io `SKILL.md` (instructions only; no bundled scripts).
    Skill { skill_md: String },
    /// One keyed fact.
    Memory { key: String, value: String },
}

/// Who produced the proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Must equal the session of the verified run.
    pub session_id: String,
    pub agent: String,
    pub model: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    /// A skill with this name is already in the user skills directory. Blocking: it is never
    /// overwritten.
    SameNameSkill,
    /// A skill with this name is in another source (bundled, team). One would shadow the other.
    ShadowsSkill,
    /// Another pending proposal is about the same skill name or memory key.
    PendingProposal,
    /// A known memory has the same key and a different value (Belnap `both` if accepted).
    Contradiction,
}

/// A clash with an existing item, shown to the member before they decide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    pub kind: ConflictKind,
    /// `skill:<source>/<name>`, `memory:<id>` or `proposal:<id>`.
    pub existing_id: String,
    pub detail: String,
    /// A blocking conflict cannot be accepted, even when acknowledged.
    pub blocking: bool,
}

/// A memory core already holds, supplied when proposing so contradictions can be found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownMemory {
    pub id: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProposalState {
    Proposed,
    Rejected {
        by: String,
        reason: String,
    },
    /// Accepted, but persisting failed; the member may accept again.
    PersistFailed {
        reason: String,
    },
    Persisted,
    /// A publish payload was built for the ceremony. Nothing was sent.
    PublishPrepared,
    /// An accepted memory the member set aside when resolving a contradiction: `kept` is the
    /// proposal whose value they chose instead. Kept for the record (Belnap `false`), never
    /// deleted, and no longer counted as known.
    Retracted {
        by: String,
        kept: String,
    },
}

impl ProposalState {
    fn label(&self) -> &'static str {
        match self {
            ProposalState::Proposed => "proposed",
            ProposalState::Rejected { .. } => "rejected",
            ProposalState::PersistFailed { .. } => "persist_failed",
            ProposalState::Persisted => "persisted",
            ProposalState::PublishPrepared => "publish_prepared",
            ProposalState::Retracted { .. } => "retracted",
        }
    }
    fn awaiting_decision(&self) -> bool {
        matches!(
            self,
            ProposalState::Proposed | ProposalState::PersistFailed { .. }
        )
    }
}

/// A skill or memory Hermes proposes to keep, with the evidence that justifies it.
///
/// It deserializes only so the learner can restore its own proposals file
/// ([`Learner::open`]); a loaded proposal is re-checked before it is kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String,
    pub kind: ProposalKind,
    pub content: ProposalContent,
    /// SHA-256 of the SKILL.md bytes, or of the framed memory key and value.
    pub content_sha256: String,
    pub evidence: Evidence,
    pub provenance: Provenance,
    pub created_at_ms: u64,
    pub conflicts: Vec<Conflict>,
    pub state: ProposalState,
    /// Known memories (`memory:<id>`, not learned here) the member set aside in favour of this
    /// memory when resolving a contradiction. Each one is a recorded HIC-1 decision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub set_aside: Vec<String>,
}

/// The member's accept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberAccept {
    pub member: String,
    /// The `existing_id` of every non-blocking conflict the member saw and accepts anyway.
    #[serde(default)]
    pub acknowledged_conflicts: Vec<String>,
}

/// Belnap value of an accepted memory. A contradiction is `both`: core keeps both claims and
/// stops relying on either until the member resolves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Belnap {
    True,
    Both,
}

/// An accepted memory, for core to store. The runtime does not store memories itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRecord {
    pub schema: String,
    pub proposal_id: String,
    pub key: String,
    pub value: String,
    pub belnap: Belnap,
    /// What this memory contradicts (acknowledged by the member): the id of a known memory
    /// core passed in, or `proposal:<id>` for a memory accepted earlier from this learner
    /// (core holds that one as the record with that `proposal_id`).
    pub contradicts: Vec<String>,
    pub content_sha256: String,
    pub evidence: Evidence,
    pub provenance: Provenance,
    pub accepted_by: String,
    pub accepted_at_ms: u64,
    /// `seq` of the HIC-1 decision record in the local decision log.
    pub decision_seq: u64,
}

/// What an accept produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Persisted {
    Skill {
        name: String,
        path: PathBuf,
        content_sha256: String,
    },
    Memory(Box<MemoryRecord>),
}

/// The member resolves a contradiction between two accepted memories: keep one, retract the
/// other. Both must be persisted memories on the same key (case and spacing ignored) with
/// different values. One side may instead be a memory core holds that was not learned here
/// (`memory:<id>`), when the learned memory's accept acknowledged that contradiction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberResolve {
    pub member: String,
    /// The proposal whose value the member keeps.
    pub keep: String,
    /// The proposal the member retracts.
    pub retract: String,
}

/// A resolved contradiction, for core to apply to its ledger and memory graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolution {
    pub schema: String,
    pub kept: String,
    pub retracted: String,
    pub key: String,
    pub kept_value: String,
    pub retracted_value: String,
    pub decided_by: String,
    pub decided_at_ms: u64,
    /// `seq` of the HIC-1 decision record in the local decision log.
    pub decision_seq: u64,
}

/// The member's explicit approval to prepare a publish of this exact proposal and content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishApproval {
    pub member: String,
    pub proposal_id: String,
    pub content_sha256: String,
}

/// Where and how to publish. The registry address comes from core's address book; nothing here
/// hardcodes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishParams {
    pub chain_id: u64,
    /// SkillRegistry address (`0x` + 40 hex).
    pub registry: String,
    /// The member's address that will sign (the contract keys the skill by `msg.sender`).
    pub owner: String,
    /// `MAJOR.MINOR.PATCH`.
    pub version: String,
    /// IPFS CID of the skill bundle, if already pinned. `None` registers it as "pending pin".
    pub manifest_cid: Option<String>,
    pub tags: Vec<String>,
}

/// An unsigned SkillRegistry call for core's SignatureCeremony. Never sent from here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkillPublishPayload {
    pub chain_id: u64,
    /// Lowercase `0x` address of the registry.
    pub to: String,
    pub value: String,
    /// `0x`-hex calldata.
    pub data: String,
    pub function: String,
    pub name: String,
    pub version: String,
    pub manifest_cid: String,
    pub description: String,
    pub tags: Vec<String>,
    pub owner: String,
    pub content_sha256: String,
    /// `0x`-hex `keccak256(owner, name, version)`, the id the contract will assign.
    pub expected_skill_hash: String,
    /// Always `hic-1`: approve each.
    pub hic: String,
    /// Always false: the runtime builds, core's ceremony signs, the member sends.
    pub broadcast: bool,
    pub proposal_id: String,
}

/// Where accepted skills go and which other skill sources to check for name clashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearnConfig {
    pub user_skills_dir: PathBuf,
    pub other_skill_sources: Vec<SkillSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LearnError {
    #[error("no proposal {0}")]
    UnknownProposal(String),
    #[error("a member id is required")]
    MemberRequired,
    #[error("proposal {id} is {state}")]
    WrongState { id: String, state: String },
    #[error("invalid skill: {0}")]
    InvalidSkill(String),
    #[error("invalid memory: {0}")]
    InvalidMemory(String),
    #[error("provenance session {got:?} does not match the verified run's session {want:?}")]
    ProvenanceMismatch { got: String, want: String },
    #[error("already known as {existing_id}")]
    AlreadyKnown { existing_id: String },
    #[error("more than {MAX_PENDING} proposals are waiting for a decision")]
    TooManyPending,
    #[error("blocked by a conflict that cannot be accepted")]
    Blocked(Vec<Conflict>),
    #[error("conflicts not acknowledged by the member")]
    UnacknowledgedConflicts(Vec<Conflict>),
    #[error("decision log: {0}")]
    Record(String),
    #[error("could not persist: {0}")]
    Persist(String),
    #[error("only skills can be published")]
    NotASkill,
    #[error("the approval is for a different proposal or content")]
    ApprovalMismatch,
    #[error("the saved skill is missing or changed since it was accepted")]
    ContentChanged,
    #[error("invalid publish parameters: {0}")]
    InvalidPublish(String),
    #[error("could not save the proposals file: {0}")]
    Store(String),
    #[error("not a contradiction: {0}")]
    NotAContradiction(String),
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

fn frame(h: &mut Sha256, b: &[u8]) {
    h.update((b.len() as u64).to_be_bytes());
    h.update(b);
}

fn memory_sha(key: &str, value: &str) -> String {
    let mut h = Sha256::new();
    h.update(MEMORY_DOMAIN);
    frame(&mut h, key.as_bytes());
    frame(&mut h, value.as_bytes());
    hex::encode(h.finalize())
}

fn collapse(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn norm_key(k: &str) -> String {
    collapse(k).to_lowercase()
}

fn file_sha(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_SKILL_FILE_BYTES as u64 {
        return None;
    }
    std::fs::read(path).ok().map(|b| sha256_hex(&b))
}

fn invalid<T>(m: impl Into<String>) -> Result<T, LearnError> {
    Err(LearnError::InvalidPublish(m.into()))
}

fn bad_memory(m: &str) -> Result<(), LearnError> {
    Err(LearnError::InvalidMemory(m.into()))
}

fn validate_memory(key: &str, value: &str) -> Result<(), LearnError> {
    if key.trim().is_empty() {
        return bad_memory("key is empty");
    }
    if value.trim().is_empty() {
        return bad_memory("value is empty");
    }
    if key.len() > MAX_MEMORY_KEY_LEN {
        return bad_memory("key is too long");
    }
    if value.len() > MAX_MEMORY_VALUE_LEN {
        return bad_memory("value is too long");
    }
    if key.chars().any(char::is_control) {
        return bad_memory("key has control characters");
    }
    if value
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return bad_memory("value has control characters");
    }
    Ok(())
}

/// Validate a SKILL.md and return its name.
fn validate_skill(md: &str) -> Result<String, LearnError> {
    if md.len() > MAX_SKILL_FILE_BYTES {
        return Err(LearnError::InvalidSkill(format!(
            "SKILL.md is larger than {MAX_SKILL_FILE_BYTES} bytes"
        )));
    }
    let (fm, _body) = parse_skill_md(md).map_err(|e| LearnError::InvalidSkill(e.to_string()))?;
    Ok(fm.name)
}

fn skill_name(p: &Proposal) -> Option<String> {
    match &p.content {
        ProposalContent::Skill { skill_md } => parse_skill_md(skill_md).ok().map(|(fm, _)| fm.name),
        ProposalContent::Memory { .. } => None,
    }
}

// ---------------------------------------------------------------------------------------------
// The learner
// ---------------------------------------------------------------------------------------------

/// Holds proposals and applies the member's decisions.
pub struct Learner {
    cfg: LearnConfig,
    log: Arc<DecisionLog>,
    clock: Arc<dyn Clock>,
    proposals: BTreeMap<String, Proposal>,
    counter: u64,
    /// The proposals file, when the learner was opened with one ([`Learner::open`]).
    store: Option<PathBuf>,
    /// Why the last save failed, until a save succeeds.
    store_error: Option<String>,
}

/// Why a stored proposal is not restored, or `None` when it is consistent.
fn stored_problem(p: &Proposal) -> Option<String> {
    let id_ok = p.id.len() == 27
        && p.id.starts_with("lp-")
        && p.id[3..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !id_ok {
        return Some("malformed id".into());
    }
    let sha = match &p.content {
        ProposalContent::Skill { skill_md } => {
            if p.kind != ProposalKind::Skill {
                return Some("kind does not match the content".into());
            }
            if let Err(e) = validate_skill(skill_md) {
                return Some(e.to_string());
            }
            sha256_hex(skill_md.as_bytes())
        }
        ProposalContent::Memory { key, value } => {
            if p.kind != ProposalKind::Memory {
                return Some("kind does not match the content".into());
            }
            if let Err(e) = validate_memory(key, value) {
                return Some(e.to_string());
            }
            if key.trim() != key || value.trim() != value {
                return Some("memory key or value is not trimmed".into());
            }
            memory_sha(key, value)
        }
    };
    if sha != p.content_sha256 {
        return Some("content does not match its hash".into());
    }
    let ev = &p.evidence;
    if ev.trajectory.session_id != p.provenance.session_id {
        return Some("evidence is from another session".into());
    }
    if ev.verdicts.is_empty() || ev.verdicts.iter().any(|v| !v.passed) {
        return Some("evidence does not show every verifier passing".into());
    }
    if ev
        .verdicts
        .iter()
        .any(|v| !ev.steps.iter().any(|s| s == &v.step))
    {
        return Some("evidence names a step that is not in the workflow".into());
    }
    if ev.trajectory.sha256.len() != 64 {
        return Some("malformed trajectory digest".into());
    }
    if !p.set_aside.is_empty()
        && (p.kind != ProposalKind::Memory || !p.set_aside.iter().all(|x| valid_known_ref(x)))
    {
        return Some("malformed set-aside memory".into());
    }
    None
}

/// `memory:<id>`: a known memory core holds, 1..=[`MAX_KNOWN_MEMORY_ID`] printable ASCII bytes
/// with no spaces.
fn valid_known_ref(r: &str) -> bool {
    r.strip_prefix(KNOWN_MEMORY_PREFIX).is_some_and(|id| {
        !id.is_empty()
            && id.len() <= MAX_KNOWN_MEMORY_ID
            && id.bytes().all(|b| b.is_ascii_graphic())
    })
}

impl Learner {
    pub fn new(cfg: LearnConfig, log: Arc<DecisionLog>) -> Self {
        Self::with_clock(cfg, log, Arc::new(SystemClock))
    }

    pub fn with_clock(cfg: LearnConfig, log: Arc<DecisionLog>, clock: Arc<dyn Clock>) -> Self {
        Learner {
            cfg,
            log,
            clock,
            proposals: BTreeMap::new(),
            counter: 0,
            store: None,
            store_error: None,
        }
    }

    /// A learner whose proposals survive a restart: they are restored from `store_path` (if it
    /// exists) and the file is rewritten after every change. Never fails: inconsistent proposals
    /// are dropped and an unreadable file is moved aside, as the [`LoadReport`] says.
    pub fn open(
        cfg: LearnConfig,
        log: Arc<DecisionLog>,
        clock: Arc<dyn Clock>,
        store_path: &Path,
    ) -> (Self, LoadReport) {
        let mut l = Self::with_clock(cfg, log, clock);
        l.store = Some(store_path.to_path_buf());
        let mut report = LoadReport::default();
        match store::read_file(store_path) {
            Ok(None) => {}
            Ok(Some(file)) => {
                l.counter = file.counter;
                for p in file.proposals {
                    if l.proposals.contains_key(&p.id) {
                        report.dropped.push((p.id, "duplicate id".into()));
                        continue;
                    }
                    if let Some(why) = stored_problem(&p) {
                        report.dropped.push((p.id, why));
                        continue;
                    }
                    l.proposals.insert(p.id.clone(), p);
                }
                report.loaded = l.proposals.len();
            }
            Err(_) => {
                report.moved_aside = store::move_aside(store_path, l.clock.now_ms());
            }
        }
        match l.reconcile_with_log() {
            Ok(0) => {}
            Ok(n) => {
                report.reconciled = n;
                l.save_after_decision();
            }
            Err(e) => report.log_error = Some(e),
        }
        (l, report)
    }

    /// The decision log is written before every effect, the proposals file after it, so a crash
    /// or a failed save can leave the file one decision behind. Move such proposals forward:
    /// a recorded reject is final; a recorded, completed skill accept whose file is on disk is
    /// persisted; a recorded publish is prepared. A recorded memory accept is offered again
    /// (`persist_failed`): its record may never have reached core, and core keys records by
    /// proposal id, so accepting again is safe. A recorded resolution retracts the memory it set
    /// aside (`formal/ContradictionResolve.tla`). Returns how many proposals moved.
    fn reconcile_with_log(&mut self) -> Result<usize, String> {
        use citrate_agent_records::Entry;
        let mut records =
            citrate_agent_records::read::page(self.log.dir(), None, MAX_RECONCILE_RECORDS)
                .map_err(|e| e.to_string())?;
        records.sort_by_key(|r| r.record.seq);
        // decision seq -> outcome
        let mut outcomes: BTreeMap<u64, Outcome> = BTreeMap::new();
        for r in &records {
            if let Entry::Outcome(o) = &r.record.entry {
                outcomes.insert(o.decision_seq, o.outcome);
            }
        }
        // proposal id -> latest (seq, kind, decision, actor, reason, kept)
        type Latest = (u64, String, Decision, String, String, Option<String>);
        let mut latest: BTreeMap<String, Latest> = BTreeMap::new();
        // (kept learned proposal, known memory set aside), from recorded resolutions.
        let mut set_asides: Vec<(String, String)> = Vec::new();
        for r in &records {
            let Entry::Decision(d) = &r.record.entry else {
                continue;
            };
            if d.kind == RESOLVE_KIND && d.decision == Decision::Approved {
                let aside = d
                    .evidence
                    .iter()
                    .find_map(|e| e.uri.strip_prefix("learn:set-aside/"));
                let kept = d
                    .evidence
                    .iter()
                    .find_map(|e| e.uri.strip_prefix("learn:kept/"));
                if let (Some(aside), Some(kept)) = (aside, kept) {
                    if valid_known_ref(aside) {
                        set_asides.push((kept.to_string(), aside.to_string()));
                    }
                    continue;
                }
            }
            if !matches!(
                d.kind.as_str(),
                "learn.skill" | "learn.memory" | "skill.publish" | RESOLVE_KIND
            ) {
                continue;
            }
            let Some(id) = d
                .evidence
                .iter()
                .find_map(|e| e.uri.strip_prefix("learn:proposal/"))
            else {
                continue;
            };
            let kept = d
                .evidence
                .iter()
                .find_map(|e| e.uri.strip_prefix("learn:kept/"))
                .map(str::to_string);
            latest.insert(
                id.to_string(),
                (
                    r.record.seq,
                    d.kind.clone(),
                    d.decision,
                    r.record.actor.id.clone(),
                    d.reason.clone(),
                    kept,
                ),
            );
        }
        let mut moved = 0;
        let ids: Vec<String> = self.proposals.keys().cloned().collect();
        for id in ids {
            let Some((seq, kind, decision, actor, reason, kept)) = latest.get(&id).cloned() else {
                continue;
            };
            let Some(p) = self.proposals.get(&id) else {
                continue;
            };
            let completed = matches!(outcomes.get(&seq), Some(Outcome::Completed));
            let next = match (&p.state, kind.as_str(), &decision) {
                (s, "learn.skill" | "learn.memory", Decision::Denied) if s.awaiting_decision() => {
                    Some(ProposalState::Rejected { by: actor, reason })
                }
                (ProposalState::Proposed, "learn.skill", Decision::Approved) => {
                    let on_disk = skill_name(p)
                        .map(|n| self.skill_dir(&n).join("SKILL.md"))
                        .and_then(|f| file_sha(&f))
                        .is_some_and(|sha| sha == p.content_sha256);
                    Some(if completed && on_disk {
                        ProposalState::Persisted
                    } else {
                        ProposalState::PersistFailed {
                            reason: "an accept was recorded but did not complete before a restart"
                                .into(),
                        }
                    })
                }
                (ProposalState::Proposed, "learn.memory", Decision::Approved) => {
                    Some(ProposalState::PersistFailed {
                        reason:
                            "accepted before a restart; accept again so the app receives the memory"
                                .into(),
                    })
                }
                (ProposalState::Persisted, "skill.publish", Decision::Approved) => {
                    Some(ProposalState::PublishPrepared)
                }
                // A recorded resolution retracts the memory whatever the file says: the resolve
                // needed a completed accept, so a file that also lost that accept (proposed or
                // persist_failed) must not offer the memory for accepting again.
                (
                    ProposalState::Proposed
                    | ProposalState::PersistFailed { .. }
                    | ProposalState::Persisted,
                    RESOLVE_KIND,
                    Decision::Approved,
                ) if p.kind == ProposalKind::Memory => {
                    kept.map(|kept| ProposalState::Retracted { by: actor, kept })
                }
                _ => None,
            };
            if let (Some(next), Some(p)) = (next, self.proposals.get_mut(&id)) {
                p.state = next;
                moved += 1;
            }
        }
        // A recorded set-aside of a known memory holds whatever the file says.
        for (kept, aside) in set_asides {
            if let Some(p) = self.proposals.get_mut(&kept) {
                if p.kind == ProposalKind::Memory && !p.set_aside.contains(&aside) {
                    p.set_aside.push(aside);
                    moved += 1;
                }
            }
        }
        Ok(moved)
    }

    /// Why the proposals file could not be saved, if the last save failed. Decisions already
    /// made are in the decision log; a restart would show stale proposal states until a later
    /// save succeeds.
    pub fn store_error(&self) -> Option<&str> {
        self.store_error.as_deref()
    }

    /// Every proposal the learner holds (undecided and recent decided ones), oldest first.
    pub fn all(&self) -> Vec<&Proposal> {
        let mut v: Vec<&Proposal> = self.proposals.values().collect();
        v.sort_by(|a, b| (a.created_at_ms, &a.id).cmp(&(b.created_at_ms, &b.id)));
        v
    }

    /// Drop the oldest decided proposals beyond [`MAX_KEPT_DECIDED`].
    fn prune(&mut self) {
        let mut decided: Vec<(u64, String)> = self
            .proposals
            .values()
            .filter(|p| !p.state.awaiting_decision())
            .map(|p| (p.created_at_ms, p.id.clone()))
            .collect();
        if decided.len() <= MAX_KEPT_DECIDED {
            return;
        }
        decided.sort();
        let excess = decided.len() - MAX_KEPT_DECIDED;
        for (_, id) in decided.into_iter().take(excess) {
            self.proposals.remove(&id);
        }
    }

    /// Rewrite the proposals file (no-op without a store).
    fn save(&mut self) -> Result<(), String> {
        let Some(path) = self.store.clone() else {
            return Ok(());
        };
        self.prune();
        let file = StoreFile {
            schema: store::STORE_SCHEMA.into(),
            counter: self.counter,
            proposals: self.all().into_iter().cloned().collect(),
        };
        let res = store::write_file(&path, &file);
        self.store_error = res.as_ref().err().cloned();
        res
    }

    /// Save after a decision: the decision stands (it is in the decision log) even when the
    /// save fails; the failure is kept for [`Learner::store_error`].
    fn save_after_decision(&mut self) {
        let _ = self.save();
    }

    pub fn get(&self, id: &str) -> Option<&Proposal> {
        self.proposals.get(id)
    }

    /// Proposals waiting for the member, oldest first.
    pub fn pending(&self) -> Vec<&Proposal> {
        let mut v: Vec<&Proposal> = self
            .proposals
            .values()
            .filter(|p| p.state.awaiting_decision())
            .collect();
        v.sort_by(|a, b| (a.created_at_ms, &a.id).cmp(&(b.created_at_ms, &b.id)));
        v
    }

    fn skill_dir(&self, name: &str) -> PathBuf {
        self.cfg.user_skills_dir.join(name)
    }

    /// Conflicts for a skill, or `AlreadyKnown` when the identical skill is already there.
    fn skill_conflicts(
        &self,
        name: &str,
        sha: &str,
        exclude: Option<&str>,
    ) -> Result<Vec<Conflict>, LearnError> {
        let mut out = Vec::new();
        let user_id = format!("skill:user/{name}");
        let direct = self.skill_dir(name);
        let user_lib = if self.cfg.user_skills_dir.is_dir() {
            SkillLibrary::load(&[SkillSource::new("user", &self.cfg.user_skills_dir)])
        } else {
            SkillLibrary::empty()
        };
        let direct_exists = std::fs::symlink_metadata(&direct).is_ok();
        if direct_exists || user_lib.get(name).is_some() {
            if file_sha(&direct.join("SKILL.md")).as_deref() == Some(sha) {
                return Err(LearnError::AlreadyKnown {
                    existing_id: user_id,
                });
            }
            out.push(Conflict {
                kind: ConflictKind::SameNameSkill,
                existing_id: user_id,
                detail: format!(
                    "a different skill named {name} is already in your skills folder; it is never overwritten"
                ),
                blocking: true,
            });
        }
        if !self.cfg.other_skill_sources.is_empty() {
            let other = SkillLibrary::load(&self.cfg.other_skill_sources);
            if let Some(s) = other.get(name) {
                out.push(Conflict {
                    kind: ConflictKind::ShadowsSkill,
                    existing_id: format!("skill:{}/{name}", s.source),
                    detail: format!(
                        "a skill named {name} also exists in {}; one will shadow the other",
                        s.source
                    ),
                    blocking: false,
                });
            }
        }
        for p in self.proposals.values() {
            if Some(p.id.as_str()) == exclude || !p.state.awaiting_decision() {
                continue;
            }
            if skill_name(p).as_deref() == Some(name) {
                if p.content_sha256 == sha {
                    return Err(LearnError::AlreadyKnown {
                        existing_id: format!("proposal:{}", p.id),
                    });
                }
                out.push(Conflict {
                    kind: ConflictKind::PendingProposal,
                    existing_id: format!("proposal:{}", p.id),
                    detail: format!("another pending proposal also defines the skill {name}"),
                    blocking: false,
                });
            }
        }
        Ok(out)
    }

    fn memory_conflicts(
        &self,
        key: &str,
        value: &str,
        known: &[KnownMemory],
        exclude: Option<&str>,
    ) -> Result<Vec<Conflict>, LearnError> {
        let (k, v) = (norm_key(key), collapse(value));
        let mut out = Vec::new();
        for m in known {
            if norm_key(&m.key) != k {
                continue;
            }
            if collapse(&m.value) == v {
                return Err(LearnError::AlreadyKnown {
                    existing_id: format!("memory:{}", m.id),
                });
            }
            out.push(Conflict {
                kind: ConflictKind::Contradiction,
                existing_id: format!("memory:{}", m.id),
                detail: format!(
                    "the known memory {} says something different for {}",
                    m.id,
                    collapse(key)
                ),
                blocking: false,
            });
        }
        for p in self.proposals.values() {
            if Some(p.id.as_str()) == exclude {
                continue;
            }
            // A memory accepted from this learner is a known memory too, even before core
            // passes it back in `known`: a later proposal that disagrees is a contradiction.
            // A memory in `persist_failed` was accepted too: a memory's persist only fails when
            // a restart found its accept recorded but not saved, and core may already hold it
            // (formal/ContradictionResolve.tla). A retracted memory is no longer known.
            let accepted = matches!(p.state, ProposalState::Persisted)
                || (p.kind == ProposalKind::Memory
                    && matches!(p.state, ProposalState::PersistFailed { .. }));
            if !accepted && !p.state.awaiting_decision() {
                continue;
            }
            if let ProposalContent::Memory { key: pk, value: pv } = &p.content {
                if norm_key(pk) != k {
                    continue;
                }
                if collapse(pv) == v {
                    return Err(LearnError::AlreadyKnown {
                        existing_id: format!("proposal:{}", p.id),
                    });
                }
                out.push(if accepted {
                    Conflict {
                        kind: ConflictKind::Contradiction,
                        existing_id: format!("proposal:{}", p.id),
                        detail: format!(
                            "a memory you accepted earlier says something different for {}",
                            collapse(key)
                        ),
                        blocking: false,
                    }
                } else {
                    Conflict {
                        kind: ConflictKind::PendingProposal,
                        existing_id: format!("proposal:{}", p.id),
                        detail: format!("another pending proposal is about {}", collapse(key)),
                        blocking: false,
                    }
                });
            }
        }
        Ok(out)
    }

    /// Propose a skill or memory from a verified run. Nothing is written and nothing is recorded:
    /// a proposal is not a decision.
    pub fn propose(
        &mut self,
        run: &VerifiedRun,
        content: ProposalContent,
        provenance: Provenance,
        known_memories: &[KnownMemory],
    ) -> Result<Proposal, LearnError> {
        let evidence = run.evidence().clone();
        if provenance.session_id != evidence.trajectory.session_id {
            return Err(LearnError::ProvenanceMismatch {
                got: provenance.session_id,
                want: evidence.trajectory.session_id,
            });
        }
        if self.pending().len() >= MAX_PENDING {
            return Err(LearnError::TooManyPending);
        }
        let (kind, content, sha, conflicts) = match content {
            ProposalContent::Skill { skill_md } => {
                let name = validate_skill(&skill_md)?;
                let sha = sha256_hex(skill_md.as_bytes());
                let conflicts = self.skill_conflicts(&name, &sha, None)?;
                (
                    ProposalKind::Skill,
                    ProposalContent::Skill { skill_md },
                    sha,
                    conflicts,
                )
            }
            ProposalContent::Memory { key, value } => {
                validate_memory(&key, &value)?;
                let (key, value) = (key.trim().to_string(), value.trim().to_string());
                let sha = memory_sha(&key, &value);
                let conflicts = self.memory_conflicts(&key, &value, known_memories, None)?;
                (
                    ProposalKind::Memory,
                    ProposalContent::Memory { key, value },
                    sha,
                    conflicts,
                )
            }
        };
        let created_at_ms = self.clock.now_ms();
        self.counter = self.counter.wrapping_add(1);
        let mut h = Sha256::new();
        h.update(PROPOSAL_DOMAIN);
        frame(&mut h, sha.as_bytes());
        frame(&mut h, evidence.trajectory.sha256.as_bytes());
        h.update(created_at_ms.to_be_bytes());
        h.update(self.counter.to_be_bytes());
        let digest = hex::encode(h.finalize());
        let id = format!("lp-{}", digest.get(..24).unwrap_or(&digest));
        let p = Proposal {
            id: id.clone(),
            kind,
            content,
            content_sha256: sha,
            evidence,
            provenance,
            created_at_ms,
            conflicts,
            state: ProposalState::Proposed,
            set_aside: Vec::new(),
        };
        self.proposals.insert(id.clone(), p.clone());
        if let Err(e) = self.save() {
            // Nothing was decided yet: keep memory and file in step by forgetting it.
            self.proposals.remove(&id);
            return Err(LearnError::Store(e));
        }
        Ok(p)
    }

    fn lookup(&self, id: &str) -> Result<&Proposal, LearnError> {
        self.proposals
            .get(id)
            .ok_or_else(|| LearnError::UnknownProposal(id.to_string()))
    }

    fn wrong_state(p: &Proposal) -> LearnError {
        LearnError::WrongState {
            id: p.id.clone(),
            state: p.state.label().to_string(),
        }
    }

    fn evidence_refs(p: &Proposal) -> Vec<EvidenceRef> {
        let mut refs = vec![
            EvidenceRef {
                kind: "proposal".into(),
                uri: format!("learn:proposal/{}", p.id),
                digest: Some(p.content_sha256.clone()),
            },
            EvidenceRef {
                kind: "trajectory".into(),
                uri: format!(
                    "session:{}/workflow:{}",
                    p.evidence.trajectory.session_id, p.evidence.trajectory.workflow_id
                ),
                digest: Some(p.evidence.trajectory.sha256.clone()),
            },
        ];
        for v in &p.evidence.verdicts {
            if refs.len() >= MAX_EVIDENCE {
                break;
            }
            refs.push(EvidenceRef {
                kind: "verifier".into(),
                uri: format!("verifier:{}/{}", v.step, v.name),
                digest: None,
            });
        }
        refs
    }

    fn decision_kind(p: &Proposal) -> &'static str {
        match p.kind {
            ProposalKind::Skill => "learn.skill",
            ProposalKind::Memory => "learn.memory",
        }
    }

    fn subject(p: &Proposal) -> String {
        let short = p.content_sha256.get(..12).unwrap_or(&p.content_sha256);
        match &p.content {
            ProposalContent::Skill { .. } => format!(
                "persist skill {} (sha256 {short})",
                skill_name(p).unwrap_or_default()
            ),
            ProposalContent::Memory { key, .. } => {
                let k: String = key.chars().take(200).collect();
                format!("persist memory {k} (sha256 {short})")
            }
        }
    }

    /// The member rejects a proposal. Recorded as an HIC-1 denial; nothing persists.
    pub fn reject(&mut self, id: &str, member: &str, reason: &str) -> Result<(), LearnError> {
        if member.trim().is_empty() {
            return Err(LearnError::MemberRequired);
        }
        let p = self.lookup(id)?;
        if !p.state.awaiting_decision() {
            return Err(Self::wrong_state(p));
        }
        let reason: String = reason.chars().take(MAX_REASON_CHARS).collect();
        let ev = DecisionEvent {
            tier: HicTier::Hic1,
            kind: Self::decision_kind(p).into(),
            subject: Self::subject(p),
            decision: Decision::Denied,
            reason: reason.clone(),
            evidence: Self::evidence_refs(p),
        };
        self.log
            .record_decision(Actor::member(member), ev)
            .map_err(|e| LearnError::Record(e.to_string()))?;
        if let Some(p) = self.proposals.get_mut(id) {
            p.state = ProposalState::Rejected {
                by: member.to_string(),
                reason,
            };
        }
        self.save_after_decision();
        Ok(())
    }

    /// The member accepts a proposal: record the HIC-1 decision, then persist.
    pub fn accept(&mut self, id: &str, decision: MemberAccept) -> Result<Persisted, LearnError> {
        if decision.member.trim().is_empty() {
            return Err(LearnError::MemberRequired);
        }
        let p = self.lookup(id)?.clone();
        if !p.state.awaiting_decision() {
            return Err(Self::wrong_state(&p));
        }
        // Re-check conflicts now: the world may have changed since the proposal was made.
        let fresh = match &p.content {
            ProposalContent::Skill { .. } => {
                let name = skill_name(&p).unwrap_or_default();
                self.skill_conflicts(&name, &p.content_sha256, Some(id))?
            }
            ProposalContent::Memory { key, value } => {
                let mut c = self.memory_conflicts(key, value, &[], Some(id))?;
                // Contradictions with known memories were found at proposal time; keep them
                // (once each: one with an accepted proposal is also in the fresh set).
                for x in &p.conflicts {
                    if x.kind == ConflictKind::Contradiction
                        && !c.iter().any(|y| y.existing_id == x.existing_id)
                    {
                        c.push(x.clone());
                    }
                }
                c
            }
        };
        // The fresh set replaces the stored one: new clashes appear, and clashes that no longer
        // hold (a pending proposal that was decided) drop out.
        let merged = fresh;
        if let Some(stored) = self.proposals.get_mut(id) {
            stored.conflicts = merged.clone();
        }
        let blocking: Vec<Conflict> = merged.iter().filter(|c| c.blocking).cloned().collect();
        if !blocking.is_empty() {
            return Err(LearnError::Blocked(blocking));
        }
        let acked: BTreeSet<&str> = decision
            .acknowledged_conflicts
            .iter()
            .map(String::as_str)
            .collect();
        let missing: Vec<Conflict> = merged
            .iter()
            .filter(|c| !acked.contains(c.existing_id.as_str()))
            .cloned()
            .collect();
        if !missing.is_empty() {
            return Err(LearnError::UnacknowledgedConflicts(missing));
        }

        let actor = Actor::member(decision.member.as_str());
        let ev = DecisionEvent {
            tier: HicTier::Hic1,
            kind: Self::decision_kind(&p).into(),
            subject: Self::subject(&p),
            decision: Decision::Approved,
            reason: if merged.is_empty() {
                "member accepted a verified proposal".into()
            } else {
                format!(
                    "member accepted a verified proposal and acknowledged: {}",
                    merged
                        .iter()
                        .map(|c| c.existing_id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            },
            evidence: Self::evidence_refs(&p),
        };
        let receipt = self
            .log
            .record_decision(actor.clone(), ev)
            .map_err(|e| LearnError::Record(e.to_string()))?;

        let result = match &p.content {
            ProposalContent::Skill { skill_md } => self.persist_skill(&p, skill_md),
            ProposalContent::Memory { key, value } => {
                let contradicts: Vec<String> = merged
                    .iter()
                    .filter(|c| c.kind == ConflictKind::Contradiction)
                    .map(|c| {
                        c.existing_id
                            .strip_prefix("memory:")
                            .unwrap_or(&c.existing_id)
                            .to_string()
                    })
                    .collect();
                Ok(Persisted::Memory(Box::new(MemoryRecord {
                    schema: MEMORY_SCHEMA.into(),
                    proposal_id: p.id.clone(),
                    key: key.clone(),
                    value: value.clone(),
                    belnap: if contradicts.is_empty() {
                        Belnap::True
                    } else {
                        Belnap::Both
                    },
                    contradicts,
                    content_sha256: p.content_sha256.clone(),
                    evidence: p.evidence.clone(),
                    provenance: p.provenance.clone(),
                    accepted_by: decision.member.clone(),
                    accepted_at_ms: receipt.ts_ms,
                    decision_seq: receipt.seq,
                })))
            }
        };

        let (outcome, detail) = match &result {
            Ok(Persisted::Skill { path, .. }) => (
                Outcome::Completed,
                format!("skill written to {}", path.display()),
            ),
            Ok(Persisted::Memory(_)) => (
                Outcome::Completed,
                "memory record handed to core for storage".to_string(),
            ),
            Err(e) => (Outcome::Failed, e.to_string()),
        };
        let closed = self.log.record_outcome(
            actor,
            OutcomeEvent {
                decision_seq: receipt.seq,
                outcome,
                detail,
            },
        );
        if let Some(stored) = self.proposals.get_mut(id) {
            stored.state = match &result {
                Ok(_) => ProposalState::Persisted,
                Err(e) => ProposalState::PersistFailed {
                    reason: e.to_string(),
                },
            };
        }
        self.save_after_decision();
        let persisted = result?;
        // The skill is on disk even if closing the record failed; the log's recovery marks the
        // decision outcome_unknown on next open, which is the honest state.
        closed.map_err(|e| LearnError::Record(e.to_string()))?;
        Ok(persisted)
    }

    fn persist_skill(&self, p: &Proposal, md: &str) -> Result<Persisted, LearnError> {
        let name = validate_skill(md)?;
        let root = &self.cfg.user_skills_dir;
        let perr =
            |what: &str, e: std::io::Error| LearnError::Persist(format!("{what}: {}", e.kind()));
        std::fs::create_dir_all(root).map_err(|e| perr("create the skills folder", e))?;
        let fin = root.join(&name);
        if std::fs::symlink_metadata(&fin).is_ok() {
            return Err(LearnError::Persist(format!(
                "{name} appeared in the skills folder before it could be written"
            )));
        }
        // Stage in a hidden directory (the loader skips hidden dirs), then rename into place.
        let tmp = root.join(format!(".learn-{}", p.id));
        if std::fs::symlink_metadata(&tmp).is_ok() {
            std::fs::remove_dir_all(&tmp).map_err(|e| perr("clear the staging folder", e))?;
        }
        let staged = (|| -> std::io::Result<()> {
            std::fs::create_dir(&tmp)?;
            let mut f = std::fs::File::create(tmp.join("SKILL.md"))?;
            f.write_all(md.as_bytes())?;
            f.sync_all()?;
            Ok(())
        })();
        if let Err(e) = staged {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(perr("stage the skill", e));
        }
        if let Err(e) = std::fs::rename(&tmp, &fin) {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(perr("move the skill into place", e));
        }
        // Validate with the same loader Hermes uses.
        let lib = SkillLibrary::load(&[SkillSource::new("user", root)]);
        let canon_fin = std::fs::canonicalize(&fin).ok();
        let loaded_here = lib
            .get(&name)
            .is_some_and(|s| Some(&s.dir) == canon_fin.as_ref());
        let path = fin.join("SKILL.md");
        if !loaded_here || file_sha(&path).as_deref() != Some(p.content_sha256.as_str()) {
            let why = lib
                .report()
                .rejected
                .iter()
                .find(|r| r.path.starts_with(&fin) || r.reason.contains(&name))
                .map(|r| r.reason.clone())
                .unwrap_or_else(|| "the skill loader did not load it".into());
            let _ = std::fs::remove_dir_all(&fin);
            return Err(LearnError::Persist(why));
        }
        Ok(Persisted::Skill {
            name,
            path,
            content_sha256: p.content_sha256.clone(),
        })
    }

    /// The member resolves a contradiction between two accepted memories: `keep` stays, `retract`
    /// is retracted (kept for the record, no longer known). The HIC-1 decision is written to the
    /// log first; the retracted proposal changes state only after it is recorded. Returns the
    /// [`Resolution`] core applies to its ledger and memory graph.
    pub fn resolve(&mut self, r: MemberResolve) -> Result<Resolution, LearnError> {
        if r.member.trim().is_empty() {
            return Err(LearnError::MemberRequired);
        }
        if r.keep.starts_with(KNOWN_MEMORY_PREFIX) || r.retract.starts_with(KNOWN_MEMORY_PREFIX) {
            return self.resolve_known(r);
        }
        let keep = self.lookup(&r.keep)?.clone();
        let drop = self.lookup(&r.retract)?.clone();
        if keep.id == drop.id {
            return Err(LearnError::NotAContradiction(
                "a memory cannot be kept and retracted at once".into(),
            ));
        }
        let (
            ProposalContent::Memory { key: kk, value: kv },
            ProposalContent::Memory { key: dk, value: dv },
        ) = (&keep.content, &drop.content)
        else {
            return Err(LearnError::NotAContradiction(
                "only two memories can be resolved".into(),
            ));
        };
        for p in [&keep, &drop] {
            if !matches!(p.state, ProposalState::Persisted) {
                return Err(Self::wrong_state(p));
            }
        }
        if norm_key(kk) != norm_key(dk) {
            return Err(LearnError::NotAContradiction(
                "the two memories are about different keys".into(),
            ));
        }
        if collapse(kv) == collapse(dv) {
            return Err(LearnError::NotAContradiction(
                "the two memories say the same thing".into(),
            ));
        }
        let mut evidence = Self::evidence_refs(&drop);
        evidence.truncate(MAX_EVIDENCE.saturating_sub(1));
        evidence.insert(
            1,
            EvidenceRef {
                kind: "kept".into(),
                uri: format!("learn:kept/{}", keep.id),
                digest: Some(keep.content_sha256.clone()),
            },
        );
        evidence.truncate(MAX_EVIDENCE);
        let key: String = collapse(kk).chars().take(200).collect();
        let actor = Actor::member(r.member.as_str());
        let receipt = self
            .log
            .record_decision(
                actor.clone(),
                DecisionEvent {
                    tier: HicTier::Hic1,
                    kind: RESOLVE_KIND.into(),
                    subject: format!(
                        "resolve memory {key}: keep {}, retract {}",
                        keep.id, drop.id
                    ),
                    decision: Decision::Approved,
                    reason: "member resolved a contradiction between two learned memories".into(),
                    evidence,
                },
            )
            .map_err(|e| LearnError::Record(e.to_string()))?;
        if let Some(stored) = self.proposals.get_mut(&drop.id) {
            stored.state = ProposalState::Retracted {
                by: r.member.clone(),
                kept: keep.id.clone(),
            };
        }
        self.save_after_decision();
        self.log
            .record_outcome(
                actor,
                OutcomeEvent {
                    decision_seq: receipt.seq,
                    outcome: Outcome::Completed,
                    detail: format!("{} retracted in favour of {}", drop.id, keep.id),
                },
            )
            .map_err(|e| LearnError::Record(e.to_string()))?;
        Ok(Resolution {
            schema: RESOLUTION_SCHEMA.into(),
            kept: keep.id,
            retracted: drop.id,
            key: kk.clone(),
            kept_value: kv.clone(),
            retracted_value: dv.clone(),
            decided_by: r.member,
            decided_at_ms: receipt.ts_ms,
            decision_seq: receipt.seq,
        })
    }

    /// Resolve a contradiction between a learned memory and a memory core holds that was not
    /// learned here (`memory:<id>`, acknowledged when the learned memory was accepted). Keeping
    /// the known memory retracts the learned one, as between two learned memories. Keeping the
    /// learned memory sets the known one aside: the learned memory records it in
    /// [`Proposal::set_aside`], and core retires it in its own store. The learner never held the
    /// known memory's value, so the [`Resolution`] carries it empty. HIC-1, recorded first.
    fn resolve_known(&mut self, r: MemberResolve) -> Result<Resolution, LearnError> {
        let keep_known = r.keep.starts_with(KNOWN_MEMORY_PREFIX);
        let drop_known = r.retract.starts_with(KNOWN_MEMORY_PREFIX);
        if keep_known && drop_known {
            return Err(LearnError::NotAContradiction(
                "two memories that were not learned here are not resolved here".into(),
            ));
        }
        let (known, learned_id) = if drop_known {
            (r.retract.as_str(), r.keep.as_str())
        } else {
            (r.keep.as_str(), r.retract.as_str())
        };
        if !valid_known_ref(known) {
            return Err(LearnError::NotAContradiction(format!(
                "{known:?} is not a memory id"
            )));
        }
        let learned = self.lookup(learned_id)?.clone();
        let ProposalContent::Memory { key, value } = &learned.content else {
            return Err(LearnError::NotAContradiction(
                "only two memories can be resolved".into(),
            ));
        };
        if !matches!(learned.state, ProposalState::Persisted) {
            return Err(Self::wrong_state(&learned));
        }
        let acknowledged = learned
            .conflicts
            .iter()
            .any(|c| c.kind == ConflictKind::Contradiction && c.existing_id == known);
        if !acknowledged {
            return Err(LearnError::NotAContradiction(format!(
                "the learned memory {} does not contradict {known}",
                learned.id
            )));
        }
        if learned.set_aside.iter().any(|x| x == known) {
            return Err(LearnError::NotAContradiction(format!(
                "{known} was already set aside in favour of {}",
                learned.id
            )));
        }
        let evidence = if drop_known {
            // The learned memory stays: it is the kept side, never the subject of a retraction.
            let mut ev = vec![
                EvidenceRef {
                    kind: "set_aside".into(),
                    uri: format!("learn:set-aside/{known}"),
                    digest: None,
                },
                EvidenceRef {
                    kind: "kept".into(),
                    uri: format!("learn:kept/{}", learned.id),
                    digest: Some(learned.content_sha256.clone()),
                },
            ];
            ev.extend(
                Self::evidence_refs(&learned)
                    .into_iter()
                    .filter(|x| !x.uri.starts_with("learn:proposal/")),
            );
            ev.truncate(MAX_EVIDENCE);
            ev
        } else {
            let mut ev = Self::evidence_refs(&learned);
            ev.truncate(MAX_EVIDENCE.saturating_sub(1));
            ev.insert(
                1,
                EvidenceRef {
                    kind: "kept".into(),
                    uri: format!("learn:kept/{known}"),
                    digest: None,
                },
            );
            ev.truncate(MAX_EVIDENCE);
            ev
        };
        let short_key: String = collapse(key).chars().take(200).collect();
        let actor = Actor::member(r.member.as_str());
        let receipt = self
            .log
            .record_decision(
                actor.clone(),
                DecisionEvent {
                    tier: HicTier::Hic1,
                    kind: RESOLVE_KIND.into(),
                    subject: format!(
                        "resolve memory {short_key}: keep {}, retract {}",
                        r.keep, r.retract
                    ),
                    decision: Decision::Approved,
                    reason: "member resolved a contradiction between a learned memory and one the app already held".into(),
                    evidence,
                },
            )
            .map_err(|e| LearnError::Record(e.to_string()))?;
        if let Some(stored) = self.proposals.get_mut(&learned.id) {
            if drop_known {
                stored.set_aside.push(known.to_string());
            } else {
                stored.state = ProposalState::Retracted {
                    by: r.member.clone(),
                    kept: known.to_string(),
                };
            }
        }
        self.save_after_decision();
        let detail = if drop_known {
            format!("{known} set aside in favour of {}", learned.id)
        } else {
            format!("{} retracted in favour of {known}", learned.id)
        };
        self.log
            .record_outcome(
                actor,
                OutcomeEvent {
                    decision_seq: receipt.seq,
                    outcome: Outcome::Completed,
                    detail,
                },
            )
            .map_err(|e| LearnError::Record(e.to_string()))?;
        let (kept_value, retracted_value) = if drop_known {
            (value.clone(), String::new())
        } else {
            (String::new(), value.clone())
        };
        Ok(Resolution {
            schema: RESOLUTION_SCHEMA.into(),
            kept: r.keep,
            retracted: r.retract,
            key: key.clone(),
            kept_value,
            retracted_value,
            decided_by: r.member,
            decided_at_ms: receipt.ts_ms,
            decision_seq: receipt.seq,
        })
    }

    /// Build the SkillRegistry call for a persisted skill, after the member's explicit approval.
    /// Records the HIC-1 decision. Builds only: nothing is signed or sent.
    pub fn prepare_publish(
        &mut self,
        id: &str,
        approval: PublishApproval,
        params: PublishParams,
    ) -> Result<SkillPublishPayload, LearnError> {
        let p = self.lookup(id)?.clone();
        if p.kind != ProposalKind::Skill {
            return Err(LearnError::NotASkill);
        }
        if !matches!(
            p.state,
            ProposalState::Persisted | ProposalState::PublishPrepared
        ) {
            return Err(Self::wrong_state(&p));
        }
        if approval.member.trim().is_empty() {
            return Err(LearnError::MemberRequired);
        }
        if approval.proposal_id != p.id || approval.content_sha256 != p.content_sha256 {
            return Err(LearnError::ApprovalMismatch);
        }
        if params.chain_id == 0 {
            return invalid("chain id is required");
        }
        let registry =
            registry::parse_address(&params.registry).map_err(LearnError::InvalidPublish)?;
        let owner = registry::parse_address(&params.owner).map_err(LearnError::InvalidPublish)?;
        if !registry::valid_version(&params.version) {
            return invalid(format!(
                "version {:?} is not MAJOR.MINOR.PATCH",
                params.version
            ));
        }
        let cid = params.manifest_cid.clone().unwrap_or_default();
        if !registry::valid_manifest_cid(&cid) {
            return invalid("manifest CID must be a bare CID");
        }
        if params.tags.len() > MAX_USER_TAGS {
            return invalid(format!("at most {MAX_USER_TAGS} tags"));
        }
        if let Some(t) = params.tags.iter().find(|t| !registry::valid_tag(t)) {
            return invalid(format!("tag {t:?} is not lowercase a-z, 0-9, - . : _"));
        }

        let ProposalContent::Skill { skill_md } = &p.content else {
            return Err(LearnError::NotASkill);
        };
        let (fm, _) =
            parse_skill_md(skill_md).map_err(|e| LearnError::InvalidSkill(e.to_string()))?;
        let path = self.skill_dir(&fm.name).join("SKILL.md");
        if file_sha(&path).as_deref() != Some(p.content_sha256.as_str()) {
            return Err(LearnError::ContentChanged);
        }

        let mut tags: Vec<String> = Vec::new();
        let hash_tag = format!("sha256:{}", p.content_sha256);
        for t in params
            .tags
            .iter()
            .cloned()
            .chain([LEARNED_TAG.to_string(), hash_tag])
        {
            if !tags.contains(&t) {
                tags.push(t);
            }
        }
        let data = registry::encode_register_skill(
            &fm.name,
            &params.version,
            &cid,
            &fm.description,
            &tags,
        );
        let skill_hash = registry::skill_hash(&owner, &fm.name, &params.version);
        let to = format!("0x{}", hex::encode(registry));
        let payload = SkillPublishPayload {
            chain_id: params.chain_id,
            to: to.clone(),
            value: "0x0".into(),
            data: format!("0x{}", hex::encode(&data)),
            function: registry::REGISTER_SKILL_SIGNATURE.into(),
            name: fm.name.clone(),
            version: params.version.clone(),
            manifest_cid: cid,
            description: fm.description.clone(),
            tags,
            owner: format!("0x{}", hex::encode(owner)),
            content_sha256: p.content_sha256.clone(),
            expected_skill_hash: format!("0x{}", hex::encode(skill_hash)),
            hic: "hic-1".into(),
            broadcast: false,
            proposal_id: p.id.clone(),
        };

        let mut evidence = Self::evidence_refs(&p);
        evidence.truncate(MAX_EVIDENCE.saturating_sub(1));
        evidence.push(EvidenceRef {
            kind: "calldata".into(),
            uri: format!("chain:{}/{to}", params.chain_id),
            digest: Some(sha256_hex(&data)),
        });
        let actor = Actor::member(approval.member.as_str());
        let receipt = self
            .log
            .record_decision(
                actor.clone(),
                DecisionEvent {
                    tier: HicTier::Hic1,
                    kind: "skill.publish".into(),
                    subject: format!(
                        "SkillRegistry.registerSkill {}@{} on chain {} at {to}",
                        fm.name, params.version, params.chain_id
                    ),
                    decision: Decision::Approved,
                    reason: "member approved preparing the publish; the transaction is signed in the core ceremony".into(),
                    evidence,
                },
            )
            .map_err(|e| LearnError::Record(e.to_string()))?;
        if let Some(stored) = self.proposals.get_mut(id) {
            stored.state = ProposalState::PublishPrepared;
        }
        self.save_after_decision();
        self.log
            .record_outcome(
                actor,
                OutcomeEvent {
                    decision_seq: receipt.seq,
                    outcome: Outcome::Completed,
                    detail: "calldata built, not sent".into(),
                },
            )
            .map_err(|e| LearnError::Record(e.to_string()))?;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::TrajectoryRef;
    use citrate_agent_records::LogConfig;

    fn proposal(n: u64, state: ProposalState) -> Proposal {
        let (key, value) = (format!("k{n}"), "v".to_string());
        Proposal {
            id: format!("lp-{n:024x}"),
            kind: ProposalKind::Memory,
            content_sha256: memory_sha(&key, &value),
            content: ProposalContent::Memory { key, value },
            evidence: Evidence {
                workflow_id: "w".into(),
                steps: vec!["s".into()],
                verdicts: vec![crate::evidence::VerifierVerdict {
                    step: "s".into(),
                    name: "v".into(),
                    passed: true,
                    detail: String::new(),
                }],
                attempts: 1,
                trajectory: TrajectoryRef {
                    session_id: "x".into(),
                    workflow_id: "w".into(),
                    messages: 1,
                    sha256: "0".repeat(64),
                },
            },
            provenance: Provenance {
                session_id: "x".into(),
                agent: "hermes".into(),
                model: "m".into(),
            },
            created_at_ms: n,
            conflicts: vec![],
            state,
            set_aside: Vec::new(),
        }
    }

    #[test]
    fn saving_keeps_every_undecided_proposal_and_only_the_newest_decided_ones() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let log = Arc::new(
            DecisionLog::open(&dir.path().join("r"), LogConfig::default())
                .unwrap_or_else(|e| panic!("{e}"))
                .0,
        );
        let (mut l, _) = Learner::open(
            LearnConfig {
                user_skills_dir: dir.path().join("u"),
                other_skill_sources: vec![],
            },
            log,
            Arc::new(SystemClock),
            &dir.path().join("p.json"),
        );
        let n = MAX_KEPT_DECIDED as u64 + 3;
        for i in 0..n {
            let p = proposal(i, ProposalState::Persisted);
            assert!(stored_problem(&p).is_none(), "{:?}", stored_problem(&p));
            l.proposals.insert(p.id.clone(), p);
        }
        // An old undecided one is never dropped.
        let old = proposal(n + 10, ProposalState::Proposed);
        let old_id = old.id.clone();
        let mut old = old;
        old.created_at_ms = 0;
        l.proposals.insert(old_id.clone(), old);
        l.save().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(l.proposals.len(), MAX_KEPT_DECIDED + 1);
        assert!(l.proposals.contains_key(&old_id));
        for i in 0..3 {
            assert!(
                !l.proposals.contains_key(&format!("lp-{i:024x}")),
                "the oldest decided ones went first"
            );
        }
        assert!(l.proposals.contains_key(&format!("lp-{:024x}", n - 1)));
    }

    #[test]
    fn a_stored_proposal_with_a_bad_id_or_kind_is_a_problem() {
        let mut p = proposal(1, ProposalState::Proposed);
        p.id = "lp-ZZ".into();
        assert!(stored_problem(&p).is_some());
        let mut p = proposal(1, ProposalState::Proposed);
        p.kind = ProposalKind::Skill;
        assert!(stored_problem(&p).is_some());
        let mut p = proposal(1, ProposalState::Proposed);
        p.evidence.verdicts[0].step = "elsewhere".into();
        assert!(stored_problem(&p).is_some());
    }
}
