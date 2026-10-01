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
}

impl ProposalState {
    fn label(&self) -> &'static str {
        match self {
            ProposalState::Proposed => "proposed",
            ProposalState::Rejected { .. } => "rejected",
            ProposalState::PersistFailed { .. } => "persist_failed",
            ProposalState::Persisted => "persisted",
            ProposalState::PublishPrepared => "publish_prepared",
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
        }
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
            let accepted = matches!(p.state, ProposalState::Persisted);
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
        };
        self.proposals.insert(id, p.clone());
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
