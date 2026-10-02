//! HUP-S3.4 wiring: verified self-learning in the sidecar, over `citrate-agent-learn`.
//!
//! Off unless both folders are configured:
//!
//! - `CITRATE_HERMES_LEARN_DIR`: the learn data folder. It holds the HIC decision log
//!   (`decisions/`) and the proposals file (`proposals.json`), so undecided proposals survive a
//!   restart.
//! - `CITRATE_HERMES_LEARN_SKILLS_DIR`: the member's skills folder, where an accepted skill is
//!   written as `<name>/SKILL.md`. Skills named in `CITRATE_HERMES_SKILLS` (bundled, team) are
//!   checked for name clashes.
//!
//! What it serves:
//!
//! - The learn routes (`/learn/...`, in `lib.rs`): propose from a verified workflow run of a
//!   session, list, accept, reject, resolve a contradiction between two accepted memories (keep
//!   one, retract the other), and build the SkillRegistry publish payload. A memory accept
//!   returns the typed memory record for core to store; the sidecar stores no memories. A skill
//!   accept reloads the skills library, so the skill is offered to the next session without a
//!   restart.
//! - The `learn_propose` tool, offered to every session while learning is on. Hermes calls it to
//!   propose a skill or memory from the session's last verified workflow run. It only proposes:
//!   the member decides in the app, and nothing is persisted by the tool.
//!
//! Guard rails: a proposal needs a verified run of the same session (agent-learn enforces that a
//! verified run exists only when every verifier passed); a session that read untrusted content
//! cannot propose; every decision needs a member id and goes to the decision log first; the
//! e-stop closes every learn write. Nothing here holds a key, signs, or sends (Rule 3).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use citrate_agent_learn::{
    KnownMemory, LearnConfig, LearnError, Learner, LoadReport, MemberAccept, MemberResolve,
    Persisted, Proposal, ProposalContent, Provenance, PublishApproval, PublishParams, Resolution,
    SkillPublishPayload,
};
use citrate_agent_loop::skills::SkillSource;
use citrate_agent_loop::{
    Effect, HostKind, ToolAnnotations, ToolCall, ToolHost, ToolOutcome, ToolSpec, Trust,
};
use citrate_agent_records::{DecisionLog, LogConfig};
use serde::{Deserialize, Serialize};

use crate::sessions::{RunState, Session};

/// The learn data folder.
pub const LEARN_DIR_ENV: &str = "CITRATE_HERMES_LEARN_DIR";
/// The member's skills folder (accepted skills are written here).
pub const LEARN_SKILLS_DIR_ENV: &str = "CITRATE_HERMES_LEARN_SKILLS_DIR";
/// The tool Hermes proposes with.
pub const LEARN_PROPOSE_TOOL: &str = "learn_propose";
/// Most known memories a caller may pass with one proposal.
pub const MAX_KNOWN_MEMORIES: usize = 512;

/// Why a learn request was refused (mapped to HTTP status by the routes).
#[derive(Debug)]
pub enum LearnRefusal {
    NotFound(String),
    Conflict {
        message: String,
        conflicts: Vec<citrate_agent_learn::Conflict>,
    },
    Invalid(String),
    Failed(String),
}

impl LearnRefusal {
    fn conflict(m: impl Into<String>) -> Self {
        LearnRefusal::Conflict {
            message: m.into(),
            conflicts: vec![],
        }
    }
}

impl From<LearnError> for LearnRefusal {
    fn from(e: LearnError) -> Self {
        let message = e.to_string();
        match e {
            LearnError::UnknownProposal(_) => LearnRefusal::NotFound(message),
            LearnError::MemberRequired
            | LearnError::InvalidSkill(_)
            | LearnError::InvalidMemory(_)
            | LearnError::InvalidPublish(_)
            | LearnError::ProvenanceMismatch { .. } => LearnRefusal::Invalid(message),
            LearnError::Blocked(conflicts) | LearnError::UnacknowledgedConflicts(conflicts) => {
                LearnRefusal::Conflict { message, conflicts }
            }
            LearnError::WrongState { .. }
            | LearnError::AlreadyKnown { .. }
            | LearnError::TooManyPending
            | LearnError::NotASkill
            | LearnError::ApprovalMismatch
            | LearnError::ContentChanged
            | LearnError::NotAContradiction(_) => LearnRefusal::conflict(message),
            LearnError::Record(_) | LearnError::Persist(_) | LearnError::Store(_) => {
                LearnRefusal::Failed(message)
            }
        }
    }
}

/// What an accept persisted, as the route returns it. A skill is named, never located: the
/// route does not echo local paths.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AcceptedView {
    Skill {
        name: String,
        content_sha256: String,
    },
    Memory(Box<citrate_agent_learn::MemoryRecord>),
}

/// The learner behind the routes and the tool.
pub struct LearnService {
    learner: Mutex<Learner>,
    report: LoadReport,
}

impl LearnService {
    /// Open the learn folder (decision log + proposals file) over a skills folder. `others` are
    /// the other skill sources checked for name clashes.
    pub fn open(
        learn_dir: &Path,
        skills_dir: &Path,
        others: Vec<SkillSource>,
    ) -> Result<Self, String> {
        let (log, _recovery) =
            DecisionLog::open(&learn_dir.join("decisions"), LogConfig::default())
                .map_err(|e| format!("decision log: {e}"))?;
        let (learner, report) = Learner::open(
            LearnConfig {
                user_skills_dir: skills_dir.to_path_buf(),
                other_skill_sources: others,
            },
            Arc::new(log),
            Arc::new(citrate_agent_records::SystemClock),
            &learn_dir.join("proposals.json"),
        );
        Ok(LearnService {
            learner: Mutex::new(learner),
            report,
        })
    }

    /// The service from the two folder values and the `CITRATE_HERMES_SKILLS` path list. `None`
    /// (learning off) unless both folders are given; an open failure is logged and is off too.
    pub fn from_values(
        learn_dir: Option<&str>,
        skills_dir: Option<&str>,
        skill_sources: &str,
    ) -> Option<Self> {
        let learn_dir = learn_dir.map(str::trim).filter(|v| !v.is_empty())?;
        let skills_dir = skills_dir.map(str::trim).filter(|v| !v.is_empty())?;
        let skills_path = PathBuf::from(skills_dir);
        let others: Vec<SkillSource> = crate::skill_sources_from_env(skill_sources)
            .into_iter()
            .filter(|s| s.root != skills_path)
            .collect();
        match Self::open(Path::new(learn_dir), &skills_path, others) {
            Ok(s) => {
                let r = &s.report;
                eprintln!(
                    "citrate-agent-sidecar: learning on: {} proposal(s) restored, {} dropped{}",
                    r.loaded,
                    r.dropped.len(),
                    if r.moved_aside.is_some() {
                        ", an unreadable proposals file was moved aside"
                    } else {
                        ""
                    }
                );
                for (id, why) in &r.dropped {
                    eprintln!("citrate-agent-sidecar: proposal {id} not restored: {why}");
                }
                Some(s)
            }
            Err(e) => {
                eprintln!("citrate-agent-sidecar: learning off: {e}");
                None
            }
        }
    }

    /// From the environment (default off).
    pub fn from_env() -> Option<Arc<Self>> {
        let dir = std::env::var(LEARN_DIR_ENV).ok();
        let skills = std::env::var(LEARN_SKILLS_DIR_ENV).ok();
        let sources = std::env::var("CITRATE_HERMES_SKILLS").unwrap_or_default();
        Self::from_values(dir.as_deref(), skills.as_deref(), &sources).map(Arc::new)
    }

    fn lock(&self) -> MutexGuard<'_, Learner> {
        // A poisoned lock means a panic mid-call; the learner's state is still the last
        // consistent one (every mutation is a single assignment after its checks).
        match self.learner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// `GET /learn/status`.
    pub fn status(&self) -> serde_json::Value {
        let l = self.lock();
        serde_json::json!({
            "enabled": true,
            "pending": l.pending().len(),
            "restored": self.report.loaded,
            "dropped": self.report.dropped.len(),
            "moved_aside": self.report.moved_aside.is_some(),
            "store_error": l.store_error(),
        })
    }

    /// Propose from a verified run of `session`.
    pub fn propose(
        &self,
        session: &Session,
        run_id: &str,
        content: ProposalContent,
        known: &[KnownMemory],
    ) -> Result<Proposal, LearnRefusal> {
        if known.len() > MAX_KNOWN_MEMORIES {
            return Err(LearnRefusal::Invalid(format!(
                "at most {MAX_KNOWN_MEMORIES} known memories"
            )));
        }
        let run = match session.run(run_id) {
            None => return Err(LearnRefusal::NotFound(format!("no run {run_id}"))),
            Some(RunState::Running { .. }) => {
                return Err(LearnRefusal::conflict("the run has not finished"))
            }
            Some(RunState::Unverified { reason, .. }) => {
                return Err(LearnRefusal::conflict(format!(
                    "the run is not verified ({reason}); only verified work can be learned"
                )))
            }
            Some(RunState::Verified(run)) => run,
        };
        self.propose_from(session, &run, content, known)
    }

    fn propose_from(
        &self,
        session: &Session,
        run: &citrate_agent_learn::VerifiedRun,
        content: ProposalContent,
        known: &[KnownMemory],
    ) -> Result<Proposal, LearnRefusal> {
        if session.taint().is_tainted() {
            return Err(LearnRefusal::conflict(
                "this session read untrusted content, so it cannot propose what to learn",
            ));
        }
        let provenance = Provenance {
            session_id: session.id.clone(),
            agent: "hermes".into(),
            model: session.model().to_string(),
        };
        Ok(self.lock().propose(run, content, provenance, known)?)
    }

    pub fn list(&self, all: bool) -> Vec<Proposal> {
        let l = self.lock();
        if all {
            l.all().into_iter().cloned().collect()
        } else {
            l.pending().into_iter().cloned().collect()
        }
    }

    pub fn get(&self, id: &str) -> Option<Proposal> {
        self.lock().get(id).cloned()
    }

    pub fn accept(&self, id: &str, decision: MemberAccept) -> Result<AcceptedView, LearnRefusal> {
        Ok(match self.lock().accept(id, decision)? {
            Persisted::Skill {
                name,
                content_sha256,
                ..
            } => AcceptedView::Skill {
                name,
                content_sha256,
            },
            Persisted::Memory(m) => AcceptedView::Memory(m),
        })
    }

    pub fn reject(&self, id: &str, member: &str, reason: &str) -> Result<(), LearnRefusal> {
        Ok(self.lock().reject(id, member, reason)?)
    }

    /// The member keeps one of two contradicting learned memories and retracts the other.
    pub fn resolve(&self, r: MemberResolve) -> Result<Resolution, LearnRefusal> {
        Ok(self.lock().resolve(r)?)
    }

    pub fn publish(
        &self,
        id: &str,
        approval: PublishApproval,
        params: PublishParams,
    ) -> Result<SkillPublishPayload, LearnRefusal> {
        Ok(self.lock().prepare_publish(id, approval, params)?)
    }
}

/// The `learn_propose` tool spec: sidecar-hosted, no effect (it only proposes), trusted output.
pub fn learn_propose_spec() -> ToolSpec {
    ToolSpec {
        name: LEARN_PROPOSE_TOOL.into(),
        description: "Propose a skill or a memory to learn from the workflow you just completed \
            and verified (learn, remember, save a skill). The member reviews the evidence and \
            decides; nothing is saved by this call. kind \"skill\": skill_md is a complete \
            SKILL.md with name and description frontmatter. kind \"memory\": one key and value."
            .into(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "kind": {"type": "string", "enum": ["skill", "memory"]},
                "skill_md": {"type": "string"},
                "key": {"type": "string"},
                "value": {"type": "string"}
            },
            "required": ["kind"]
        }),
        host: HostKind::Sidecar,
        annotations: ToolAnnotations {
            effect: Some(Effect::None),
            trust: Some(Trust::Trusted),
            ..Default::default()
        },
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ToolArgs {
    Skill { skill_md: String },
    Memory { key: String, value: String },
}

/// Runs `learn_propose` for one session.
pub struct LearnToolHost {
    service: Arc<LearnService>,
    session: Arc<Session>,
}

impl LearnToolHost {
    pub fn new(service: Arc<LearnService>, session: Arc<Session>) -> Self {
        LearnToolHost { service, session }
    }
}

impl ToolHost for LearnToolHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        let args: ToolArgs = match serde_json::from_str(call.arguments.trim()) {
            Ok(a) => a,
            Err(e) => return ToolOutcome::Error(format!("bad arguments: {e}")),
        };
        let content = match args {
            ToolArgs::Skill { skill_md } => ProposalContent::Skill { skill_md },
            ToolArgs::Memory { key, value } => ProposalContent::Memory { key, value },
        };
        let Some((run_id, run)) = self.session.last_verified() else {
            return ToolOutcome::Error(
                "there is no verified workflow run in this session yet, so there is nothing to \
                 learn from"
                    .into(),
            );
        };
        match self.service.propose_from(&self.session, &run, content, &[]) {
            Ok(p) => ToolOutcome::Ok(
                serde_json::json!({
                    "proposal_id": p.id,
                    "run_id": run_id,
                    "conflicts": p.conflicts.len(),
                    "status": "waiting for the member to accept or reject it in the app",
                })
                .to_string(),
            ),
            Err(LearnRefusal::NotFound(m))
            | Err(LearnRefusal::Invalid(m))
            | Err(LearnRefusal::Failed(m))
            | Err(LearnRefusal::Conflict { message: m, .. }) => ToolOutcome::Error(m),
        }
    }
}
