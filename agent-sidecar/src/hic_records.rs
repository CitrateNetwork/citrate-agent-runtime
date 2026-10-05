//! HUP-S2.6 (US-7.2 AC1): local decision records for every HIC-1/2 event, in the one records
//! directory the nightly anchor batches (`CITRATE_HERMES_RECORDS_DIR`, HUP-S7.3).
//!
//! The sidecar has one writer for that directory ([`crate::web_signing_records::shared_log`],
//! held by the session manager as [`crate::sessions::SessionManager::records`]). Every HIC event
//! reaches it one of three ways:
//!
//! | event | where it is decided | how it is recorded |
//! |---|---|---|
//! | capsule chain effect (ceremony bridge) | core's ceremony, then `POST /approvals/approve` or `/reject` | here, kind `ceremony.capsule_effect` |
//! | browser action after taint | `POST /browser/actions/decide` | here, kind `browser.action` |
//! | learn accept, reject, resolve, publish | the learn routes | `citrate-agent-learn`, on the same log |
//! | budgeted SIWE, budget grants and revokes | core's web-budget store | `POST /records/web-signing` |
//! | folder grants, full access, escalation spend, ceremony and tool approval cards, the in-app faucet switch and top-ups (HUP-S6.5) | core | `POST /records/core` ([`write_core`]) |
//!
//! A member decision that allows something is written **before** it takes effect (write-ahead,
//! like the log itself), and closed with an outcome after. For the two sidecar routes the effect
//! of the decision is the release of that one reviewed call (for a chain effect, core's ceremony
//! has already signed and broadcast it); the call's own result is in the session's tool result.
//!
//! **Fail closed (pending owner sign-off).** With records configured, an approval whose decision
//! record cannot be written is refused (503) and nothing is released. A denial still takes effect
//! (denying is the safe direction) and the write failure is logged to stderr. Unconfigured
//! (`CITRATE_HERMES_RECORDS_DIR` unset), nothing is recorded and the routes behave as before.
//!
//! Records are hash-chained by `citrate-agent-records`; nothing here signs, holds a key, or MACs
//! with a device key (Rule 3; a device-key MAC is an open owner decision).

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use citrate_agent_records::{
    Actor, Decision, DecisionEvent, DecisionLog, EvidenceRef, HicTier, Outcome, OutcomeEvent,
};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;

/// At most this many core records per call.
pub const MAX_CORE_RECORDS_PER_CALL: usize = 100;
/// At most this many extra evidence references per core record.
pub const MAX_CORE_EVIDENCE: usize = 4;

/// Record a member's decision on one call (write-ahead). Returns the decision's `seq`.
pub fn record_member_decision(
    log: &DecisionLog,
    kind: &str,
    subject: &str,
    allow: bool,
    reason: &str,
    evidence: Vec<EvidenceRef>,
) -> Result<u64, String> {
    log.record_decision(
        Actor::member("member"),
        DecisionEvent {
            tier: HicTier::Hic1,
            kind: kind.to_string(),
            subject: clip(subject, 300),
            decision: if allow {
                Decision::Approved
            } else {
                Decision::Denied
            },
            reason: clip(reason, 500),
            evidence,
        },
    )
    .map(|r| r.seq)
    .map_err(|e| format!("the decision could not be recorded: {e}"))
}

/// Close an allowing decision with its outcome. A failure is logged (the decision stays open and
/// the log closes it as `outcome_unknown` when it is next opened).
pub fn record_outcome(log: &DecisionLog, seq: u64, outcome: Outcome, detail: &str) {
    if let Err(e) = log.record_outcome(
        Actor::member("member"),
        OutcomeEvent {
            decision_seq: seq,
            outcome,
            detail: clip(detail, 300),
        },
    ) {
        eprintln!(
            "citrate-agent-sidecar: the outcome of decision {seq} could not be recorded: {e}"
        );
    }
}

/// Control characters removed, then cut at a character boundary to at most `max` bytes (the
/// record limits are in bytes, so a long or multibyte page summary never fails a record).
fn clip(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in s.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    out
}

fn is_hash(s: &str) -> bool {
    s.len() == 66 && s.starts_with("0x") && s.as_bytes()[2..].iter().all(|b| b.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------------------------
// POST /records/core
// ---------------------------------------------------------------------------------------------

/// One evidence reference core attaches.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreEvidence {
    pub kind: String,
    pub uri: String,
    #[serde(default)]
    pub digest: Option<String>,
}

/// One of core's HIC records (core keeps the authoritative, hash-chained copy in its outbox).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoreHicRecord {
    pub record_id: u64,
    /// See [`kind_rule`].
    pub kind: String,
    /// `approved`, `denied`, `auto_within_budget`.
    pub decision: String,
    pub subject: String,
    pub reason: String,
    /// `completed`, `failed`, `outcome_unknown`; absent for a denial, or when core does not know.
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub outcome_detail: Option<String>,
    #[serde(default)]
    pub evidence: Vec<CoreEvidence>,
    pub at_ms: u64,
    /// Core's record hash (`0x` + 64 hex).
    pub hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreWriteReq {
    pub records: Vec<CoreHicRecord>,
}

/// The decisions each core kind may carry. Only an escalation inside the member's daily budget
/// and a faucet top-up inside the member's faucet budget are HIC-2 (`auto_within_budget`); every
/// other kind is the member's own HIC-1 decision.
fn kind_rule(kind: &str) -> Option<&'static [&'static str]> {
    Some(match kind {
        "grant.folder_added" | "grant.revoked" | "grant.reset" | "grant.full_access_confirmed" => {
            &["approved"]
        }
        "ceremony.approval" | "agent.tool_approval" => &["approved", "denied"],
        "escalation.spend" => &["approved", "auto_within_budget"],
        // HUP-S6.5 (faucet ADR D4.3): the member's in-app faucet switch, and each faucet call
        // (HIC-2 when Hermes or an MCP client asked inside the member's budget).
        "faucet.budget_granted" | "faucet.budget_revoked" => &["approved"],
        "faucet.topup" => &["approved", "auto_within_budget"],
        _ => return None,
    })
}

/// What one core record is written as: the decision, and the outcome when it allows something.
pub type CoreEvents = (Actor, DecisionEvent, Option<(Outcome, String)>);

/// Check one core record and map it. Refuses anything malformed.
pub fn core_to_events(r: &CoreHicRecord) -> Result<CoreEvents, String> {
    let id = r.record_id;
    if !is_hash(&r.hash) {
        return Err(format!("record {id}: the record hash is malformed"));
    }
    let allowed =
        kind_rule(&r.kind).ok_or_else(|| format!("record {id}: unknown kind {:?}", r.kind))?;
    if !allowed.contains(&r.decision.as_str()) {
        return Err(format!(
            "record {id}: a {} cannot be {:?}",
            r.kind, r.decision
        ));
    }
    let (decision, tier, actor) = match r.decision.as_str() {
        "approved" => (Decision::Approved, HicTier::Hic1, Actor::member("member")),
        "denied" => (Decision::Denied, HicTier::Hic1, Actor::member("member")),
        _ => (
            Decision::AutoWithinBudget,
            HicTier::Hic2,
            Actor::agent("hermes"),
        ),
    };
    if r.subject.trim().is_empty() || r.subject.len() > 300 {
        return Err(format!("record {id}: the subject is missing or too long"));
    }
    if r.reason.len() > 500 {
        return Err(format!("record {id}: the reason is too long"));
    }
    if r.evidence.len() > MAX_CORE_EVIDENCE {
        return Err(format!(
            "record {id}: at most {MAX_CORE_EVIDENCE} evidence references"
        ));
    }
    let outcome = match (decision.expects_outcome(), r.outcome.as_deref()) {
        (false, None) => None,
        (false, Some(_)) => return Err(format!("record {id}: a denial has no outcome")),
        (true, o) => {
            let detail = r
                .outcome_detail
                .as_deref()
                .map(|d| clip(d, 300))
                .unwrap_or_default();
            Some(match o {
                Some("completed") => (Outcome::Completed, detail),
                Some("failed") => (Outcome::Failed, detail),
                Some("outcome_unknown") => (Outcome::OutcomeUnknown, detail),
                None => (
                    Outcome::OutcomeUnknown,
                    "core recorded the decision; the effect's result is not part of this record"
                        .to_string(),
                ),
                Some(other) => return Err(format!("record {id}: unknown outcome {other:?}")),
            })
        }
    };
    let mut evidence = vec![EvidenceRef {
        kind: "core_hic_record".to_string(),
        uri: format!("citrate-core:hic/record/{id}"),
        digest: Some(r.hash.clone()),
    }];
    for e in &r.evidence {
        if e.kind.is_empty() || e.kind.len() > 64 || e.uri.is_empty() || e.uri.len() > 300 {
            return Err(format!("record {id}: an evidence reference is malformed"));
        }
        if let Some(d) = e.digest.as_deref() {
            if !is_hash(d) {
                return Err(format!("record {id}: an evidence digest is malformed"));
            }
        }
        evidence.push(EvidenceRef {
            kind: clip(&e.kind, 64),
            uri: clip(&e.uri, 300),
            digest: e.digest.clone(),
        });
    }
    let reason = format!(
        "{} (core record {id}, at {} ms)",
        clip(&r.reason, 400),
        r.at_ms
    );
    Ok((
        actor,
        DecisionEvent {
            tier,
            kind: r.kind.clone(),
            subject: clip(&r.subject, 300),
            decision,
            reason,
            evidence,
        },
        outcome,
    ))
}

/// Write each core record as a decision plus its outcome. All records are checked before any is
/// written, so a malformed batch writes nothing. Returns the last `seq` written.
pub fn write_core_records(
    log: &DecisionLog,
    records: &[CoreHicRecord],
) -> Result<Option<u64>, String> {
    if records.len() > MAX_CORE_RECORDS_PER_CALL {
        return Err(format!(
            "at most {MAX_CORE_RECORDS_PER_CALL} records per call"
        ));
    }
    let events = records
        .iter()
        .map(core_to_events)
        .collect::<Result<Vec<_>, _>>()?;
    let mut last = None;
    for (actor, decision, outcome) in events {
        let rcpt = log
            .record_decision(actor.clone(), decision)
            .map_err(|e| format!("the decision records could not be written: {e}"))?;
        last = Some(rcpt.seq);
        if let Some((outcome, detail)) = outcome {
            let out = log
                .record_outcome(
                    actor,
                    OutcomeEvent {
                        decision_seq: rcpt.seq,
                        outcome,
                        detail,
                    },
                )
                .map_err(|e| format!("the decision records could not be written: {e}"))?;
            last = Some(out.seq);
        }
    }
    Ok(last)
}

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

/// `POST /records/core {records: [...]}`. 404 when no records directory is configured.
pub async fn write_core(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Response {
    if !crate::authorized(&headers, &st.bearer) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(log) = st.sessions.records() else {
        return err(
            StatusCode::NOT_FOUND,
            "decision records are not configured (CITRATE_HERMES_RECORDS_DIR)",
        );
    };
    let Ok(req) = serde_json::from_slice::<CoreWriteReq>(&body) else {
        return err(StatusCode::BAD_REQUEST, "malformed records");
    };
    let out = tokio::task::spawn_blocking(move || {
        write_core_records(&log, &req.records).map(|last| (req.records.len(), last))
    })
    .await;
    match out {
        Ok(Ok((n, last))) => Json(json!({ "written": n, "lastSeq": last })).into_response(),
        Ok(Err(m)) if m.starts_with("record ") || m.starts_with("at most") => {
            err(StatusCode::BAD_REQUEST, &m)
        }
        Ok(Err(m)) => err(StatusCode::INTERNAL_SERVER_ERROR, &m),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}
