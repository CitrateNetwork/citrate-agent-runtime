//! HUP-S2.3 (US-2.3 AC3): web-signing decisions into the local decision records, so the nightly
//! anchor (HUP-S7.3) covers them.
//!
//! citrate-core keeps the authoritative, hash-chained web-signing records in its own budget store,
//! which the sidecar never reads (Rule-3 ADR D4 "Storage"). After each decision core sends a copy
//! here, over the bearer-authed loopback channel:
//!
//! `POST /records/web-signing {records: [...]}`
//!
//! Each copy becomes one HIC decision in `citrate-agent-records`' log at
//! `CITRATE_HERMES_RECORDS_DIR` (the directory the anchor batches), plus its outcome:
//!
//! | core record | tier | kind | decision | outcome |
//! |---|---|---|---|---|
//! | `auto_sign` (signed) | HIC-2 | `siwe` | `auto_within_budget` | `completed` |
//! | `auto_sign` (not signed) | HIC-2 | `siwe` | `auto_within_budget` | `failed` |
//! | `auto_sign` (outcome unknown) | HIC-2 | `siwe` | `auto_within_budget` | `outcome_unknown` |
//! | `budget_granted`, `budget_revoked`, `all_budgets_revoked`, `store_reset` | HIC-1 | `siwe_budget` | `approved` | `completed` |
//!
//! The evidence of every decision carries core's record id and record hash, so a proof of a
//! nightly batch can be matched to core's own chain. Delivery is at least once: core advances its
//! export cursor only after this route answers, so a crash in between can repeat a record; the
//! core record id in the evidence identifies repeats.
//!
//! Nothing here signs, holds a key, or reads core's budget file.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use citrate_agent_records::{
    Actor, Decision, DecisionEvent, DecisionLog, EvidenceRef, HicTier, LogConfig, Outcome,
    OutcomeEvent,
};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;

/// At most this many records per call.
pub const MAX_RECORDS_PER_CALL: usize = 100;

/// One of core's web-signing decision records, as core sends it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoreRecord {
    pub record_id: u64,
    /// `auto_sign`, `budget_granted`, `budget_revoked`, `all_budgets_revoked`, `store_reset`.
    pub kind: String,
    /// `signed`, `not_signed`, `outcome_unknown`, `final`.
    pub status: String,
    pub origin: String,
    #[serde(default)]
    pub budget_id: Option<u64>,
    #[serde(default)]
    pub payload_digest: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub statement: Option<String>,
    #[serde(default)]
    pub signer_address: Option<String>,
    pub at_ms: u64,
    pub hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteReq {
    pub records: Vec<CoreRecord>,
}

fn is_hash(s: &str) -> bool {
    s.len() == 66 && s.starts_with("0x") && s.as_bytes()[2..].iter().all(|b| b.is_ascii_hexdigit())
}

fn clip(s: &str, n: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(n).collect()
}

/// The decision (and its outcome) one core record becomes. Refuses anything malformed.
pub fn to_events(r: &CoreRecord) -> Result<(Actor, DecisionEvent, Outcome, String), String> {
    if !is_hash(&r.hash) {
        return Err(format!(
            "record {}: the record hash is malformed",
            r.record_id
        ));
    }
    if r.origin.is_empty() || r.origin.len() > 300 {
        return Err(format!(
            "record {}: the origin is missing or too long",
            r.record_id
        ));
    }
    let mut evidence = vec![EvidenceRef {
        kind: "web_budget_record".to_string(),
        uri: format!("citrate-core:web-budget/record/{}", r.record_id),
        digest: Some(r.hash.clone()),
    }];
    if let Some(b) = r.budget_id {
        evidence.push(EvidenceRef {
            kind: "web_budget".to_string(),
            uri: format!("citrate-core:web-budget/budget/{b}"),
            digest: None,
        });
    }
    let (actor, tier, kind, decision, outcome, detail) = match r.kind.as_str() {
        "auto_sign" => {
            let digest = r
                .payload_digest
                .as_deref()
                .filter(|d| is_hash(d))
                .ok_or_else(|| {
                    format!("record {}: a sign-in needs its payload digest", r.record_id)
                })?;
            evidence.push(EvidenceRef {
                kind: "siwe_payload_keccak256".to_string(),
                uri: "citrate-core:web-budget/payload".to_string(),
                digest: Some(digest.to_string()),
            });
            if let Some(n) = r.nonce.as_deref() {
                evidence.push(EvidenceRef {
                    kind: "siwe_nonce".to_string(),
                    uri: format!("siwe-nonce:{}", clip(n, 128)),
                    digest: None,
                });
            }
            let (outcome, detail) = match r.status.as_str() {
                "signed" => (Outcome::Completed, "signed inside the member's budget"),
                "not_signed" => (Outcome::Failed, "nothing was signed"),
                "outcome_unknown" => (
                    Outcome::OutcomeUnknown,
                    "core stopped between the reservation and the signature",
                ),
                other => {
                    return Err(format!(
                        "record {}: a sign-in cannot have status {other:?} (still reserved?)",
                        r.record_id
                    ))
                }
            };
            (
                Actor::agent("hermes"),
                HicTier::Hic2,
                "siwe",
                Decision::AutoWithinBudget,
                outcome,
                detail,
            )
        }
        "budget_granted" | "budget_revoked" | "all_budgets_revoked" | "store_reset" => {
            if r.status != "final" {
                return Err(format!(
                    "record {}: a member decision is final",
                    r.record_id
                ));
            }
            (
                Actor::member("member"),
                HicTier::Hic1,
                "siwe_budget",
                Decision::Approved,
                Outcome::Completed,
                "the member's decision in Settings, Budgets",
            )
        }
        other => return Err(format!("record {}: unknown kind {other:?}", r.record_id)),
    };
    let mut reason = format!("{} (core record {}, at {} ms", r.kind, r.record_id, r.at_ms);
    if let Some(a) = r.signer_address.as_deref() {
        reason.push_str(&format!(", signer {}", clip(a, 42)));
    }
    reason.push(')');
    if let Some(s) = r.statement.as_deref() {
        reason.push_str(&format!(": statement {:?}", clip(s, 300)));
    }
    Ok((
        actor,
        DecisionEvent {
            tier,
            kind: kind.to_string(),
            subject: clip(&r.origin, 300),
            decision,
            reason,
            evidence,
        },
        outcome,
        detail.to_string(),
    ))
}

/// Write each record as a decision plus its outcome. All records are checked before any is
/// written, so a malformed batch writes nothing. Returns the last `seq` written.
pub fn write_records(log: &DecisionLog, records: &[CoreRecord]) -> Result<Option<u64>, String> {
    if records.len() > MAX_RECORDS_PER_CALL {
        return Err(format!("at most {MAX_RECORDS_PER_CALL} records per call"));
    }
    let events = records
        .iter()
        .map(to_events)
        .collect::<Result<Vec<_>, _>>()?;
    let mut last = None;
    for (actor, decision, outcome, detail) in events {
        let rcpt = log
            .record_decision(actor.clone(), decision)
            .map_err(|e| format!("the decision records could not be written: {e}"))?;
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
    Ok(last)
}

/// The records directory from `CITRATE_HERMES_RECORDS_DIR` (absolute only).
pub fn records_dir_from_env() -> Option<PathBuf> {
    let v = std::env::var(crate::anchor::RECORDS_DIR_ENV).ok()?;
    let p = PathBuf::from(v.trim());
    (!v.trim().is_empty() && p.is_absolute()).then_some(p)
}

/// The open log and the folder it was opened in.
type OpenLog = (PathBuf, Arc<DecisionLog>);

/// The sidecar's one writer for the records directory (the log is single-writer per directory,
/// enforced with an OS file lock). Opened on first use. Other sidecar code that needs to write
/// decision records into the same directory should use this handle too.
pub fn shared_log(dir: &Path) -> Result<Arc<DecisionLog>, String> {
    static LOG: OnceLock<Mutex<Option<OpenLog>>> = OnceLock::new();
    let cell = LOG.get_or_init(|| Mutex::new(None));
    let mut g = match cell.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some((p, log)) = g.as_ref() {
        if p == dir {
            return Ok(log.clone());
        }
        return Err("the decision records are already open in another folder".to_string());
    }
    let (log, _report) = DecisionLog::open(dir, LogConfig::default())
        .map_err(|e| format!("the decision records could not be opened: {e}"))?;
    let log = Arc::new(log);
    *g = Some((dir.to_path_buf(), log.clone()));
    Ok(log)
}

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

/// `POST /records/web-signing`
pub async fn write(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Response {
    if !crate::authorized(&headers, &st.bearer) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(dir) = records_dir_from_env() else {
        return err(
            StatusCode::NOT_FOUND,
            "decision records are not configured (CITRATE_HERMES_RECORDS_DIR)",
        );
    };
    let Ok(req) = serde_json::from_slice::<WriteReq>(&body) else {
        return err(StatusCode::BAD_REQUEST, "malformed records");
    };
    let out = tokio::task::spawn_blocking(move || {
        let log = shared_log(&dir)?;
        write_records(&log, &req.records).map(|last| (req.records.len(), last))
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
