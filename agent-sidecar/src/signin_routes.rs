//! HUP-S2.3: the sign-in bridge's control routes (bearer-gated, loopback, for citrate-core only).
//!
//! The managed browser's page provider turns `eth_requestAccounts` and `personal_sign` into
//! requests that wait in the browser worker ([`citrate_agent_browser::signin`]). Core collects them
//! here, decides through its own signature ceremony, and hands the answer back:
//!
//! - `GET /browser/sign-in`: the waiting requests, the facts core needs to attest the page origin
//!   itself (the managed browser's loopback DevTools port and the tab's target id), and what the
//!   live sessions have read (the taint core's budget check needs, ADR D2 #19).
//! - `POST /browser/sign-in/answer {id, accounts | signature | refused}`: deliver core's answer to
//!   the page context that asked. The answer must fit the request.
//!
//! The sidecar holds no key and decides nothing here (Rule 3). The agent loop cannot reach these
//! routes; they are core's.
//!
//! **Taint, computed here from the sessions themselves, never from the caller.** For every live
//! session that is tainted, each source is mapped: a `browser_*` tool contributes the origins whose
//! page content reached the model (or `ext:browser` when none was recorded); anything else
//! contributes `ext:<tool>`. No tainted session means `clean`. A state that cannot be read means
//! `unknown`. Core treats `unknown` as tainted and applies the O-3 same-origin exemption only when
//! every source is the attested origin.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use citrate_agent_browser::signin::SignInAnswer;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::AppState;

/// The taint view core reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TaintView {
    Clean,
    Sources { sources: Vec<String> },
    Unknown,
}

/// Fold the tainted sessions' sources with the origins the browser has shown the model.
pub fn fold_taint(per_session: Option<Vec<Vec<String>>>, read_origins: &[String]) -> TaintView {
    let Some(per_session) = per_session else {
        return TaintView::Unknown;
    };
    if per_session.is_empty() {
        return TaintView::Clean;
    }
    let mut out = BTreeSet::new();
    for sources in per_session {
        if sources.is_empty() {
            // A tainted session must name at least one source; if it does not, nobody knows what
            // it read.
            return TaintView::Unknown;
        }
        for s in sources {
            if s.starts_with("browser_") {
                if read_origins.is_empty() {
                    out.insert("ext:browser".to_string());
                }
                out.extend(read_origins.iter().cloned());
            } else {
                out.insert(format!("ext:{s}"));
            }
        }
    }
    TaintView::Sources {
        sources: out.into_iter().collect(),
    }
}

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

/// `GET /browser/sign-in`
pub async fn list(headers: HeaderMap, State(st): State<Arc<AppState>>) -> Response {
    if !crate::authorized(&headers, &st.bearer) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(b) = st.sessions.browser().cloned() else {
        return err(StatusCode::NOT_FOUND, "the browser is off");
    };
    let sessions = st.sessions.clone();
    let out = tokio::task::spawn_blocking(move || {
        let status = b.status();
        let requests = b.sign_in_requests();
        let taint = fold_taint(sessions.tainted_session_sources(), &b.read_origins());
        json!({
            "mode": status.mode,
            "devtoolsPort": status.devtools_port,
            "targetId": status.target_id,
            "url": status.url,
            "requests": requests,
            "taint": taint,
        })
    })
    .await;
    match out {
        Ok(v) => Json(v).into_response(),
        Err(_) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal: the browser task failed",
        ),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refused {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerReq {
    pub id: String,
    #[serde(default)]
    pub accounts: Option<Vec<String>>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub refused: Option<Refused>,
}

/// Exactly one of the three answers.
pub fn answer_of(r: AnswerReq) -> Result<(String, SignInAnswer), String> {
    let answer = match (r.accounts, r.signature, r.refused) {
        (Some(a), None, None) => SignInAnswer::Accounts(a),
        (None, Some(s), None) => SignInAnswer::Signature(s),
        (None, None, Some(f)) => SignInAnswer::Refused {
            code: f.code,
            message: f.message,
        },
        _ => return Err("give exactly one of accounts, signature or refused".to_string()),
    };
    if r.id.is_empty() || r.id.len() > 64 {
        return Err("invalid request id".to_string());
    }
    Ok((r.id, answer))
}

/// `POST /browser/sign-in/answer`
pub async fn answer(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Response {
    if !crate::authorized(&headers, &st.bearer) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(b) = st.sessions.browser().cloned() else {
        return err(StatusCode::NOT_FOUND, "the browser is off");
    };
    let Ok(req) = serde_json::from_slice::<AnswerReq>(&body) else {
        return err(StatusCode::BAD_REQUEST, "malformed answer");
    };
    let (id, ans) = match answer_of(req) {
        Ok(x) => x,
        Err(m) => return err(StatusCode::BAD_REQUEST, &m),
    };
    let out = tokio::task::spawn_blocking(move || b.answer_sign_in(&id, &ans)).await;
    match out {
        Ok(Ok(())) => Json(json!({ "ok": true })).into_response(),
        Ok(Err(m)) => err(StatusCode::CONFLICT, &m),
        Err(_) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal: the browser task failed",
        ),
    }
}
