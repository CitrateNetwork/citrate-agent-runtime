//! Route handlers for HUP-S7.5 metering and HUP-S7.3 anchoring. Every route is bearer-gated and
//! runs its file I/O on the blocking pool. None of them signs or sends anything (Rule 3).

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use citrate_agent_metering::{build_benchmark_payload, BenchmarkOptIn, MeteringError};
use serde::Deserialize;

use crate::anchor::{AnchorRouteError, AnchorStatus};
use crate::{authorized, AppState};

type Reply = Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)>;

fn err(c: StatusCode, m: &str) -> (StatusCode, Json<serde_json::Value>) {
    (c, Json(serde_json::json!({ "error": m })))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn metering_err(e: MeteringError) -> (StatusCode, Json<serde_json::Value>) {
    let code = match e {
        MeteringError::InvalidDay(_) | MeteringError::InvalidAddress(_) => StatusCode::BAD_REQUEST,
        MeteringError::NotOptedIn => StatusCode::BAD_REQUEST,
        MeteringError::EmptyReport => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    err(code, &e.to_string())
}

fn anchor_err(e: AnchorRouteError) -> (StatusCode, Json<serde_json::Value>) {
    match e {
        AnchorRouteError::Bad(m) => err(StatusCode::BAD_REQUEST, &m),
        AnchorRouteError::Conflict(m) => err(StatusCode::CONFLICT, &m),
        AnchorRouteError::Unprocessable(m) => err(StatusCode::UNPROCESSABLE_ENTITY, &m),
        AnchorRouteError::NotFound(m) => err(StatusCode::NOT_FOUND, &m),
        AnchorRouteError::Internal(m) => err(StatusCode::INTERNAL_SERVER_ERROR, &m),
    }
}

async fn blocking<T, F>(f: F) -> Result<T, (StatusCode, Json<serde_json::Value>)>
where
    F: FnOnce() -> Result<T, (StatusCode, Json<serde_json::Value>)> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "internal"))?
}

#[derive(Deserialize)]
pub(crate) struct DayQuery {
    day: Option<String>,
}

fn day_or_today(day: Option<String>) -> String {
    day.filter(|d| !d.trim().is_empty())
        .unwrap_or_else(|| citrate_agent_metering::utc_day_of_ms(now_ms()))
}

/// `GET /metering/daily?day=YYYY-MM-DD` (default: today, UTC).
pub(crate) async fn metering_daily(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Query(q): Query<DayQuery>,
) -> Reply {
    if !authorized(&headers, &st.bearer) {
        return Err(err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let day = day_or_today(q.day);
    let store = st.sessions.metering().clone();
    let resp = blocking(move || store.daily(&day).map_err(metering_err)).await?;
    serde_json::to_value(resp)
        .map(Json)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BenchmarkReq {
    day: Option<String>,
    /// The member's AgentSBT id, decimal.
    agent_id: Option<String>,
    /// The BenchmarkRegistry address.
    registry: Option<String>,
}

/// `POST /metering/benchmark` — unsigned BenchmarkRegistry calldata for one day's aggregates.
/// Naming an agent id and a registry is the opt-in; without both nothing is built.
pub(crate) async fn metering_benchmark(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Reply {
    if !authorized(&headers, &st.bearer) {
        return Err(err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let req: BenchmarkReq = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")))?;
    let (Some(agent), Some(registry)) = (req.agent_id, req.registry) else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "sharing needs the member's opt-in: an agentId and the BenchmarkRegistry address",
        ));
    };
    let agent_id: u128 = agent
        .trim()
        .parse()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "agentId is not a decimal number"))?;
    let opt_in = BenchmarkOptIn::new(agent_id, &registry).map_err(metering_err)?;
    let day = day_or_today(req.day);
    let store = st.sessions.metering().clone();
    let payload = blocking(move || {
        let daily = store.daily(&day).map_err(metering_err)?;
        build_benchmark_payload(&daily.report, Some(&opt_in)).map_err(metering_err)
    })
    .await?;
    serde_json::to_value(payload)
        .map(Json)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
}

/// `GET /anchor/status`.
pub(crate) async fn anchor_status(headers: HeaderMap, State(st): State<Arc<AppState>>) -> Reply {
    if !authorized(&headers, &st.bearer) {
        return Err(err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let status = match st.sessions.anchor().cloned() {
        None => AnchorStatus::not_configured(),
        Some(svc) => blocking(move || svc.status(now_ms()).map_err(anchor_err)).await?,
    };
    serde_json::to_value(status)
        .map(Json)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
}

fn anchor_service(
    st: &AppState,
) -> Result<Arc<crate::anchor::AnchorService>, (StatusCode, Json<serde_json::Value>)> {
    st.sessions.anchor().cloned().ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "the anchor store is not configured",
        )
    })
}

#[derive(Deserialize)]
pub(crate) struct PlanReq {
    day: u64,
    registry: Option<String>,
}

/// `POST /anchor/plan {day, registry?}` — batch one closed day; returns the unsigned call.
pub(crate) async fn anchor_plan(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Reply {
    if !authorized(&headers, &st.bearer) {
        return Err(err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let svc = anchor_service(&st)?;
    let req: PlanReq = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")))?;
    let v = blocking(move || {
        svc.plan(req.day, now_ms(), req.registry.as_deref())
            .map_err(anchor_err)
    })
    .await?;
    Ok(Json(v))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfirmReq {
    day: u64,
    commitment: String,
    tx_hash: String,
    block_number: u64,
}

/// `POST /anchor/confirm` — core reports a mined, successful anchor receipt for `day`.
pub(crate) async fn anchor_confirm(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Reply {
    if !authorized(&headers, &st.bearer) {
        return Err(err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let svc = anchor_service(&st)?;
    let req: ConfirmReq = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")))?;
    let outcome = blocking(move || {
        svc.confirm(
            req.day,
            &req.commitment,
            &req.tx_hash,
            req.block_number,
            now_ms(),
        )
        .map_err(anchor_err)
    })
    .await?;
    let recorded = match outcome {
        citrate_agent_anchor::RecordOutcome::New => "new",
        citrate_agent_anchor::RecordOutcome::Unchanged => "unchanged",
    };
    Ok(Json(
        serde_json::json!({ "ok": true, "recorded": recorded }),
    ))
}

#[derive(Deserialize)]
pub(crate) struct ProofQuery {
    seq: u64,
}

/// `GET /anchor/proof?seq=N`.
pub(crate) async fn anchor_proof(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    q: Option<Query<ProofQuery>>,
) -> Reply {
    if !authorized(&headers, &st.bearer) {
        return Err(err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let svc = anchor_service(&st)?;
    let Some(Query(q)) = q else {
        return Err(err(StatusCode::BAD_REQUEST, "seq is required"));
    };
    let v = blocking(move || svc.proof(q.seq).map_err(anchor_err)).await?;
    Ok(Json(v))
}
