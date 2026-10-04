//! HUP-S1.5 — escalation routes.
//!
//! `POST /escalations` runs ONE chat completion against a member-added endpoint. citrate-core has
//! already quoted the price, shown it, checked the member's daily spend budget (or had the member
//! confirm), and reserved the worst case before it calls here. The request carries the API key core
//! read from the OS keyring for this request only; the sidecar uses it as a bearer header and drops
//! it (wiped). It is never written to disk, logged, or returned.
//!
//! Every error answer carries `sent`: `false` means nothing left this process (core may release the
//! reservation), `true` means the provider may have received and billed the request (core keeps the
//! reservation charged; over-counting is the safe direction).
//!
//! Each escalation that may have cost money (settled, or failed after sending) leaves a content-free
//! receipt in the session metering store (US-1.5 AC3); `GET /metering/daily` sums them.
//!
//! `GET /escalations/registry` reports the registry route's status. It is disabled in this build.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use citrate_agent_escalation::{
    run, DisabledRegistry, EscalationError, EscalationRequest, HttpTransport, RegistryEscalation,
};
use citrate_agent_metering::EscalationReceipt;

use crate::{authorized, AppState};

/// One escalation may take this long end to end (a large planning answer from a remote model).
pub const ESCALATION_TIMEOUT: Duration = Duration::from_secs(120);
/// Escalations in flight at once. A further request waits up to [`SLOT_WAIT`] for a slot, then is
/// refused with 429.
pub const MAX_CONCURRENT_ESCALATIONS: usize = 2;
/// How long a request waits for a free slot.
pub const SLOT_WAIT: Duration = Duration::from_secs(10);

static SLOTS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_CONCURRENT_ESCALATIONS);

type Reply = (StatusCode, Json<serde_json::Value>);

fn refuse(code: StatusCode, msg: &str, sent: bool) -> Reply {
    (
        code,
        Json(serde_json::json!({ "error": msg, "sent": sent })),
    )
}

/// `POST /escalations`.
pub(crate) async fn escalate(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, Reply> {
    if !authorized(&headers, &st.bearer) {
        return Err(refuse(StatusCode::UNAUTHORIZED, "unauthorized", false));
    }
    if st.estop.is_stopped() {
        return Err(refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "emergency stop engaged",
            false,
        ));
    }
    // Coarse on purpose: a serde message can quote part of the body, and the body holds the key.
    let req: EscalationRequest = serde_json::from_slice(&body)
        .map_err(|_| refuse(StatusCode::BAD_REQUEST, "bad escalation request", false))?;
    let busy = || {
        refuse(
            StatusCode::TOO_MANY_REQUESTS,
            "too many escalations in flight",
            false,
        )
    };
    // What the receipt needs, taken before the request (and its key) moves to the worker.
    let receipt_id = req.escalation_id.clone();
    let receipt_model = req.model.clone();
    let reserved = req.reserved_micros;
    let permit = tokio::time::timeout(SLOT_WAIT, SLOTS.acquire())
        .await
        .map_err(|_| busy())?
        .map_err(|_| busy())?;
    let estop = st.estop.clone();
    let started_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let started = std::time::Instant::now();
    let outcome = tokio::task::spawn_blocking(move || {
        // A stop that lands while this request waited for a worker still wins.
        if estop.is_stopped() {
            return Err(EscalationError::Invalid("emergency stop engaged".into()));
        }
        run(&req, &HttpTransport, ESCALATION_TIMEOUT)
    })
    .await;
    drop(permit);
    // US-1.5 AC3: every escalation that may have cost money leaves a content-free receipt in
    // metering. A request refused before sending costs nothing and leaves none.
    let latency_ms = started.elapsed().as_millis() as u64;
    let receipt = match &outcome {
        Ok(Ok(out)) => Some(EscalationReceipt::settled(
            &receipt_id,
            &receipt_model,
            started_unix_ms,
            latency_ms,
            out.usage.map(|u| (u.prompt_tokens, u.completion_tokens)),
            reserved,
            out.charged_micros,
            out.exceeded_quote,
        )),
        Ok(Err(e)) if !e.may_have_reached_provider() => None,
        Ok(Err(_)) | Err(_) => Some(EscalationReceipt::failed_after_send(
            &receipt_id,
            &receipt_model,
            started_unix_ms,
            latency_ms,
            reserved,
        )),
    };
    if let Some(rec) = receipt {
        let store = st.sessions.metering().clone();
        // The log append is file I/O: keep it off the async workers.
        let _ = tokio::task::spawn_blocking(move || store.append_escalation(rec)).await;
    }
    match outcome {
        Ok(Ok(out)) => Ok(Json(serde_json::to_value(&out).map_err(|_| {
            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not encode the answer",
                true,
            )
        })?)),
        Ok(Err(e @ EscalationError::Invalid(_))) => Err(refuse(
            StatusCode::UNPROCESSABLE_ENTITY,
            &e.to_string(),
            false,
        )),
        Ok(Err(e)) => Err(refuse(StatusCode::BAD_GATEWAY, &e.to_string(), true)),
        Err(_) => Err(refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the escalation worker failed",
            true,
        )),
    }
}

/// `GET /escalations/registry` — the registry route's status (disabled in this build).
pub(crate) async fn registry_status(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, Reply> {
    if !authorized(&headers, &st.bearer) {
        return Err(refuse(StatusCode::UNAUTHORIZED, "unauthorized", false));
    }
    serde_json::to_value(DisabledRegistry.status())
        .map(Json)
        .map_err(|_| {
            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "status unavailable",
                false,
            )
        })
}
