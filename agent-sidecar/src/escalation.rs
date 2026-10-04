//! HUP-S1.5 — escalation routes.
//!
//! `POST /escalations` runs ONE chat completion against a member-added endpoint. citrate-core has
//! already quoted the price, shown it, checked the member's daily spend budget (or had the member
//! confirm), and reserved the worst case before it calls here. The request carries the API key core
//! read from the OS keyring for this request only; the sidecar uses it as a bearer header and drops
//! it (wiped). It is never written to disk, logged, or returned.
//!
//! `POST /escalations/registry` runs ONE paid chat completion against a provider the on-chain
//! InferenceRouter lists. citrate-core read the router, built the x402 authorization, had the
//! member approve it in the SignatureCeremony and checked the signature before calling here; the
//! sidecar only carries the signed payment as the `X-PAYMENT` header and returns the answer with the
//! provider's `X-PAYMENT-RESPONSE` receipt. It never signs and holds no key.
//!
//! Every error answer carries `sent`: `false` means nothing left this process (core may release the
//! reservation), `true` means the provider may have received the request (and, on the registry
//! route, the payment authorization; core keeps it charged and checks the chain).
//!
//! Every escalation, answered or not, leaves one content-free record in metering
//! (`escalations.jsonl` beside the turn log when citrate-core configures a metering folder, else in
//! memory). `GET /metering/escalations?day=YYYY-MM-DD` reports a day of them (US-1.5 AC3).
//!
//! `GET /escalations/registry` reports what the sidecar's half of the registry route carries.
//! Whether the route is on is citrate-core's decision.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use citrate_agent_escalation::{
    registry_route_status, run, run_registry, EscalationError, EscalationRequest, HttpTransport,
    RegistryEscalationRequest, RegistryOutcome, Usage,
};
use citrate_agent_metering::{
    ChargeUnit, EscalationLog, EscalationOutcomeKind, EscalationRecord, EscalationReport,
    EscalationRoute, MeteringError, ReceiptRecord, ESCALATION_RECORD_SCHEMA,
};
use serde::Deserialize;

use crate::{authorized, AppState};

/// One escalation may take this long end to end (a large planning answer from a remote model).
pub const ESCALATION_TIMEOUT: Duration = Duration::from_secs(120);
/// Escalations in flight at once (both routes share the slots). A further request waits up to
/// [`SLOT_WAIT`] for a slot, then is refused with 429.
pub const MAX_CONCURRENT_ESCALATIONS: usize = 2;
/// How long a request waits for a free slot.
pub const SLOT_WAIT: Duration = Duration::from_secs(10);
/// The escalation log inside the metering folder.
pub const ESCALATION_LOG_FILE: &str = "escalations.jsonl";
/// Records kept in memory when there is no log (oldest dropped first).
pub const ESCALATION_MEMORY_CAP: usize = 2_000;

static SLOTS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_CONCURRENT_ESCALATIONS);

type Reply = (StatusCode, Json<serde_json::Value>);

fn refuse(code: StatusCode, msg: &str, sent: bool) -> Reply {
    (
        code,
        Json(serde_json::json!({ "error": msg, "sent": sent })),
    )
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Metering store for escalation records
// ---------------------------------------------------------------------------

/// Where escalation records live: the JSONL log beside the turn log, or a bounded memory list.
pub struct EscalationStore {
    log: Option<EscalationLog>,
    memory: Mutex<VecDeque<EscalationRecord>>,
}

impl EscalationStore {
    pub fn in_memory() -> Self {
        EscalationStore {
            log: None,
            memory: Mutex::new(VecDeque::new()),
        }
    }

    /// Records appended to `<dir>/escalations.jsonl`.
    pub fn persistent(dir: &std::path::Path) -> Self {
        EscalationStore {
            log: Some(EscalationLog::new(dir.join(ESCALATION_LOG_FILE))),
            memory: Mutex::new(VecDeque::new()),
        }
    }

    /// The store named by the metering folder (an absolute path), else in memory.
    pub fn from_value(value: Option<&str>) -> Self {
        match value.map(str::trim).filter(|v| !v.is_empty()) {
            Some(dir) if std::path::Path::new(dir).is_absolute() => {
                Self::persistent(std::path::Path::new(dir))
            }
            _ => Self::in_memory(),
        }
    }

    /// `"log"` when records are written to disk, `"memory"` otherwise.
    pub fn source(&self) -> &'static str {
        if self.log.is_some() {
            "log"
        } else {
            "memory"
        }
    }

    fn memory(&self) -> std::sync::MutexGuard<'_, VecDeque<EscalationRecord>> {
        match self.memory.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    fn remember(&self, rec: EscalationRecord) {
        let mut m = self.memory();
        m.push_back(rec);
        while m.len() > ESCALATION_MEMORY_CAP {
            m.pop_front();
        }
    }

    /// Keep one record. A record the log cannot take is kept in memory instead.
    pub fn append(&self, rec: EscalationRecord) {
        match &self.log {
            Some(log) => {
                if let Err(e) = log.append(&rec) {
                    eprintln!("citrate-agent-sidecar: escalation metering write failed: {e}");
                    self.remember(rec);
                }
            }
            None => self.remember(rec),
        }
    }

    pub fn records(&self) -> Result<Vec<EscalationRecord>, MeteringError> {
        let mut out = match &self.log {
            Some(log) => log.read_all()?,
            None => Vec::new(),
        };
        out.extend(self.memory().iter().cloned());
        Ok(out)
    }
}

/// The process-wide store, opened from `CITRATE_HERMES_METERING_DIR` on first use.
pub fn escalation_store() -> &'static EscalationStore {
    static STORE: OnceLock<EscalationStore> = OnceLock::new();
    STORE.get_or_init(|| {
        EscalationStore::from_value(
            std::env::var(crate::metering::METERING_DIR_ENV)
                .ok()
                .as_deref(),
        )
    })
}

fn outcome_of(e: &EscalationError) -> EscalationOutcomeKind {
    if e.may_have_reached_provider() {
        EscalationOutcomeKind::FailedMaybeSent
    } else {
        EscalationOutcomeKind::FailedNotSent
    }
}

struct Started {
    id: String,
    model: String,
    at_ms: u64,
    clock: Instant,
}

impl Started {
    fn new(id: &str, model: &str) -> Self {
        Started {
            id: id.to_string(),
            model: model.to_string(),
            at_ms: now_ms(),
            clock: Instant::now(),
        }
    }

    fn record(
        &self,
        route: EscalationRoute,
        usage: Option<Usage>,
        (charged, unit): (String, ChargeUnit),
        payee: Option<String>,
        receipt: Option<ReceiptRecord>,
        outcome: EscalationOutcomeKind,
    ) -> EscalationRecord {
        EscalationRecord {
            schema: ESCALATION_RECORD_SCHEMA,
            escalation_id: self.id.clone(),
            route,
            model: self.model.clone(),
            started_unix_ms: self.at_ms,
            latency_ms: self.clock.elapsed().as_millis() as u64,
            tokens_in: usage.map(|u| u.prompt_tokens),
            tokens_out: usage.map(|u| u.completion_tokens),
            charged,
            unit,
            payee,
            receipt,
            outcome,
        }
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

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
    let permit = tokio::time::timeout(SLOT_WAIT, SLOTS.acquire())
        .await
        .map_err(|_| busy())?
        .map_err(|_| busy())?;
    let started = Started::new(&req.escalation_id, &req.model);
    let reserved = req.reserved_micros;
    let estop = st.estop.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        // A stop that lands while this request waited for a worker still wins.
        if estop.is_stopped() {
            return Err(EscalationError::Invalid("emergency stop engaged".into()));
        }
        run(&req, &HttpTransport, ESCALATION_TIMEOUT)
    })
    .await;
    drop(permit);
    let rec = |usage, charged: u64, outcome| {
        started.record(
            EscalationRoute::Endpoint,
            usage,
            (charged.to_string(), ChargeUnit::MicroUsd),
            None,
            None,
            outcome,
        )
    };
    match outcome {
        Ok(Ok(out)) => {
            escalation_store().append(rec(
                out.usage,
                out.charged_micros,
                EscalationOutcomeKind::Answered,
            ));
            Ok(Json(serde_json::to_value(&out).map_err(|_| {
                refuse(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not encode the answer",
                    true,
                )
            })?))
        }
        Ok(Err(e @ EscalationError::Invalid(_))) => {
            escalation_store().append(rec(None, 0, EscalationOutcomeKind::FailedNotSent));
            Err(refuse(
                StatusCode::UNPROCESSABLE_ENTITY,
                &e.to_string(),
                false,
            ))
        }
        Ok(Err(e)) => {
            // Core keeps the reservation charged when the request may have been billed.
            escalation_store().append(rec(None, reserved, outcome_of(&e)));
            Err(refuse(StatusCode::BAD_GATEWAY, &e.to_string(), true))
        }
        Err(_) => {
            escalation_store().append(rec(None, reserved, EscalationOutcomeKind::FailedMaybeSent));
            Err(refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the escalation worker failed",
                true,
            ))
        }
    }
}

fn now_secs() -> u64 {
    now_ms() / 1000
}

fn registry_record(
    started: &Started,
    req_asset: &str,
    req_network: &str,
    payee: &str,
    value: &str,
    out: Option<&RegistryOutcome>,
    outcome: EscalationOutcomeKind,
) -> EscalationRecord {
    // An EIP-3009 authorization settles its full value or nothing. Once it may have reached the
    // provider it counts as spent until core's on-chain check says otherwise.
    let charged = match outcome {
        EscalationOutcomeKind::FailedNotSent => "0".to_string(),
        _ => value.to_string(),
    };
    started.record(
        EscalationRoute::Registry,
        out.and_then(|o| o.usage),
        (
            charged,
            ChargeUnit::BaseUnits {
                asset: req_asset.to_ascii_lowercase(),
                network: req_network.to_string(),
            },
        ),
        Some(payee.to_ascii_lowercase()),
        out.and_then(|o| o.receipt.as_ref()).map(|r| ReceiptRecord {
            success: r.success,
            transaction: r.transaction.clone(),
            network: r.network.clone(),
            payer: r.payer.clone(),
        }),
        outcome,
    )
}

/// `POST /escalations/registry`: one paid request to a router-listed provider.
pub(crate) async fn escalate_registry(
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
    let req: RegistryEscalationRequest = serde_json::from_slice(&body).map_err(|_| {
        refuse(
            StatusCode::BAD_REQUEST,
            "bad registry escalation request",
            false,
        )
    })?;
    let busy = || {
        refuse(
            StatusCode::TOO_MANY_REQUESTS,
            "too many escalations in flight",
            false,
        )
    };
    let permit = tokio::time::timeout(SLOT_WAIT, SLOTS.acquire())
        .await
        .map_err(|_| busy())?
        .map_err(|_| busy())?;
    let started = Started::new(&req.escalation_id, &req.model);
    let (asset, network, payee, value) = (
        req.payment.asset.clone(),
        req.payment.network.clone(),
        req.payment.to.clone(),
        req.payment.value.clone(),
    );
    let estop = st.estop.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        if estop.is_stopped() {
            return Err(EscalationError::Invalid("emergency stop engaged".into()));
        }
        run_registry(&req, &HttpTransport, ESCALATION_TIMEOUT, now_secs())
    })
    .await;
    drop(permit);
    let record = |out: Option<&RegistryOutcome>, kind| {
        escalation_store().append(registry_record(
            &started, &asset, &network, &payee, &value, out, kind,
        ))
    };
    match outcome {
        Ok(Ok(out)) => {
            record(Some(&out), EscalationOutcomeKind::Answered);
            Ok(Json(serde_json::to_value(&out).map_err(|_| {
                refuse(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not encode the answer",
                    true,
                )
            })?))
        }
        Ok(Err(e @ EscalationError::Invalid(_))) => {
            record(None, EscalationOutcomeKind::FailedNotSent);
            Err(refuse(
                StatusCode::UNPROCESSABLE_ENTITY,
                &e.to_string(),
                false,
            ))
        }
        Ok(Err(e)) => {
            record(None, outcome_of(&e));
            Err(refuse(StatusCode::BAD_GATEWAY, &e.to_string(), true))
        }
        Err(_) => {
            record(None, EscalationOutcomeKind::FailedMaybeSent);
            Err(refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the escalation worker failed",
                true,
            ))
        }
    }
}

/// `GET /escalations/registry` — what the sidecar's half of the registry route carries.
pub(crate) async fn registry_status(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, Reply> {
    if !authorized(&headers, &st.bearer) {
        return Err(refuse(StatusCode::UNAUTHORIZED, "unauthorized", false));
    }
    serde_json::to_value(registry_route_status())
        .map(Json)
        .map_err(|_| {
            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "status unavailable",
                false,
            )
        })
}

#[derive(Deserialize)]
pub(crate) struct EscalationDayQuery {
    day: Option<String>,
}

/// `GET /metering/escalations?day=YYYY-MM-DD` (default: today, UTC): the day's escalation report.
pub(crate) async fn metering_escalations(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Query(q): Query<EscalationDayQuery>,
) -> Result<Json<serde_json::Value>, Reply> {
    if !authorized(&headers, &st.bearer) {
        return Err(refuse(StatusCode::UNAUTHORIZED, "unauthorized", false));
    }
    let day = q
        .day
        .filter(|d| !d.trim().is_empty())
        .unwrap_or_else(|| citrate_agent_metering::utc_day_of_ms(now_ms()));
    let built = tokio::task::spawn_blocking(move || {
        let store = escalation_store();
        let records = store.records()?;
        EscalationReport::build(&day, &records).map(|r| (r, store.source()))
    })
    .await
    .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "internal", false))?;
    match built {
        Ok((report, source)) => Ok(Json(serde_json::json!({
            "source": source,
            "persisted": source == "log",
            "report": report,
        }))),
        Err(MeteringError::InvalidDay(d)) => Err(refuse(
            StatusCode::BAD_REQUEST,
            &format!("not a valid UTC day: {d}"),
            false,
        )),
        Err(e) => Err(refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            &e.to_string(),
            false,
        )),
    }
}
