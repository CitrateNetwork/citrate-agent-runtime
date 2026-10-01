//! HUP-S7.3 (runtime, sidecar routes): the nightly anchor batch over the local decision records.
//!
//! citrate-core owns the schedule, the anchor key and the signature (Rule 3, Rule-3 ADR D5). The
//! sidecar owns the batching code ([`citrate_agent_anchor`]), so core asks it, over the
//! bearer-authed loopback channel:
//!
//! - `GET /anchor/status`: closed days still to batch, batched days awaiting confirmation,
//!   confirmed days, days reported incomplete.
//! - `POST /anchor/plan {day, registry?}`: batch one closed day (recorded in the local ledger) and
//!   return the **unsigned** `AnchorRegistry.anchor(NightlyMerkle, commitment)` call. Nothing is
//!   signed or sent here.
//! - `POST /anchor/confirm {day, commitment, txHash, blockNumber}`: core reports a mined, successful
//!   receipt. The day is marked anchored only when `commitment` is the one batched for that day.
//! - `GET /anchor/proof?seq=N`: an inclusion proof for one decision record.
//!
//! Both directories come from citrate-core (`CITRATE_HERMES_RECORDS_DIR`,
//! `CITRATE_HERMES_ANCHOR_DIR`). Unset: the routes answer "not configured".

use std::path::{Path, PathBuf};

use citrate_agent_anchor::{
    pending_days, plan_day, prove, verify_proof, AnchorLedger, EntryStatus, Error as AnchorError,
    NightlyPlan, RecordOutcome,
};
use serde::Serialize;

pub const RECORDS_DIR_ENV: &str = "CITRATE_HERMES_RECORDS_DIR";
pub const ANCHOR_DIR_ENV: &str = "CITRATE_HERMES_ANCHOR_DIR";
const DAY_MS: u64 = 86_400_000;

/// The two directories the anchor service needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorPaths {
    pub records_dir: PathBuf,
    pub anchor_dir: PathBuf,
}

impl AnchorPaths {
    /// Both must be given and absolute.
    pub fn from_values(records: Option<&str>, anchor: Option<&str>) -> Option<Self> {
        let abs = |v: Option<&str>| {
            let v = v?.trim();
            let p = PathBuf::from(v);
            (!v.is_empty() && p.is_absolute()).then_some(p)
        };
        Some(AnchorPaths {
            records_dir: abs(records)?,
            anchor_dir: abs(anchor)?,
        })
    }

    pub fn from_env() -> Option<Self> {
        Self::from_values(
            std::env::var(RECORDS_DIR_ENV).ok().as_deref(),
            std::env::var(ANCHOR_DIR_ENV).ok().as_deref(),
        )
    }
}

/// An error mapped to an HTTP status by the routes.
#[derive(Debug, PartialEq, Eq)]
pub enum AnchorRouteError {
    /// 400: the request itself is malformed.
    Bad(String),
    /// 409: the request conflicts with the ledger (wrong commitment, not batched, records changed).
    Conflict(String),
    /// 422: well formed but not allowed now (the day is not over).
    Unprocessable(String),
    /// 404
    NotFound(String),
    /// 500: the records or the ledger could not be read or written.
    Internal(String),
}

fn map_err(e: AnchorError) -> AnchorRouteError {
    match e {
        AnchorError::BadCalldata(m) => AnchorRouteError::Bad(m),
        e @ AnchorError::DayNotClosed { .. } => AnchorRouteError::Unprocessable(e.to_string()),
        e @ (AnchorError::Conflict { .. }
        | AnchorError::NotBatched { .. }
        | AnchorError::PrunedDay { .. }
        | AnchorError::Overlap { .. }) => AnchorRouteError::Conflict(e.to_string()),
        e => AnchorRouteError::Internal(e.to_string()),
    }
}

/// `YYYY-MM-DD` for a UTC day number.
pub fn date_of_day(day: u64) -> String {
    citrate_agent_metering::utc_day_of_ms(day.saturating_mul(DAY_MS))
}

fn hex32(b: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let h = s.strip_prefix("0x")?;
    if h.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(h, &mut out).ok()?;
    Some(out)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DayRef {
    pub day: u64,
    pub date: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchedDay {
    pub day: u64,
    pub date: String,
    pub count: u64,
    pub commitment: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchoredDay {
    pub day: u64,
    pub date: String,
    pub count: u64,
    pub commitment: Option<String>,
    pub tx_hash: String,
    pub block_number: u64,
}

/// `GET /anchor/status` body.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorStatus {
    pub configured: bool,
    pub reason: Option<String>,
    /// Whether the decision-records directory exists yet (nothing writes it until decisions are
    /// recorded).
    pub records_present: bool,
    pub pending_days: Vec<DayRef>,
    pub awaiting_confirmation: Vec<BatchedDay>,
    pub anchored: Vec<AnchoredDay>,
    pub incomplete: Vec<DayRef>,
}

impl AnchorStatus {
    pub fn not_configured() -> Self {
        AnchorStatus {
            configured: false,
            reason: Some(
                "the anchor store is not configured (citrate-core sets the decision-records and \
                 anchor-ledger folders)"
                    .into(),
            ),
            records_present: false,
            pending_days: vec![],
            awaiting_confirmation: vec![],
            anchored: vec![],
            incomplete: vec![],
        }
    }
}

/// The ledger plus the records it batches. Holds the ledger's writer lock for its life.
pub struct AnchorService {
    records_dir: PathBuf,
    ledger: AnchorLedger,
}

impl AnchorService {
    pub fn open(records_dir: &Path, anchor_dir: &Path) -> Result<Self, String> {
        let ledger = AnchorLedger::open(anchor_dir).map_err(|e| e.to_string())?;
        Ok(AnchorService {
            records_dir: records_dir.to_path_buf(),
            ledger,
        })
    }

    pub fn from_paths(p: &AnchorPaths) -> Result<Self, String> {
        Self::open(&p.records_dir, &p.anchor_dir)
    }

    fn records_present(&self) -> bool {
        self.records_dir.is_dir()
    }

    pub fn status(&self, now_ms: u64) -> Result<AnchorStatus, AnchorRouteError> {
        let records_present = self.records_present();
        let pending = if records_present {
            pending_days(&self.records_dir, &self.ledger, now_ms).map_err(map_err)?
        } else {
            Vec::new()
        };
        let mut st = AnchorStatus {
            configured: true,
            reason: None,
            records_present,
            pending_days: pending
                .into_iter()
                .map(|day| DayRef {
                    day,
                    date: date_of_day(day),
                })
                .collect(),
            awaiting_confirmation: vec![],
            anchored: vec![],
            incomplete: vec![],
        };
        for e in self.ledger.entries().map_err(map_err)? {
            let date = date_of_day(e.day);
            match (e.status, &e.confirmed) {
                (EntryStatus::Incomplete, _) => st.incomplete.push(DayRef { day: e.day, date }),
                (EntryStatus::Batched, None) => st.awaiting_confirmation.push(BatchedDay {
                    day: e.day,
                    date,
                    count: e.count,
                    commitment: e.commitment.as_ref().map(hex32),
                }),
                (EntryStatus::Batched, Some(c)) => st.anchored.push(AnchoredDay {
                    day: e.day,
                    date,
                    count: e.count,
                    commitment: e.commitment.as_ref().map(hex32),
                    tx_hash: c.tx_hash.clone(),
                    block_number: c.block_number,
                }),
            }
        }
        Ok(st)
    }

    /// Plan one closed day. The JSON names the plan (`empty`, `pruned`, `incomplete`, `ready`,
    /// `already_anchored`) and, for `ready`, carries the unsigned call. `sent` is always false.
    pub fn plan(
        &self,
        day: u64,
        now_ms: u64,
        registry: Option<&str>,
    ) -> Result<serde_json::Value, AnchorRouteError> {
        if !self.records_present() {
            let today = now_ms / DAY_MS;
            if day >= today {
                return Err(AnchorRouteError::Unprocessable(format!(
                    "day {day} is not over yet"
                )));
            }
            return Ok(serde_json::json!({
                "plan": "empty", "day": day, "date": date_of_day(day), "sent": false
            }));
        }
        let plan =
            plan_day(&self.records_dir, &self.ledger, day, now_ms, registry).map_err(map_err)?;
        Ok(match plan {
            NightlyPlan::Empty { day } => serde_json::json!({
                "plan": "empty", "day": day, "date": date_of_day(day), "sent": false
            }),
            NightlyPlan::Pruned { day } => serde_json::json!({
                "plan": "pruned", "day": day, "date": date_of_day(day), "sent": false
            }),
            NightlyPlan::Incomplete { day, retained } => serde_json::json!({
                "plan": "incomplete", "day": day, "date": date_of_day(day),
                "retained": retained, "sent": false
            }),
            NightlyPlan::Ready {
                header,
                commitment,
                call,
                newly_recorded,
            } => serde_json::json!({
                "plan": "ready",
                "day": header.day,
                "date": date_of_day(header.day),
                "header": header,
                "commitment": hex32(&commitment),
                "call": call,
                "newlyRecorded": newly_recorded,
                "sent": false,
            }),
            NightlyPlan::AlreadyAnchored { entry } => serde_json::json!({
                "plan": "already_anchored",
                "day": entry.day,
                "date": date_of_day(entry.day),
                "commitment": entry.commitment.as_ref().map(hex32),
                "confirmed": entry.confirmed,
                "sent": false,
            }),
        })
    }

    /// Record core's confirmation. `commitment` must be the batched one for `day`.
    pub fn confirm(
        &self,
        day: u64,
        commitment: &str,
        tx_hash: &str,
        block_number: u64,
        now_ms: u64,
    ) -> Result<RecordOutcome, AnchorRouteError> {
        let claimed = parse_hex32(commitment)
            .ok_or_else(|| AnchorRouteError::Bad("commitment is not 0x + 64 hex digits".into()))?;
        if parse_hex32(tx_hash).is_none() {
            return Err(AnchorRouteError::Bad(
                "txHash is not 0x + 64 hex digits".into(),
            ));
        }
        let entry =
            self.ledger.get(day).map_err(map_err)?.ok_or_else(|| {
                AnchorRouteError::Conflict(format!("day {day} was never batched"))
            })?;
        if entry.commitment != Some(claimed) {
            return Err(AnchorRouteError::Conflict(format!(
                "day {day} was batched with a different commitment"
            )));
        }
        self.ledger
            .mark_confirmed(day, &tx_hash.to_ascii_lowercase(), block_number, now_ms)
            .map_err(map_err)
    }

    /// An inclusion proof for record `seq`, checked against the batched commitment.
    pub fn proof(&self, seq: u64) -> Result<serde_json::Value, AnchorRouteError> {
        if !self.records_present() {
            return Err(AnchorRouteError::NotFound(format!(
                "record {seq} is not retained"
            )));
        }
        let p = prove(&self.records_dir, &self.ledger, seq)
            .map_err(map_err)?
            .ok_or_else(|| AnchorRouteError::NotFound(format!("record {seq} is not retained")))?;
        let commitment = p.header.commitment();
        let entry = self.ledger.get(p.header.day).map_err(map_err)?;
        Ok(serde_json::json!({
            "seq": seq,
            "day": p.header.day,
            "date": date_of_day(p.header.day),
            "commitment": hex32(&commitment),
            "verifies": verify_proof(&p, &commitment),
            "anchored": entry.and_then(|e| e.confirmed),
            "proof": p,
        }))
    }
}
