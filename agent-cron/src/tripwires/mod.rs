//! BFR-INT-poam-B — Tripwire production cron.
//!
//! 9 named FedRAMP tripwires (TRIP-AC-001..TRIP-SI-001) implemented
//! as scheduled jobs. Each job follows the same shape:
//!
//! ```text
//! poll metric → eval threshold (with hysteresis) → fire on chain
//! ```
//!
//! The 9 jobs are factored into 3 categories per the planset:
//!
//! - **Simple metric** (`TRIP-AU-001`, `TRIP-AU-002`, `TRIP-SC-001`):
//!   read a single number from Prometheus / disk, compare to a
//!   threshold.
//! - **Chain correlation** (`TRIP-AC-001`, `TRIP-CM-001`,
//!   `TRIP-IA-001`): scan recent on-chain events + cross-check.
//! - **Critical** (`TRIP-AC-002`, `TRIP-AU-003`, `TRIP-SI-001`):
//!   higher-stakes correlations (FN status change race, IPFS pin
//!   failure rate, release manifest hash mismatch).
//!
//! Each job has a `run()` async function that returns a `JobOutcome`:
//! `NoBreach` (most common), `Fired(tx_hash)`, or `Failed(reason)`.
//!
//! See `.agentile/planset/2026-05-16-poam-operationalization/
//! 02_TRIPWIRE_CRON.md` for the full design.

pub mod metric_source;
pub mod evaluator;
pub mod jobs;

pub use evaluator::{HysteresisGate, JobOutcome};
pub use metric_source::{ChainEvent, ChainQuery, MetricSource};
