//! Citrate Agent Cron — cron scheduling and Standard Operating Procedures.
//!
//! This crate provides:
//! - `CronScheduler` for time-based job scheduling with cron expressions
//! - `SOPEngine` for defining and executing Standard Operating Procedures
//! - Built-in Citrate SOPs for chain monitoring and health checks
//!
//! Each agent crate depends only on `citrate-agent-core` — never on each
//! other. The cron scheduler and SOP engine use the shared `AgentTool`
//! trait and `ToolRegistry` from agent-core.

pub mod scheduler;
pub mod sop;
pub mod citrate_sops;

// BFR-INT-poam-B — Tripwire production cron. Uses the
// `citrate-recorder` dep (alias for the new agent-core crate at
// `agent/core/`) rather than the legacy agent-core aliased above.
pub mod tripwires;
