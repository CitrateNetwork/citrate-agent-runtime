//! Citrate Agent Core — shared primitives for all agent types.
//!
//! This crate provides:
//! - `AgentTool` trait and `ToolRegistry` for registering tools
//! - `ApprovalFlow` for risk-tiered human-in-the-loop approval
//! - `Budget` for token/cost tracking and limits
//! - `AuditTrail` for immutable execution logging
//! - `EmergencyStop` for kill-switch functionality
//!
//! Each agent crate (agent-chain, agent-cron, agent-code) depends only
//! on this crate — never on each other. This ensures composability.

pub mod adapters;
pub mod approval;
pub mod audit;
pub mod benchmark;
pub mod budget;
pub mod canonical;
pub mod delegation;
pub mod error;
pub mod estop;
pub mod mcp_server;
pub mod tool;
