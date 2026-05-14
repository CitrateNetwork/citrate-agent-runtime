//! External runtime adapters — Hermes, OpenClaw, ZeroClaw.
//! Each adapter bridges an external runtime to the Citrate substrate
//! through the MCP server and capability grant system.

pub mod hermes;
pub mod openclaw;
pub mod sandbox;
