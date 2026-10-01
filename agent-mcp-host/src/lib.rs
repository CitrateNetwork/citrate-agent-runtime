//! # citrate-agent-mcp-host: Hermes's MCP host (HUP-S4.1)
//!
//! Hermes is an MCP *host*: the sidecar runs one MCP client per server named in an allowlist
//! file ([`config::MCP_CONFIG_ENV`]; unset = no MCP, and nothing changes). This crate:
//!
//! - **Transports:** stdio (a child process started from an absolute path with `env_clear()`, then
//!   only [`config::BASE_ENV_ALLOWLIST`] plus the server's explicit `env`; stderr discarded) and
//!   streamable HTTP (https, or http to a loopback host; redirects refused; JSON or SSE answers;
//!   `Mcp-Session-Id` and `MCP-Protocol-Version` headers).
//! - **Lifecycle:** `initialize` asks for [`client::PROTOCOL_VERSION`] and accepts any of
//!   [`client::SUPPORTED_VERSIONS`]; capabilities and server info are recorded; then
//!   `notifications/initialized`.
//! - **Tools:** `tools/list` (paginated, bounded) → agent-loop [`ToolSpec`]s with host
//!   [`HostKind::Sidecar`], names `mcp__<server>__<tool>`, annotations mapped
//!   (`readOnlyHint` → effect none, otherwise write; `destructiveHint`/`openWorldHint` kept as
//!   hints) and trust ALWAYS untrusted, so MCP output taints the session (HUP-S2.7). By default a
//!   server offers only its read-only-annotated tools (`allow_write_tools = false`).
//! - **Calls:** `tools/call` with a per-server deadline, a response size cap, an output cap, and
//!   cancellation (`notifications/cancelled`) on timeout or when the session's stop flag rises.
//!   Server-to-client requests are answered "method not found" (no client capabilities are
//!   advertised), except `ping`.
//!
//! Keyless by construction (Rule 3): nothing here holds a key or signs. Not implemented (honest
//! scope): the 2026-07-28 stateless revision, the Tasks extension, URL-mode elicitation,
//! resources/prompts, authorization (OAuth) for remote servers, automatic reconnect after a
//! server exits, and acting on `tools/list_changed` (recorded only).
//!
//! [`ToolSpec`]: citrate_agent_loop::ToolSpec
//! [`HostKind::Sidecar`]: citrate_agent_loop::HostKind::Sidecar

pub mod client;
pub mod config;
pub mod error;
pub mod host;
pub mod mapping;
mod transport;

pub use client::{
    CallResult, McpClient, RemoteTool, ServerInfo, PROTOCOL_VERSION, SUPPORTED_VERSIONS,
};
pub use error::McpError;
pub use host::{McpHost, McpToolHost, ServerState, ServerStatus};
