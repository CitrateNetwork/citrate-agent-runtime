//! # citrate-agent-mcp-host: Hermes's MCP host (HUP-S4.1)
//!
//! Hermes is an MCP *host*: the sidecar runs one MCP client per server named in an allowlist
//! file ([`config::MCP_CONFIG_ENV`]; unset = no MCP, and nothing changes). This crate:
//!
//! - **Transports:** stdio (a child process started from an absolute path with `env_clear()`, then
//!   only [`config::BASE_ENV_ALLOWLIST`] plus the server's explicit `env`; stderr discarded) and
//!   streamable HTTP (https, or http to a loopback host; redirects refused; JSON or SSE answers;
//!   `Mcp-Session-Id` and `MCP-Protocol-Version` headers).
//! - **Lifecycle (dual-era):** a 2026-07-28 server is found with `server/discover` and then spoken
//!   to statelessly (`_meta` on every request, `resultType`-aware results, the Tasks extension,
//!   URL-mode elicitation through the member); an older server gets `initialize` (asking for
//!   [`client::PROTOCOL_VERSION`], accepting [`client::LEGACY_VERSIONS`]) and
//!   `notifications/initialized`.
//! - **Reconnect and tool-list changes:** see [`host`].
//! - **Tools:** `tools/list` (paginated, bounded) → agent-loop [`ToolSpec`]s with host
//!   [`HostKind::Sidecar`], names `mcp__<server>__<tool>`, annotations mapped
//!   (`readOnlyHint` → effect none, otherwise write; `destructiveHint`/`openWorldHint` kept as
//!   hints) and trust ALWAYS untrusted, so MCP output taints the session (HUP-S2.7). By default a
//!   server offers only its read-only-annotated tools (`allow_write_tools = false`).
//! - **Calls:** `tools/call` with a per-server deadline, a response size cap, an output cap, and
//!   cancellation (`notifications/cancelled` on stdio and legacy HTTP; closing the stream on
//!   modern HTTP) on timeout or when the session's stop flag rises. Legacy server-to-client
//!   requests are answered "method not found" (no legacy client capabilities are advertised),
//!   except `ping`.
//!
//! Keyless by construction (Rule 3): nothing here holds a key or signs. Not implemented (honest
//! scope): resources/prompts, form-mode elicitation, sampling and roots (never declared), and
//! authorization (OAuth) for remote servers.
//!
//! [`ToolSpec`]: citrate_agent_loop::ToolSpec
//! [`HostKind::Sidecar`]: citrate_agent_loop::HostKind::Sidecar

pub mod client;
pub mod config;
pub mod error;
pub mod host;
pub mod mapping;
pub mod probe;
mod transport;
pub mod user;

pub use client::{
    CallOpts, CallResult, ElicitAction, Elicitor, Era, McpClient, RemoteTool, ServerInfo,
    UrlElicitation, MODERN_VERSION, PROTOCOL_VERSION, SUPPORTED_VERSIONS, TASKS_EXTENSION,
};
pub use error::McpError;
pub use host::{
    CallApproval, CallCtx, McpApprover, McpHost, McpToolHost, ServerState, ServerStatus,
};
