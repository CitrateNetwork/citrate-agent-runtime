//! MCP host errors. Messages name the server, never its URL, env or a request body.

use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpError {
    /// The server could not be started or reached.
    Spawn(String),
    /// A transport failure (pipe closed, HTTP status, connection refused, …).
    Transport(String),
    /// No answer within the deadline. The server was asked to cancel.
    Timeout(Duration),
    /// The session's stop flag was raised. The server was asked to cancel.
    Cancelled,
    /// A single response exceeded the configured cap (bytes).
    Oversize(usize),
    /// The server's answer was not usable JSON-RPC / MCP.
    BadResponse(String),
    /// A JSON-RPC error object from the server (its message is untrusted text).
    Rpc { code: i64, message: String },
    /// The server process exited.
    ServerExited(String),
    /// The server negotiated something this host does not speak.
    Unsupported(String),
    /// A non-success HTTP status whose body was not a recognized MCP error (streamable HTTP).
    HttpStatus(u16),
    /// The server does not implement the requested protocol version (`-32022`, 2026-07-28); the
    /// versions it says it supports.
    UnsupportedVersion { supported: Vec<String> },
    /// The server ended a task without a result (Tasks extension `cancelled`).
    TaskCancelled,
    /// The server asked for input this host does not provide (a form, sampling, or roots), or
    /// kept asking past the round limit.
    InputRequired(String),
}

impl McpError {
    /// A JSON-RPC error code reserved for the 2026-07-28 specification (`-32020..=-32099`), or an
    /// unsupported-version answer: either way the server speaks the modern protocol.
    pub fn is_modern_protocol_error(&self) -> bool {
        match self {
            McpError::UnsupportedVersion { .. } => true,
            McpError::Rpc { code, .. } => (-32099..=-32020).contains(code),
            _ => false,
        }
    }
}

impl std::fmt::Display for McpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpError::Spawn(m) => write!(f, "could not start the server: {m}"),
            McpError::Transport(m) => write!(f, "transport error: {m}"),
            McpError::Timeout(d) => write!(
                f,
                "no answer within {} ms; the server was asked to cancel",
                d.as_millis()
            ),
            McpError::Cancelled => write!(f, "stopped; the server was asked to cancel"),
            McpError::Oversize(n) => write!(f, "the response was larger than {n} bytes"),
            McpError::BadResponse(m) => write!(f, "unusable response: {m}"),
            McpError::Rpc { code, message } => write!(f, "server error {code}: {message}"),
            McpError::ServerExited(m) => write!(f, "the server exited ({m})"),
            McpError::Unsupported(m) => write!(f, "unsupported: {m}"),
            McpError::HttpStatus(code) => write!(f, "transport error: HTTP {code}"),
            McpError::UnsupportedVersion { supported } => write!(
                f,
                "the server does not speak this protocol version (it supports: {})",
                supported
                    .iter()
                    .take(8)
                    .map(|v| v.chars().take(20).collect::<String>())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            McpError::TaskCancelled => write!(f, "the server cancelled the task"),
            McpError::InputRequired(m) => write!(f, "the server needs input: {m}"),
        }
    }
}

impl std::error::Error for McpError {}
