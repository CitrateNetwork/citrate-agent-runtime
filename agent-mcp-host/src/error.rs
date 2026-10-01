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
        }
    }
}

impl std::error::Error for McpError {}
