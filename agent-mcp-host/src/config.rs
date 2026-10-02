//! The MCP server allowlist (HUP-S4.1). The sidecar reads it from the file named by
//! [`MCP_CONFIG_ENV`]; unset means no MCP at all. Only servers listed here are ever started or
//! contacted, and every field is validated before anything runs.
//!
//! TOML (any extension other than `.json`):
//!
//! ```toml
//! [[servers]]
//! name = "scan"                       # [a-z0-9][a-z0-9_-]{0,23}; tools become mcp__scan__<tool>
//! transport = "http"
//! url = "https://scan.example/api/mcp" # https, or http to a loopback host only
//!
//! [[servers]]
//! name = "mem"
//! transport = "stdio"
//! command = "/opt/citrate/bin/mem-mcp"  # absolute path; no PATH lookup
//! args = ["--tenant", "personal"]
//! env = { MEM_TENANT = "personal" }     # explicit per-server env; nothing else is inherited
//! timeout_ms = 30000
//! allow_write_tools = false             # default: only read-only-annotated tools are offered
//! ```
//!
//! JSON (`.json`): the same shape, `{"servers": [ ... ]}`.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The environment variable naming the allowlist file. Unset (the default) = no MCP.
pub const MCP_CONFIG_ENV: &str = "CITRATE_HERMES_MCP";

/// At most this many servers.
pub const MAX_SERVERS: usize = 16;
/// Defaults and bounds.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_INIT_TIMEOUT: Duration = Duration::from_secs(15);
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1 << 20;
pub const DEFAULT_MAX_OUTPUT_CHARS: usize = 16_000;
const MIN_TIMEOUT_MS: u64 = 100;
const MAX_TIMEOUT_MS: u64 = 600_000;
const MIN_RESPONSE_BYTES: usize = 1024;
const MAX_RESPONSE_BYTES: usize = 16 << 20;
const MAX_ENV: usize = 64;
const MAX_ARGS: usize = 64;

/// Variables a stdio server may inherit from the sidecar's environment. Everything else is
/// dropped; a server that needs more gets it through its explicit `env` table.
pub const BASE_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    // Windows needs these to start most processes at all.
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PATHEXT",
    "COMSPEC",
];

/// How to reach one server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportConfig {
    /// A child process speaking newline-delimited JSON-RPC on stdin/stdout.
    Stdio {
        command: PathBuf,
        args: Vec<String>,
        /// Explicit per-server environment (added on top of [`BASE_ENV_ALLOWLIST`]).
        env: BTreeMap<String, String>,
        cwd: Option<PathBuf>,
    },
    /// Streamable HTTP (one POST per message; JSON or SSE responses).
    Http { url: String },
}

/// One allowlisted server.
#[derive(Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub name: String,
    pub transport: TransportConfig,
    /// Per-request deadline for tool calls.
    pub timeout: Duration,
    /// Deadline for `initialize` and `tools/list`.
    pub init_timeout: Duration,
    /// Largest single response accepted (bytes on the wire).
    pub max_response_bytes: usize,
    /// Longest tool output handed to the model (chars); longer output is truncated.
    pub max_output_chars: usize,
    /// Offer tools that are not annotated read-only. Default false.
    pub allow_write_tools: bool,
}

impl std::fmt::Debug for ServerConfig {
    // Never print env values or URLs (either may carry a credential).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.transport {
            TransportConfig::Stdio { .. } => "stdio",
            TransportConfig::Http { .. } => "http",
        };
        f.debug_struct("ServerConfig")
            .field("name", &self.name)
            .field("transport", &kind)
            .field("timeout", &self.timeout)
            .field("allow_write_tools", &self.allow_write_tools)
            .finish_non_exhaustive()
    }
}

impl ServerConfig {
    /// A server with the default limits.
    pub fn new(name: &str, transport: TransportConfig) -> Self {
        ServerConfig {
            name: name.to_string(),
            transport,
            timeout: DEFAULT_TIMEOUT,
            init_timeout: DEFAULT_INIT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_output_chars: DEFAULT_MAX_OUTPUT_CHARS,
            allow_write_tools: false,
        }
    }

    pub fn transport_kind(&self) -> &'static str {
        match self.transport {
            TransportConfig::Stdio { .. } => "stdio",
            TransportConfig::Http { .. } => "http",
        }
    }
}

/// The whole allowlist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct McpConfig {
    pub servers: Vec<ServerConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(default)]
    servers: Vec<RawServer>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    name: String,
    transport: String,
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    cwd: Option<String>,
    url: Option<String>,
    timeout_ms: Option<u64>,
    init_timeout_ms: Option<u64>,
    max_response_bytes: Option<usize>,
    max_output_chars: Option<usize>,
    #[serde(default)]
    allow_write_tools: bool,
}

/// `[a-z0-9][a-z0-9_-]{0,23}` with no `__` (the name is part of every exposed tool name).
pub fn validate_server_name(name: &str) -> Result<(), String> {
    let ok_len = !name.is_empty() && name.len() <= 24;
    let ok_first = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let ok_chars = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if ok_len && ok_first && ok_chars && !name.contains("__") {
        Ok(())
    } else {
        Err(format!(
            "server name {name:?} must be 1-24 chars of a-z, 0-9, '_' or '-', start with a letter or digit, and not contain '__'"
        ))
    }
}

/// Only `https://<host>` or `http://<loopback>` (localhost, 127.0.0.0/8, ::1). No credentials in
/// the authority.
pub fn validate_url(url: &str) -> Result<(), String> {
    let (scheme_https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err("an MCP url must be https:// or http:// to a loopback host".into());
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err("the MCP url has no host".into());
    }
    if authority.contains('@') {
        return Err("credentials in the MCP url are not allowed".into());
    }
    if scheme_https {
        return Ok(());
    }
    let host = if let Some(h) = authority.strip_prefix('[') {
        h.split(']').next().unwrap_or("")
    } else {
        authority
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(authority)
    };
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    if loopback {
        Ok(())
    } else {
        Err("plain http is only allowed to a loopback host".into())
    }
}

fn validate_env_key(k: &str) -> Result<(), String> {
    if k.is_empty() || k.contains('=') || k.contains('\0') {
        Err(format!("invalid env name {k:?}"))
    } else {
        Ok(())
    }
}

impl McpConfig {
    pub fn parse_toml(s: &str) -> Result<Self, String> {
        let raw: RawFile = toml::from_str(s).map_err(|e| format!("MCP config: {e}"))?;
        Self::from_raw(raw)
    }

    pub fn parse_json(s: &str) -> Result<Self, String> {
        let raw: RawFile = serde_json::from_str(s).map_err(|e| format!("MCP config: {e}"))?;
        Self::from_raw(raw)
    }

    /// Read and validate the file (`.json` → JSON, anything else → TOML).
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading MCP config {}: {e}", path.display()))?;
        let is_json = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("json"));
        if is_json {
            Self::parse_json(&text)
        } else {
            Self::parse_toml(&text)
        }
    }

    fn from_raw(raw: RawFile) -> Result<Self, String> {
        if raw.servers.len() > MAX_SERVERS {
            return Err(format!("at most {MAX_SERVERS} MCP servers"));
        }
        let mut servers: Vec<ServerConfig> = Vec::with_capacity(raw.servers.len());
        for r in raw.servers {
            validate_server_name(&r.name)?;
            if servers.iter().any(|s| s.name == r.name) {
                return Err(format!("duplicate MCP server name {:?}", r.name));
            }
            let transport = match r.transport.as_str() {
                "stdio" => {
                    if r.url.is_some() {
                        return Err(format!("server {:?}: 'url' is for http servers", r.name));
                    }
                    let command = r
                        .command
                        .ok_or_else(|| format!("server {:?}: 'command' is required", r.name))?;
                    let command = PathBuf::from(command);
                    if !command.is_absolute() {
                        return Err(format!(
                            "server {:?}: 'command' must be an absolute path",
                            r.name
                        ));
                    }
                    if r.args.len() > MAX_ARGS || r.env.len() > MAX_ENV {
                        return Err(format!("server {:?}: too many args or env entries", r.name));
                    }
                    if r.args.iter().any(|a| a.contains('\0')) {
                        return Err(format!("server {:?}: NUL in args", r.name));
                    }
                    for (k, v) in &r.env {
                        validate_env_key(k)?;
                        // The user-entry env rules apply to every entry the file holds, so the
                        // file cannot bring in what the Settings form refuses.
                        if !crate::user::valid_env_key(k) {
                            return Err(format!(
                                "server {:?}: env name {k:?} must use letters, digits and '_'",
                                r.name
                            ));
                        }
                        if crate::user::is_loader_env(k) {
                            return Err(format!(
                                "server {:?}: env {k} changes which code the server loads",
                                r.name
                            ));
                        }
                        if v.contains('\0') {
                            return Err(format!("server {:?}: NUL in env value", r.name));
                        }
                        if crate::user::is_env_reference(v) {
                            return Err(format!(
                                "server {:?}: env {k} refers to another variable; values are literal",
                                r.name
                            ));
                        }
                    }
                    let cwd = match r.cwd {
                        Some(c) => {
                            let p = PathBuf::from(c);
                            if !p.is_absolute() {
                                return Err(format!(
                                    "server {:?}: 'cwd' must be an absolute path",
                                    r.name
                                ));
                            }
                            Some(p)
                        }
                        None => None,
                    };
                    TransportConfig::Stdio {
                        command,
                        args: r.args,
                        env: r.env,
                        cwd,
                    }
                }
                "http" => {
                    if r.command.is_some()
                        || !r.args.is_empty()
                        || !r.env.is_empty()
                        || r.cwd.is_some()
                    {
                        return Err(format!(
                            "server {:?}: command/args/env/cwd are for stdio servers",
                            r.name
                        ));
                    }
                    let url = r
                        .url
                        .ok_or_else(|| format!("server {:?}: 'url' is required", r.name))?;
                    validate_url(&url).map_err(|e| format!("server {:?}: {e}", r.name))?;
                    TransportConfig::Http { url }
                }
                other => {
                    return Err(format!(
                        "server {:?}: unknown transport {other:?} (stdio | http)",
                        r.name
                    ))
                }
            };
            let mut cfg = ServerConfig::new(&r.name, transport);
            if let Some(ms) = r.timeout_ms {
                cfg.timeout = Duration::from_millis(ms.clamp(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS));
            }
            if let Some(ms) = r.init_timeout_ms {
                cfg.init_timeout = Duration::from_millis(ms.clamp(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS));
            }
            if let Some(b) = r.max_response_bytes {
                cfg.max_response_bytes = b.clamp(MIN_RESPONSE_BYTES, MAX_RESPONSE_BYTES);
            }
            if let Some(c) = r.max_output_chars {
                cfg.max_output_chars = c.clamp(256, 200_000);
            }
            cfg.allow_write_tools = r.allow_write_tools;
            servers.push(cfg);
        }
        Ok(McpConfig { servers })
    }
}

/// The environment a stdio server is started with: the allowlisted subset of `parent` plus the
/// explicit per-server entries (which win).
pub fn child_env(
    explicit: &BTreeMap<String, String>,
    parent: impl IntoIterator<Item = (String, String)>,
) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = parent
        .into_iter()
        .filter(|(k, _)| BASE_ENV_ALLOWLIST.contains(&k.as_str()))
        .collect();
    for (k, v) in explicit {
        out.insert(k.clone(), v.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_and_json_parse_to_the_same_config() {
        let t = r#"
[[servers]]
name = "mem"
transport = "stdio"
command = "/opt/mem-mcp"
args = ["--x"]
env = { A = "1" }
timeout_ms = 5000
allow_write_tools = true

[[servers]]
name = "scan"
transport = "http"
url = "https://scan.example/api/mcp"
"#;
        let j = r#"{"servers": [
 {"name": "mem", "transport": "stdio", "command": "/opt/mem-mcp", "args": ["--x"], "env": {"A": "1"}, "timeout_ms": 5000, "allow_write_tools": true},
 {"name": "scan", "transport": "http", "url": "https://scan.example/api/mcp"}
]}"#;
        let a = McpConfig::parse_toml(t).expect("toml");
        let b = McpConfig::parse_json(j).expect("json");
        assert_eq!(a, b);
        assert_eq!(a.servers.len(), 2);
        assert_eq!(a.servers[0].timeout, Duration::from_millis(5000));
        assert!(a.servers[0].allow_write_tools);
        assert!(!a.servers[1].allow_write_tools);
        assert_eq!(a.servers[1].timeout, DEFAULT_TIMEOUT);
    }

    #[test]
    fn invalid_configs_are_refused() {
        let cases = [
            // relative command (PATH lookup would be a hijack vector)
            "[[servers]]\nname='a'\ntransport='stdio'\ncommand='mem-mcp'",
            // bad names
            "[[servers]]\nname='A'\ntransport='http'\nurl='https://x'",
            "[[servers]]\nname='a__b'\ntransport='http'\nurl='https://x'",
            "[[servers]]\nname=''\ntransport='http'\nurl='https://x'",
            // non-loopback plain http, credentials, unknown scheme
            "[[servers]]\nname='a'\ntransport='http'\nurl='http://example.com/mcp'",
            "[[servers]]\nname='a'\ntransport='http'\nurl='https://u:p@example.com/mcp'",
            "[[servers]]\nname='a'\ntransport='http'\nurl='ftp://example.com'",
            // fields of the other transport
            "[[servers]]\nname='a'\ntransport='http'\nurl='https://x'\ncommand='/bin/x'",
            "[[servers]]\nname='a'\ntransport='stdio'\ncommand='/bin/x'\nurl='https://x'",
            // unknown transport, unknown field (typo), duplicate names
            "[[servers]]\nname='a'\ntransport='sse'\nurl='https://x'",
            "[[servers]]\nname='a'\ntransport='http'\nurl='https://x'\nallow_writes=true",
            "[[servers]]\nname='a'\ntransport='http'\nurl='https://x'\n[[servers]]\nname='a'\ntransport='http'\nurl='https://y'",
            // bad env key
            "[[servers]]\nname='a'\ntransport='stdio'\ncommand='/bin/x'\nenv={'A=B'='1'}",
        ];
        for c in cases {
            assert!(McpConfig::parse_toml(c).is_err(), "accepted: {c}");
        }
    }

    /// The allowlist file is checked with the same env rules as a user entry when it is loaded,
    /// so whoever can write the file still cannot make a server load other code or inherit a
    /// secret by reference.
    #[test]
    fn the_allowlist_refuses_loader_env_and_env_references_at_load() {
        for env in [
            "{\"LD_PRELOAD\": \"/tmp/x.so\"}",
            "{\"DYLD_INSERT_LIBRARIES\": \"/tmp/x.dylib\"}",
            "{\"ld_library_path\": \"/tmp\"}",
            "{\"NODE_OPTIONS\": \"--require /tmp/x.js\"}",
            "{\"PYTHONPATH\": \"/tmp\"}",
            "{\"TOKEN\": \"${GITHUB_TOKEN}\"}",
            "{\"TOKEN\": \"$OPENAI_API_KEY\"}",
            "{\"TOKEN\": \"%APPDATA%\"}",
            "{\"1BAD\": \"x\"}",
        ] {
            let json = format!(
                "{{\"servers\": [{{\"name\": \"a\", \"transport\": \"stdio\", \"command\": \"/bin/x\", \"env\": {env}}}]}}"
            );
            assert!(McpConfig::parse_json(&json).is_err(), "accepted: {env}");
        }
        let ok = r#"{"servers": [{"name": "a", "transport": "stdio", "command": "/bin/x", "env": {"MEM_TENANT": "personal", "PRICE": "pa$$word"}}]}"#;
        assert!(McpConfig::parse_json(ok).is_ok());
    }

    #[test]
    fn loopback_http_is_allowed() {
        for u in [
            "http://127.0.0.1:8080/mcp",
            "http://localhost:3000/mcp",
            "http://[::1]:9/mcp",
            "https://scan.citrate.ai/api/mcp",
        ] {
            assert!(validate_url(u).is_ok(), "{u}");
        }
        assert!(validate_url("http://10.0.0.1/mcp").is_err());
        assert!(validate_url("http://127.0.0.1.example.com/mcp").is_err());
    }

    #[test]
    fn limits_are_clamped() {
        let c = McpConfig::parse_toml(
            "[[servers]]\nname='a'\ntransport='http'\nurl='https://x'\ntimeout_ms=1\nmax_response_bytes=1",
        )
        .expect("parse");
        assert_eq!(c.servers[0].timeout, Duration::from_millis(MIN_TIMEOUT_MS));
        assert_eq!(c.servers[0].max_response_bytes, MIN_RESPONSE_BYTES);
    }

    #[test]
    fn child_env_keeps_only_the_allowlist_and_explicit_entries() {
        let parent = vec![
            ("PATH".to_string(), "/bin".to_string()),
            ("AWS_SECRET_ACCESS_KEY".to_string(), "s".to_string()),
            ("HF_TOKEN".to_string(), "t".to_string()),
            ("HOME".to_string(), "/h".to_string()),
        ];
        let mut explicit = BTreeMap::new();
        explicit.insert("MEM_TENANT".to_string(), "p".to_string());
        explicit.insert("HOME".to_string(), "/override".to_string());
        let env = child_env(&explicit, parent);
        assert_eq!(env.get("PATH").map(String::as_str), Some("/bin"));
        assert_eq!(env.get("HOME").map(String::as_str), Some("/override"));
        assert_eq!(env.get("MEM_TENANT").map(String::as_str), Some("p"));
        assert!(!env.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert!(!env.contains_key("HF_TOKEN"));
    }

    #[test]
    fn debug_never_prints_env_values_or_urls() {
        let c = McpConfig::parse_toml(
            "[[servers]]\nname='a'\ntransport='stdio'\ncommand='/bin/x'\nenv={TOKEN='sekrit'}\n[[servers]]\nname='b'\ntransport='http'\nurl='https://x/mcp?key=sekrit'",
        )
        .expect("parse");
        let d = format!("{c:?}");
        assert!(!d.contains("sekrit"), "{d}");
    }
}
