//! User-added MCP servers (HUP-S4.4): the stricter validation applied to a server entry a person
//! types into citrate-core's Settings, before it is probed or written to the allowlist file.
//!
//! An entry has the same shape as one `[[servers]]` item of the allowlist ([`crate::config`]), so
//! what passes here is exactly what the sidecar will load. On top of the allowlist's own rules:
//!
//! - every problem is reported against its field (`name`, `transport`, `command`, `args`, `cwd`,
//!   `url`, `env.<KEY>`, or `entry` for the whole object), so the form can show it in place;
//! - env keys are plain identifiers (`[A-Za-z_][A-Za-z0-9_]*`, at most 128 chars), and keys that
//!   change which code a process loads (`LD_*`, `DYLD_*`, `NODE_OPTIONS`, ...) are refused, so the
//!   command shown on the review screen is the code that runs;
//! - env values are explicit: a value that refers to another variable (`$X`, `${X}`, `%X%`) is
//!   refused, because nothing is expanded and nothing is inherited from the sidecar's environment
//!   beyond [`crate::config::BASE_ENV_ALLOWLIST`] (process basics, no credentials);
//! - names used by built-in servers are reserved ([`RESERVED_SERVER_NAMES`]).
//!
//! Error messages never contain an env value.

use crate::config::{validate_server_name, validate_url, McpConfig, ServerConfig};
use serde::Serialize;
use serde_json::{Map, Value};

/// Names kept for the servers Hermes ships with (planset 02 §5), so a user entry can never take a
/// built-in server's tool namespace.
pub const RESERVED_SERVER_NAMES: &[&str] = &[
    "citrate",
    "citrate-node",
    "node",
    "mem",
    "memory",
    "citratescan",
    "scan",
    "browser",
    "search",
    "toolchain",
    "fs",
    "shell",
    "office",
    "media",
    "hermes",
];

/// Longest env value accepted.
pub const MAX_ENV_VALUE: usize = 8192;
/// Longest single argument accepted.
pub const MAX_ARG: usize = 4096;
/// Longest URL accepted.
pub const MAX_URL: usize = 2048;
const MAX_ENV_KEY: usize = 128;
const MAX_ARGS: usize = 64;
const MAX_ENV: usize = 64;

/// Env names that change which code a process loads or runs at start-up.
const LOADER_ENV_EXACT: &[&str] = &[
    "NODE_OPTIONS",
    "NODE_PATH",
    "BASH_ENV",
    "ENV",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PYTHONHOME",
    "PERL5OPT",
    "PERL5LIB",
    "RUBYOPT",
    "RUBYLIB",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
];
const LOADER_ENV_PREFIXES: &[&str] = &["LD_", "DYLD_"];

/// Fields an entry may carry (the allowlist's `[[servers]]` keys).
const KNOWN_FIELDS: &[&str] = &[
    "name",
    "transport",
    "command",
    "args",
    "env",
    "cwd",
    "url",
    "timeout_ms",
    "init_timeout_ms",
    "max_response_bytes",
    "max_output_chars",
    "allow_write_tools",
];

/// One problem with one field of an entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldError {
    pub field: String,
    pub message: String,
}

fn err(field: impl Into<String>, message: impl Into<String>) -> FieldError {
    FieldError {
        field: field.into(),
        message: message.into(),
    }
}

/// Whether `k` changes which code a process loads.
pub fn is_loader_env(k: &str) -> bool {
    let up = k.to_ascii_uppercase();
    LOADER_ENV_EXACT.contains(&up.as_str()) || LOADER_ENV_PREFIXES.iter().any(|p| up.starts_with(p))
}

fn valid_env_key(k: &str) -> bool {
    let mut chars = k.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    first_ok && k.len() <= MAX_ENV_KEY && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether `v` looks like a reference to another variable rather than a value.
pub fn is_env_reference(v: &str) -> bool {
    if v.contains("${") {
        return true;
    }
    let t = v.trim();
    if let Some(rest) = t.strip_prefix('$') {
        if rest.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
            return true;
        }
    }
    if t.len() >= 3 && t.starts_with('%') && t.ends_with('%') {
        let inner = &t[1..t.len() - 1];
        if valid_env_key(inner) {
            return true;
        }
    }
    false
}

fn str_field<'a>(
    o: &'a Map<String, Value>,
    k: &str,
    errs: &mut Vec<FieldError>,
) -> Option<&'a str> {
    match o.get(k) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => {
            errs.push(err(k, format!("'{k}' must be text")));
            None
        }
    }
}

fn check_env(o: &Map<String, Value>, errs: &mut Vec<FieldError>) {
    let Some(env) = o.get("env") else { return };
    let Some(env) = env.as_object() else {
        errs.push(err("env", "'env' must be a table of NAME = value"));
        return;
    };
    if env.len() > MAX_ENV {
        errs.push(err("env", format!("at most {MAX_ENV} env entries")));
    }
    for (k, v) in env {
        let field = format!("env.{k}");
        if !valid_env_key(k) {
            errs.push(err(
                field,
                "env names use letters, digits and '_', start with a letter or '_', at most 128 characters",
            ));
            continue;
        }
        if is_loader_env(k) {
            errs.push(err(
                field,
                format!("{k} changes which code the server loads, so it is not allowed for added servers"),
            ));
            continue;
        }
        let Some(v) = v.as_str() else {
            errs.push(err(field, "env values must be text"));
            continue;
        };
        if v.contains('\0') {
            errs.push(err(field, "env values cannot contain a NUL character"));
        } else if v.chars().count() > MAX_ENV_VALUE {
            errs.push(err(
                field,
                format!("env values are at most {MAX_ENV_VALUE} characters"),
            ));
        } else if is_env_reference(v) {
            errs.push(err(
                field,
                "env values are passed literally; references to other variables are not expanded and nothing secret is inherited. Enter the value itself",
            ));
        }
    }
}

fn check_args(o: &Map<String, Value>, errs: &mut Vec<FieldError>) {
    let Some(args) = o.get("args") else { return };
    let Some(args) = args.as_array() else {
        errs.push(err("args", "'args' must be a list of text"));
        return;
    };
    if args.len() > MAX_ARGS {
        errs.push(err("args", format!("at most {MAX_ARGS} arguments")));
    }
    for a in args {
        match a.as_str() {
            Some(s) if s.contains('\0') => {
                errs.push(err("args", "arguments cannot contain a NUL character"));
                return;
            }
            Some(s) if s.chars().count() > MAX_ARG => {
                errs.push(err(
                    "args",
                    format!("each argument is at most {MAX_ARG} characters"),
                ));
                return;
            }
            Some(_) => {}
            None => {
                errs.push(err("args", "'args' must be a list of text"));
                return;
            }
        }
    }
}

fn has(o: &Map<String, Value>, k: &str) -> bool {
    match o.get(k) {
        None | Some(Value::Null) => false,
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(m)) => !m.is_empty(),
        Some(_) => true,
    }
}

/// Validate one user entry (JSON, the allowlist's `[[servers]]` shape). `Ok` is the exact
/// [`ServerConfig`] the sidecar would load; `Err` lists every problem found, by field.
pub fn validate_user_entry(entry: &Value) -> Result<ServerConfig, Vec<FieldError>> {
    let Some(o) = entry.as_object() else {
        return Err(vec![err("entry", "a server entry must be an object")]);
    };
    let mut errs = Vec::new();
    for k in o.keys() {
        if !KNOWN_FIELDS.contains(&k.as_str()) {
            errs.push(err("entry", format!("unknown field {k:?}")));
        }
    }
    match str_field(o, "name", &mut errs) {
        None if !errs.iter().any(|e| e.field == "name") => {
            errs.push(err("name", "a name is required"))
        }
        None => {}
        Some(n) => {
            if let Err(m) = validate_server_name(n) {
                errs.push(err("name", m));
            } else if RESERVED_SERVER_NAMES.contains(&n) {
                errs.push(err(
                    "name",
                    format!("{n:?} is reserved for a built-in server; choose another name"),
                ));
            }
        }
    }
    let transport = str_field(o, "transport", &mut errs);
    match transport {
        Some("stdio") => {
            for k in ["url"] {
                if has(o, k) {
                    errs.push(err(k, "'url' is for http servers"));
                }
            }
            match str_field(o, "command", &mut errs) {
                None => {
                    if !errs.iter().any(|e| e.field == "command") {
                        errs.push(err("command", "a command (absolute path) is required"))
                    }
                }
                Some(c) => {
                    if !std::path::Path::new(c).is_absolute() {
                        errs.push(err(
                            "command",
                            "the command must be an absolute path (no PATH lookup)",
                        ));
                    } else if c.contains('\0') {
                        errs.push(err("command", "the command cannot contain a NUL character"));
                    }
                }
            }
            if let Some(c) = str_field(o, "cwd", &mut errs) {
                if !std::path::Path::new(c).is_absolute() {
                    errs.push(err("cwd", "the working folder must be an absolute path"));
                }
            }
            check_args(o, &mut errs);
            check_env(o, &mut errs);
        }
        Some("http") => {
            for k in ["command", "args", "env", "cwd"] {
                if has(o, k) {
                    errs.push(err(k, format!("'{k}' is for stdio servers")));
                }
            }
            match str_field(o, "url", &mut errs) {
                None => {
                    if !errs.iter().any(|e| e.field == "url") {
                        errs.push(err("url", "a URL is required"))
                    }
                }
                Some(u) if u.len() > MAX_URL => errs.push(err(
                    "url",
                    format!("the URL is longer than {MAX_URL} characters"),
                )),
                Some(u) => {
                    if let Err(m) = validate_url(u) {
                        errs.push(err("url", m));
                    }
                }
            }
        }
        Some(other) => errs.push(err(
            "transport",
            format!(
                "unknown transport {:?} (stdio or http)",
                other.chars().take(16).collect::<String>()
            ),
        )),
        None => {
            if !errs.iter().any(|e| e.field == "transport") {
                errs.push(err("transport", "choose stdio or http"))
            }
        }
    }
    if !errs.is_empty() {
        return Err(errs);
    }
    // The allowlist's own rules (types, limits, clamps) decide the final shape, so the result is
    // exactly what the sidecar loads.
    let file = serde_json::json!({ "servers": [entry] });
    let text = file.to_string();
    match McpConfig::parse_json(&text) {
        Ok(mut cfg) => cfg
            .servers
            .pop()
            .ok_or_else(|| vec![err("entry", "the entry was not read")]),
        Err(m) => Err(vec![err("entry", redact_values(&m, o))]),
    }
}

/// Remove any env value from a message (serde errors can quote input).
fn redact_values(msg: &str, o: &Map<String, Value>) -> String {
    let mut out = msg.to_string();
    if let Some(env) = o.get("env").and_then(Value::as_object) {
        for v in env.values().filter_map(Value::as_str) {
            if !v.is_empty() {
                out = out.replace(v, "[value]");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_are_recognised() {
        for v in ["$A", " $A", "${A}", "x${A}y", "%APPDATA%", "%_X%"] {
            assert!(is_env_reference(v), "{v}");
        }
        for v in ["", "a$", "pa$$word", "100%", "%%", "% x %", "$1", "abc"] {
            assert!(!is_env_reference(v), "{v}");
        }
    }

    #[test]
    fn loader_keys_are_recognised_case_insensitively() {
        assert!(is_loader_env("LD_PRELOAD"));
        assert!(is_loader_env("dyld_insert_libraries"));
        assert!(is_loader_env("NODE_OPTIONS"));
        assert!(!is_loader_env("NOTES_TOKEN"));
        assert!(!is_loader_env("OLD_VALUE"));
    }

    #[test]
    fn reserved_names_are_themselves_valid_names() {
        for n in RESERVED_SERVER_NAMES {
            assert!(validate_server_name(n).is_ok(), "{n}");
        }
    }

    #[test]
    fn a_base_rule_failure_is_redacted() {
        let o = serde_json::json!({"env": {"K": "hunter2"}});
        let m = redact_values("bad value hunter2 here", o.as_object().expect("obj"));
        assert!(!m.contains("hunter2"));
    }
}
