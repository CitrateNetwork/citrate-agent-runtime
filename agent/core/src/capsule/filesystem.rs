//! Typed `FilesystemEntry` parser — RFC-CIT-AGENT-0001 §4.3 field
//! `[capability].filesystem`.
//!
//! Format: `"(read|write|both):<absolute-path>"`. The manifest schema
//! holds these as `Vec<String>` for canonical-CBOR stability of the
//! TOML; this module is the typed view the wasmtime linker
//! (CIT-AGENT-3c) consumes.
//!
//! Validation rules:
//!   - Access prefix MUST be one of `read`, `write`, `both`
//!   - Path MUST be absolute (`/...`)
//!   - Path is stored as `PathBuf` for the linker's wasi-filesystem
//!     allow-list construction

use crate::error::AgentError;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemAccess {
    Read,
    Write,
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemEntry {
    pub access: FilesystemAccess,
    pub path: PathBuf,
}

impl FilesystemEntry {
    /// Parse a manifest filesystem entry. Returns
    /// `AgentError::Capsule(msg)` on any validation failure.
    pub fn parse(s: &str) -> Result<Self, AgentError> {
        let Some(colon_pos) = s.find(':') else {
            return Err(AgentError::Capsule(format!(
                "[capability].filesystem entry '{s}' must be of form '(read|write|both):<path>'"
            )));
        };
        let access_str = &s[..colon_pos];
        let path_str = &s[colon_pos + 1..];
        let access = match access_str {
            "read" => FilesystemAccess::Read,
            "write" => FilesystemAccess::Write,
            "both" => FilesystemAccess::Both,
            other => {
                return Err(AgentError::Capsule(format!(
                    "[capability].filesystem entry has unknown access prefix '{other}'; \
                     must be one of 'read', 'write', 'both'"
                )))
            }
        };
        if !path_str.starts_with('/') {
            return Err(AgentError::Capsule(format!(
                "[capability].filesystem path '{path_str}' must be absolute (start with '/')"
            )));
        }
        Ok(FilesystemEntry {
            access,
            path: PathBuf::from(path_str),
        })
    }
}

/// Parse a slice of manifest filesystem strings into typed entries.
/// Fails on the first invalid entry.
pub fn parse_all(entries: &[String]) -> Result<Vec<FilesystemEntry>, AgentError> {
    entries.iter().map(|s| FilesystemEntry::parse(s)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_read_write_both() {
        let r = FilesystemEntry::parse("read:/data/students").expect("read parses");
        assert_eq!(r.access, FilesystemAccess::Read);
        assert_eq!(r.path, PathBuf::from("/data/students"));
        let w = FilesystemEntry::parse("write:/var/log/x").expect("write parses");
        assert_eq!(w.access, FilesystemAccess::Write);
        let b = FilesystemEntry::parse("both:/scratch").expect("both parses");
        assert_eq!(b.access, FilesystemAccess::Both);
    }

    #[test]
    fn reject_unknown_access_prefix() {
        let err = FilesystemEntry::parse("exec:/bin/sh").expect_err("exec not allowed");
        assert!(err.to_string().contains("exec"));
    }

    #[test]
    fn reject_relative_path() {
        let err = FilesystemEntry::parse("read:./relative").expect_err("relative path rejected");
        assert!(err.to_string().contains("absolute"));
    }

    #[test]
    fn reject_missing_colon() {
        let err = FilesystemEntry::parse("readonly").expect_err("no colon rejected");
        assert!(err.to_string().contains("read|write|both"));
    }

    #[test]
    fn parse_all_collects_errors_lazily() {
        let entries = vec!["read:/a".to_string(), "write:/b".to_string()];
        let parsed = parse_all(&entries).expect("both parse");
        assert_eq!(parsed.len(), 2);

        let mixed = vec!["read:/a".to_string(), "bad:/b".to_string()];
        parse_all(&mixed).expect_err("second entry rejected");
    }
}
