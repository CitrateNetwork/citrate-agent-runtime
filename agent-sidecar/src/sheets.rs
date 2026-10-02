//! HUP-S10.2 — the grant-checked sheet tools: `sheet_read` and `sheet_write` (`.csv`, `.xlsx`).
//!
//! Offered only to a session opened with the member's grant document, next to the file tools
//! (`grants.rs`), and held to the same rules:
//!
//! * every path goes through the session's folder grants at the moment of use (the deny list
//!   wins, read and write are separate, an expired or revoked grant allows nothing);
//! * a read that only full access covers comes back untrusted and taints the session;
//! * a write needs a live write folder grant, never follows a symlink at the leaf, refuses a file
//!   with other hard links, and never creates folders;
//! * the format work (bounded parsing, no formulas written, CSV formula text neutralised) is
//!   `citrate-agent-office`.
//!
//! A write replaces the whole file. It is built in memory and checked against the limits first,
//! so a refused write leaves the file as it was.
//!
//! Keyless: nothing here holds a key or signs (Rule 3).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use citrate_agent_grants::{GrantKind, Op};
use citrate_agent_loop::{
    Effect, HostKind, ToolAnnotations, ToolCall, ToolHost, ToolOutcome, ToolSpec, Trust,
};
use citrate_agent_office::{format_for, read_sheet, write_sheet, Cell, Limits, SheetFormat};

use crate::grants::{hard_linked, open_nofollow, SessionGrants};

pub const SHEET_READ_TOOL: &str = "sheet_read";
pub const SHEET_WRITE_TOOL: &str = "sheet_write";
/// The tool names this module owns (reserved in sessions opened with grants).
pub const SHEET_TOOL_NAMES: [&str; 2] = [SHEET_READ_TOOL, SHEET_WRITE_TOOL];

/// The limits both tools use. Conservative defaults, pending owner sign-off: 10 MiB files,
/// 64 MiB inflated workbook, 5,000 rows, 200 columns, 8,192 characters a cell.
pub const SHEET_LIMITS: Limits = Limits {
    max_bytes: 10 * 1024 * 1024,
    max_inflated_bytes: 64 * 1024 * 1024,
    max_rows: 5_000,
    max_cols: 200,
    max_cell_chars: 8_192,
};

/// Whether `name` is one of the sheet tools.
pub fn handles(name: &str) -> bool {
    SHEET_TOOL_NAMES.contains(&name)
}

fn format_name(f: SheetFormat) -> &'static str {
    match f {
        SheetFormat::Csv => "csv",
        SheetFormat::Xlsx => "xlsx",
    }
}

/// The sheet tool specs offered to the model.
pub fn sheet_tool_specs() -> Vec<ToolSpec> {
    let path = serde_json::json!({
        "type": "string",
        "description": "Absolute path of a .csv or .xlsx file inside a folder the member granted."
    });
    let sheet = serde_json::json!({
        "type": "string",
        "description": "For .xlsx: the sheet name (default: the first sheet to read, Sheet1 to write)."
    });
    let ann = |effect: Effect| ToolAnnotations {
        read_only: effect == Effect::None,
        destructive: effect == Effect::Write,
        idempotent: true,
        open_world: false,
        effect: Some(effect),
        // Same trust split as file_read: a folder-grant read is the member's own file. A read only
        // full access covers returns ToolOutcome::Untrusted (pending owner sign-off, as there).
        trust: Some(Trust::Trusted),
    };
    vec![
        ToolSpec {
            name: SHEET_READ_TOOL.into(),
            description: format!(
                "Read a spreadsheet (.csv or .xlsx) from a folder the member granted read access to. Returns rows of cells (text, number, true/false or null), at most {} rows and {} columns; `truncated` says when more was cut.",
                SHEET_LIMITS.max_rows, SHEET_LIMITS.max_cols
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": { "path": path, "sheet": sheet },
                "required": ["path"],
            }),
            host: HostKind::Sidecar,
            annotations: ann(Effect::None),
        },
        ToolSpec {
            name: SHEET_WRITE_TOOL.into(),
            description: "Create or replace a spreadsheet (.csv or .xlsx) in a folder the member granted write access to. `rows` is an array of rows, each an array of cells (text, number, true/false or null). Formulas are never written. The parent folder must already exist.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": path,
                    "sheet": sheet,
                    "rows": {
                        "type": "array",
                        "items": {"type": "array", "items": {"type": ["string", "number", "boolean", "null"]}}
                    }
                },
                "required": ["path", "rows"],
            }),
            host: HostKind::Sidecar,
            annotations: ann(Effect::Write),
        },
    ]
}

/// Runs the sheet tools for one session.
pub struct SheetToolHost {
    grants: Arc<SessionGrants>,
}

type Args = serde_json::Map<String, serde_json::Value>;

impl SheetToolHost {
    pub fn new(grants: Arc<SessionGrants>) -> Self {
        SheetToolHost { grants }
    }

    fn args(call: &ToolCall) -> Result<Args, String> {
        let raw = if call.arguments.trim().is_empty() {
            "{}"
        } else {
            call.arguments.as_str()
        };
        match serde_json::from_str::<serde_json::Value>(raw) {
            Ok(serde_json::Value::Object(m)) => Ok(m),
            _ => Err("the arguments must be a JSON object".into()),
        }
    }

    fn path_arg(args: &Args) -> Result<PathBuf, String> {
        match args.get("path") {
            Some(serde_json::Value::String(p)) if !p.trim().is_empty() => {
                let p = PathBuf::from(p);
                if p.is_absolute() {
                    Ok(p)
                } else {
                    Err("path must be absolute".into())
                }
            }
            _ => Err("path is required".into()),
        }
    }

    fn sheet_arg(args: &Args) -> Result<Option<String>, String> {
        match args.get("sheet") {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
            _ => Err("sheet must be a string".into()),
        }
    }

    fn rows_arg(args: &Args) -> Result<Vec<Vec<Cell>>, String> {
        let rows = args.get("rows").ok_or("rows is required")?;
        if !rows.is_array() {
            return Err("rows must be an array of rows".into());
        }
        serde_json::from_value::<Vec<Vec<Cell>>>(rows.clone()).map_err(|_| {
            "rows must be an array of arrays of cells (text, number, true/false or null)".into()
        })
    }

    fn read(&self, path: &Path, sheet: Option<&str>) -> ToolOutcome {
        let format = match format_for(path) {
            Ok(f) => f,
            Err(e) => return ToolOutcome::Error(e.to_string()),
        };
        if let Some(why) = crate::grants::leaf_link(path) {
            return ToolOutcome::Denied(why);
        }
        let (file, kind) = match self.grants.check(path, Op::Read) {
            Ok(x) => x,
            Err(e) => return ToolOutcome::Denied(e),
        };
        let mut f = match open_nofollow(&file, false) {
            Ok(f) => f,
            Err(e) => return ToolOutcome::Error(format!("cannot open {}: {e}", file.display())),
        };
        match f.metadata() {
            Ok(m) if !m.is_file() => {
                return ToolOutcome::Error(format!("{} is not a regular file", file.display()))
            }
            Ok(m) if hard_linked(&m) => {
                return ToolOutcome::Denied(format!(
                    "{} has other hard links, so it was not read",
                    file.display()
                ))
            }
            Ok(m) if m.len() > SHEET_LIMITS.max_bytes => {
                return ToolOutcome::Error(format!(
                    "{} is {} bytes; sheet_read reads at most {}",
                    file.display(),
                    m.len(),
                    SHEET_LIMITS.max_bytes
                ))
            }
            Ok(_) => {}
            Err(e) => return ToolOutcome::Error(format!("cannot inspect {}: {e}", file.display())),
        }
        let mut buf = Vec::new();
        if let Err(e) = (&mut f)
            .take(SHEET_LIMITS.max_bytes + 1)
            .read_to_end(&mut buf)
        {
            return ToolOutcome::Error(format!("cannot read {}: {e}", file.display()));
        }
        let data = match read_sheet(format, &buf, sheet, &SHEET_LIMITS) {
            Ok(d) => d,
            Err(e) => return ToolOutcome::Error(format!("{}: {e}", file.display())),
        };
        let body = serde_json::json!({
            "path": file,
            "format": format_name(format),
            "sheetNames": data.sheet_names,
            "sheet": data.sheet,
            "rows": data.rows,
            "truncated": data.truncated,
        })
        .to_string();
        match kind {
            GrantKind::Folder => ToolOutcome::Ok(body),
            GrantKind::FullAccess => ToolOutcome::Untrusted(body),
        }
    }

    fn write(&self, path: &Path, sheet: Option<&str>, rows: &[Vec<Cell>]) -> ToolOutcome {
        let format = match format_for(path) {
            Ok(f) => f,
            Err(e) => return ToolOutcome::Error(e.to_string()),
        };
        // Build and check the whole file before touching the disk.
        let bytes = match write_sheet(format, sheet, rows, &SHEET_LIMITS) {
            Ok(b) => b,
            Err(e) => return ToolOutcome::Error(e.to_string()),
        };
        let (file, _) = match self.grants.check(path, Op::Write) {
            Ok(x) => x,
            Err(e) => return ToolOutcome::Denied(e),
        };
        match std::fs::symlink_metadata(&file) {
            Ok(m) if m.file_type().is_symlink() => {
                return ToolOutcome::Denied(format!("{} is a symbolic link", file.display()))
            }
            Ok(m) if !m.is_file() => {
                return ToolOutcome::Error(format!("{} is not a regular file", file.display()))
            }
            Ok(m) if hard_linked(&m) => {
                return ToolOutcome::Denied(format!(
                    "{} has other hard links, so writing it could change a file outside the grant",
                    file.display()
                ))
            }
            _ => {}
        }
        let mut f = match open_nofollow(&file, true) {
            Ok(f) => f,
            Err(e) => return ToolOutcome::Error(format!("cannot open {}: {e}", file.display())),
        };
        if let Err(e) = f.write_all(&bytes).and_then(|_| f.flush()) {
            return ToolOutcome::Error(format!("cannot write {}: {e}", file.display()));
        }
        ToolOutcome::Ok(
            serde_json::json!({
                "path": file,
                "format": format_name(format),
                "rows": rows.len(),
                "bytes": bytes.len(),
                "written": true,
            })
            .to_string(),
        )
    }
}

impl ToolHost for SheetToolHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        let parsed = Self::args(call).and_then(|a| {
            let path = Self::path_arg(&a)?;
            let sheet = Self::sheet_arg(&a)?;
            Ok((a, path, sheet))
        });
        let (args, path, sheet) = match parsed {
            Ok(x) => x,
            Err(e) => return ToolOutcome::Error(e),
        };
        match call.name.as_str() {
            SHEET_READ_TOOL => self.read(&path, sheet.as_deref()),
            SHEET_WRITE_TOOL => match Self::rows_arg(&args) {
                Ok(rows) => self.write(&path, sheet.as_deref(), &rows),
                Err(e) => ToolOutcome::Error(e),
            },
            other => ToolOutcome::Error(format!("'{other}' is not a sheet tool")),
        }
    }
}
