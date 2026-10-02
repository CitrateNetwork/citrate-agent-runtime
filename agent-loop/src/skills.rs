//! # HUP-S3.2 — one loader for `SKILL.md` skills, a description index, and `skill_load`
//!
//! A skill is **instructions only** (planset 02_ARCHITECTURE, "Skill" row): an agentskills.io
//! `SKILL.md` — YAML frontmatter with `name` + `description`, then a markdown body — plus optional
//! bundled files (`references/`, `assets/`, `scripts/`). For each turn Hermes ranks the skill
//! descriptions against the request and puts at most [`SKILLS_PER_TURN`] of them in context (one
//! short line each); a body loads only when the model asks for it with the `skill_load` tool.
//!
//! What this module guarantees:
//! - **Strict, bounded parsing.** The frontmatter is a small, explicit YAML subset (plain/quoted
//!   scalars, `>`/`|` block scalars, one-level maps and lists). Anchors, aliases, tags, nesting,
//!   unknown keys and duplicate keys are refused. File, field and ref sizes are capped. No YAML
//!   dependency is pulled in for this; the accepted grammar is the whole surface.
//! - **One format, many sources.** Sources are searched in precedence order (first wins); a name
//!   shadowed by an earlier source is reported, and a name that appears twice inside one source is
//!   ambiguous and refused outright.
//! - **Confined reads.** `skill_load` can read only files that were listed for that skill at load
//!   time, and only if they still resolve inside the skill's own directory.
//! - **Scripts are never executed.** Files under `scripts/` are listed and flagged so the model knows
//!   they exist; they cannot be run or loaded through this module. Anything side-effecting is a tool
//!   or a capsule, never a skill.

use crate::{
    HostKind, Message, Role, TokenCounter, ToolAnnotations, ToolCall, ToolHost, ToolOutcome,
    ToolSpec, TurnContext,
};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

/// The tool name the model calls to read a skill.
pub const SKILL_LOAD_TOOL: &str = "skill_load";
/// The whole `SKILL.md` (frontmatter + body), in bytes.
pub const MAX_SKILL_FILE_BYTES: usize = 64 * 1024;
/// agentskills.io: `name` is 1–64 chars of `[a-z0-9-]`.
pub const MAX_NAME_LEN: usize = 64;
/// agentskills.io: `description` is 1–1024 chars.
pub const MAX_DESCRIPTION_LEN: usize = 1024;
/// agentskills.io: `compatibility` is at most 500 chars.
pub const MAX_COMPATIBILITY_LEN: usize = 500;
/// Any other single frontmatter value.
pub const MAX_VALUE_LEN: usize = 1024;
/// One bundled file read through `skill_load`.
pub const MAX_REF_BYTES: usize = 128 * 1024;
/// Skills accepted from one source.
pub const MAX_SKILLS_PER_SOURCE: usize = 512;
/// Directories visited while discovering skills in one source.
pub const MAX_SCAN_DIRS: usize = 4096;
/// How deep below a source root a `SKILL.md` may sit (plugin marketplaces nest a few levels).
pub const MAX_SCAN_DEPTH: usize = 6;
/// Bundled files listed per skill.
pub const MAX_FILES_LISTED: usize = 64;
/// How deep bundled files are listed inside a skill directory.
pub const MAX_RESOURCE_DEPTH: usize = 4;
/// A skill description is cut to this many characters in the index (about 30 tokens).
pub const INDEX_DESC_CHARS: usize = 120;
/// US-3.2 AC1: the most skills surfaced in the system prompt for one turn.
pub const SKILLS_PER_TURN: usize = 5;

/// Keys from the agentskills.io specification.
const SPEC_KEYS: &[&str] = &[
    "name",
    "description",
    "license",
    "compatibility",
    "metadata",
    "allowed-tools",
];
/// Claude Code extension keys seen in real skill sources; tolerated and recorded, never acted on.
const EXTENSION_KEYS: &[&str] = &[
    "argument-hint",
    "disable-model-invocation",
    "user-invocable",
    "model",
    "type",
    "version",
];

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// Why a `SKILL.md` was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkillError {
    /// The file does not start with a `---` frontmatter fence.
    NoFrontmatter,
    /// The frontmatter has no closing `---` fence.
    Unterminated,
    /// The file is larger than [`MAX_SKILL_FILE_BYTES`].
    TooLarge {
        max: usize,
    },
    /// The file is not UTF-8 text.
    NotUtf8,
    /// The frontmatter uses YAML outside the accepted subset (1-based line within the frontmatter).
    Yaml {
        line: usize,
        msg: String,
    },
    MissingField(&'static str),
    InvalidName(String),
    TooLong {
        field: &'static str,
        max: usize,
    },
    UnknownKey(String),
    DuplicateKey(String),
    Io(String),
}

impl std::fmt::Display for SkillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkillError::NoFrontmatter => write!(f, "no YAML frontmatter (expected a leading ---)"),
            SkillError::Unterminated => write!(f, "frontmatter has no closing ---"),
            SkillError::TooLarge { max } => write!(f, "SKILL.md is larger than {max} bytes"),
            SkillError::NotUtf8 => write!(f, "SKILL.md is not UTF-8 text"),
            SkillError::Yaml { line, msg } => write!(f, "frontmatter line {line}: {msg}"),
            SkillError::MissingField(k) => write!(f, "required field '{k}' is missing or empty"),
            SkillError::InvalidName(n) => write!(
                f,
                "invalid name {n:?} (1-{MAX_NAME_LEN} chars of a-z, 0-9 and single inner hyphens)"
            ),
            SkillError::TooLong { field, max } => {
                write!(f, "field '{field}' is longer than {max} characters")
            }
            SkillError::UnknownKey(k) => write!(f, "unknown frontmatter key '{k}'"),
            SkillError::DuplicateKey(k) => write!(f, "frontmatter key '{k}' appears twice"),
            SkillError::Io(e) => write!(f, "read failed: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Frontmatter
// ---------------------------------------------------------------------------------------------

/// The validated frontmatter of one skill.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SkillFrontmatter {
    pub name: String,
    pub description: String,
    pub license: Option<String>,
    pub compatibility: Option<String>,
    pub metadata: BTreeMap<String, String>,
    /// Informational only: Hermes's own tool gates decide what runs.
    pub allowed_tools: Vec<String>,
    /// Tolerated extension keys (see `EXTENSION_KEYS`), recorded verbatim and never acted on.
    pub extensions: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Str(String),
    List(Vec<String>),
    Map(BTreeMap<String, String>),
}

fn yaml_err(line: usize, msg: impl Into<String>) -> SkillError {
    SkillError::Yaml {
        line,
        msg: msg.into(),
    }
}

fn valid_key(k: &str) -> bool {
    !k.is_empty()
        && k.len() <= 64
        && k.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Parse one inline scalar (plain, single- or double-quoted). Refuses YAML features outside the
/// accepted subset.
fn scalar(raw: &str, line: usize) -> Result<String, SkillError> {
    let s = raw.trim();
    if let Some(rest) = s.strip_prefix('"') {
        let Some(inner) = rest.strip_suffix('"') else {
            return Err(yaml_err(line, "unterminated double-quoted string"));
        };
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('/') => out.push('/'),
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some(other) => {
                        return Err(yaml_err(line, format!("unsupported escape \\{other}")))
                    }
                    None => return Err(yaml_err(line, "dangling escape")),
                },
                '"' => return Err(yaml_err(line, "unescaped quote inside a string")),
                c => out.push(c),
            }
        }
        return Ok(out);
    }
    if let Some(rest) = s.strip_prefix('\'') {
        let Some(inner) = rest.strip_suffix('\'') else {
            return Err(yaml_err(line, "unterminated single-quoted string"));
        };
        if inner.replace("''", "").contains('\'') {
            return Err(yaml_err(line, "unescaped quote inside a string"));
        }
        return Ok(inner.replace("''", "'"));
    }
    match s.chars().next() {
        Some('&') => return Err(yaml_err(line, "anchors are not supported")),
        Some('*') => return Err(yaml_err(line, "aliases are not supported")),
        Some('!') => return Err(yaml_err(line, "tags are not supported")),
        Some('{') => return Err(yaml_err(line, "flow maps are not supported")),
        Some('@') | Some('`') => return Err(yaml_err(line, "reserved indicator")),
        Some('%') => return Err(yaml_err(line, "directives are not supported")),
        _ => {}
    }
    // A plain scalar ends at a " #" comment.
    let plain = match s.find(" #") {
        Some(i) => s[..i].trim_end(),
        None => s,
    };
    Ok(plain.to_string())
}

fn flow_list(raw: &str, line: usize) -> Result<Vec<String>, SkillError> {
    let s = raw.trim();
    let inner = s
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .ok_or_else(|| yaml_err(line, "unterminated flow list"))?;
    if inner.contains('[') || inner.contains('{') {
        return Err(yaml_err(line, "nested collections are not supported"));
    }
    inner
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| scalar(p, line))
        .collect()
}

fn indent_of(l: &str) -> usize {
    l.len() - l.trim_start_matches(' ').len()
}

/// Parse the frontmatter lines into key → value, refusing anything outside the subset.
fn parse_frontmatter(lines: &[&str]) -> Result<Vec<(String, Value, usize)>, SkillError> {
    let mut out: Vec<(String, Value, usize)> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let ln = i + 1;
        let l = lines[i];
        if l.contains('\t') && l.trim_start().len() != l.len() {
            return Err(yaml_err(ln, "tab indentation is not supported"));
        }
        let t = l.trim();
        if t.is_empty() || t.starts_with('#') {
            i += 1;
            continue;
        }
        if indent_of(l) > 0 {
            return Err(yaml_err(ln, "unexpected indentation"));
        }
        if t == "---" || t == "..." {
            return Err(yaml_err(ln, "multiple documents are not supported"));
        }
        let Some((k, rest)) = t.split_once(':') else {
            return Err(yaml_err(ln, "expected `key: value`"));
        };
        let key = k.trim();
        if !valid_key(key) {
            return Err(yaml_err(ln, format!("invalid key {key:?}")));
        }
        if !rest.is_empty() && !rest.starts_with(' ') {
            return Err(yaml_err(ln, "expected a space after ':'"));
        }
        let rest = rest.trim();
        i += 1;
        // Indented continuation lines belonging to this key.
        let start = i;
        while i < lines.len() && (lines[i].trim().is_empty() || indent_of(lines[i]) > 0) {
            i += 1;
        }
        let block: Vec<&str> = lines[start..i].to_vec();
        let block_has_content = block.iter().any(|b| !b.trim().is_empty());
        let value = match rest {
            ">" | ">-" | "|" | "|-" => {
                let content: Vec<&str> = block.clone();
                let base = content
                    .iter()
                    .find(|b| !b.trim().is_empty())
                    .map(|b| indent_of(b))
                    .unwrap_or(0);
                let mut parts: Vec<String> = Vec::new();
                for (j, b) in content.iter().enumerate() {
                    if b.contains('\t') {
                        return Err(yaml_err(start + j + 1, "tabs are not supported"));
                    }
                    if b.trim().is_empty() {
                        parts.push(String::new());
                    } else if indent_of(b) < base {
                        return Err(yaml_err(start + j + 1, "block scalar indentation"));
                    } else {
                        parts.push(b[base..].trim_end().to_string());
                    }
                }
                while parts.last().is_some_and(|p| p.is_empty()) {
                    parts.pop();
                }
                let joined = if rest.starts_with('|') {
                    parts.join("\n")
                } else {
                    // Folded: single newlines become spaces; blank lines become newlines.
                    let mut s = String::new();
                    for p in &parts {
                        if p.is_empty() {
                            s.push('\n');
                        } else {
                            if !s.is_empty() && !s.ends_with('\n') {
                                s.push(' ');
                            }
                            s.push_str(p);
                        }
                    }
                    s
                };
                Value::Str(joined)
            }
            "" if block_has_content => {
                let items: Vec<(usize, &str)> = block
                    .iter()
                    .enumerate()
                    .filter(|(_, b)| !b.trim().is_empty())
                    .map(|(j, b)| (start + j + 1, *b))
                    .collect();
                let base = indent_of(items[0].1);
                if items.iter().any(|(_, b)| indent_of(b) != base) {
                    return Err(yaml_err(items[0].0, "nested collections are not supported"));
                }
                if items[0].1.trim_start().starts_with("- ") || items[0].1.trim() == "-" {
                    let mut list = Vec::new();
                    for (n, b) in &items {
                        let Some(item) = b.trim().strip_prefix('-') else {
                            return Err(yaml_err(*n, "mixed list and map"));
                        };
                        let item = item.trim();
                        if item.contains(": ") || item.ends_with(':') {
                            return Err(yaml_err(*n, "nested collections are not supported"));
                        }
                        list.push(scalar(item, *n)?);
                    }
                    Value::List(list)
                } else {
                    let mut map = BTreeMap::new();
                    for (n, b) in &items {
                        let Some((mk, mv)) = b.trim().split_once(':') else {
                            return Err(yaml_err(*n, "expected `key: value`"));
                        };
                        let mk = mk.trim();
                        if !valid_key(mk) {
                            return Err(yaml_err(*n, format!("invalid key {mk:?}")));
                        }
                        if mv.trim().is_empty() {
                            return Err(yaml_err(*n, "nested collections are not supported"));
                        }
                        let v = scalar(mv, *n)?;
                        if map.insert(mk.to_string(), v).is_some() {
                            return Err(SkillError::DuplicateKey(format!("{key}.{mk}")));
                        }
                    }
                    Value::Map(map)
                }
            }
            "" => Value::Str(String::new()),
            r if block_has_content => {
                return Err(yaml_err(
                    start + 1,
                    format!("multi-line plain values are not supported for {key:?} ({r:.12}…)"),
                ));
            }
            r if r.starts_with('[') => Value::List(flow_list(r, ln)?),
            r => Value::Str(scalar(r, ln)?),
        };
        if out.iter().any(|(k, _, _)| k == key) {
            return Err(SkillError::DuplicateKey(key.to_string()));
        }
        out.push((key.to_string(), value, ln));
    }
    Ok(out)
}

/// agentskills.io name rule: 1–64 chars of `[a-z0-9-]`, no leading/trailing or doubled hyphen.
pub fn valid_skill_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= MAX_NAME_LEN
        && n.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !n.starts_with('-')
        && !n.ends_with('-')
        && !n.contains("--")
}

fn str_field(v: Value, field: &'static str, line: usize) -> Result<String, SkillError> {
    match v {
        Value::Str(s) => Ok(s),
        _ => Err(yaml_err(line, format!("'{field}' must be a string"))),
    }
}

fn capped(s: String, field: &'static str, max: usize) -> Result<String, SkillError> {
    if s.chars().count() > max {
        Err(SkillError::TooLong { field, max })
    } else {
        Ok(s)
    }
}

/// Parse and validate a whole `SKILL.md`. Returns the frontmatter and the body (everything after
/// the closing fence).
pub fn parse_skill_md(text: &str) -> Result<(SkillFrontmatter, String), SkillError> {
    if text.len() > MAX_SKILL_FILE_BYTES {
        return Err(SkillError::TooLarge {
            max: MAX_SKILL_FILE_BYTES,
        });
    }
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let normalized;
    let text = if text.contains('\r') {
        normalized = text.replace("\r\n", "\n");
        normalized.as_str()
    } else {
        text
    };
    let Some(after_open) = text.strip_prefix("---\n") else {
        return Err(SkillError::NoFrontmatter);
    };
    // Find the closing fence: a line that is exactly `---`.
    let mut offset = 0usize;
    let mut close: Option<(usize, usize)> = None;
    for line in after_open.split_inclusive('\n') {
        if line.trim_end_matches('\n').trim_end() == "---" {
            close = Some((offset, offset + line.len()));
            break;
        }
        offset += line.len();
    }
    let Some((fm_end, body_start)) = close else {
        return Err(SkillError::Unterminated);
    };
    let fm_text = &after_open[..fm_end];
    let body = after_open[body_start..].to_string();
    let lines: Vec<&str> = fm_text.lines().collect();

    let mut fm = SkillFrontmatter::default();
    let mut have_name = false;
    let mut have_desc = false;
    for (key, value, line) in parse_frontmatter(&lines)? {
        match key.as_str() {
            "name" => {
                let n = str_field(value, "name", line)?;
                let n = n.trim().to_string();
                if n.is_empty() {
                    continue;
                }
                if !valid_skill_name(&n) {
                    return Err(SkillError::InvalidName(n));
                }
                fm.name = n;
                have_name = true;
            }
            "description" => {
                let d = str_field(value, "description", line)?.trim().to_string();
                if d.is_empty() {
                    continue;
                }
                fm.description = capped(d, "description", MAX_DESCRIPTION_LEN)?;
                have_desc = true;
            }
            "license" => {
                let v = str_field(value, "license", line)?;
                fm.license = Some(capped(v.trim().to_string(), "license", MAX_VALUE_LEN)?);
            }
            "compatibility" => {
                let v = str_field(value, "compatibility", line)?;
                fm.compatibility = Some(capped(
                    v.trim().to_string(),
                    "compatibility",
                    MAX_COMPATIBILITY_LEN,
                )?);
            }
            "metadata" => match value {
                Value::Map(m) => {
                    for (k, v) in m {
                        fm.metadata.insert(k, capped(v, "metadata", MAX_VALUE_LEN)?);
                    }
                }
                Value::Str(s) if s.is_empty() => {}
                _ => return Err(yaml_err(line, "'metadata' must be a map of strings")),
            },
            "allowed-tools" => {
                fm.allowed_tools = match value {
                    Value::Str(s) => s.split_whitespace().map(str::to_string).collect(),
                    Value::List(l) => l,
                    Value::Map(_) => {
                        return Err(yaml_err(line, "'allowed-tools' must be a string or list"))
                    }
                };
            }
            k if EXTENSION_KEYS.contains(&k) => {
                let v = match value {
                    Value::Str(s) => s,
                    Value::List(l) => l.join(", "),
                    Value::Map(_) => {
                        return Err(yaml_err(line, format!("'{k}' must be a string or list")))
                    }
                };
                fm.extensions
                    .insert(k.to_string(), capped(v, "extension", MAX_VALUE_LEN)?);
            }
            other => {
                debug_assert!(!SPEC_KEYS.contains(&other));
                return Err(SkillError::UnknownKey(other.to_string()));
            }
        }
    }
    if !have_name {
        return Err(SkillError::MissingField("name"));
    }
    if !have_desc {
        return Err(SkillError::MissingField("description"));
    }
    Ok((fm, body))
}

// ---------------------------------------------------------------------------------------------
// Loading a library from sources
// ---------------------------------------------------------------------------------------------

/// One place skills come from. Sources are given in precedence order: the first wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillSource {
    pub label: String,
    pub root: PathBuf,
}

impl SkillSource {
    pub fn new(label: impl Into<String>, root: impl Into<PathBuf>) -> Self {
        SkillSource {
            label: label.into(),
            root: root.into(),
        }
    }
}

/// One loaded skill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skill {
    pub name: String,
    pub description: String,
    /// The label of the source it came from.
    pub source: String,
    /// The skill's directory, canonicalized at load time.
    pub dir: PathBuf,
    pub body: String,
    pub frontmatter: SkillFrontmatter,
    /// Readable bundled files (relative, `/`-separated, sorted), confined to `dir`.
    pub refs: Vec<String>,
    /// Files under `scripts/`: listed and flagged, never executed or loaded.
    pub scripts: Vec<String>,
}

/// A path that was not loaded, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub path: PathBuf,
    pub reason: String,
}

/// A skill name present in a lower-precedence source that an earlier source already provided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shadowed {
    pub name: String,
    pub kept_source: String,
    pub dropped_source: String,
}

/// What happened while loading (for the operator log and the UI, never for the model).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadReport {
    pub rejected: Vec<Rejected>,
    pub shadowed: Vec<Shadowed>,
}

/// The compact description index that rides in the system prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillIndex {
    pub text: String,
    pub included: usize,
    pub omitted: usize,
}

/// Every loaded skill, by name.
#[derive(Debug, Clone, Default)]
pub struct SkillLibrary {
    skills: BTreeMap<String, Skill>,
    report: LoadReport,
}

fn is_hidden(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with('.'))
}

fn sorted_entries(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path())).collect(),
        Err(_) => Vec::new(),
    };
    v.sort();
    v
}

/// Find every directory under `root` holding a `SKILL.md` (not descending into a skill).
fn discover(root: &Path, report: &mut LoadReport) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut visited = 0usize;
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        visited += 1;
        if visited > MAX_SCAN_DIRS {
            report.rejected.push(Rejected {
                path: root.to_path_buf(),
                reason: format!("scan stopped after {MAX_SCAN_DIRS} directories"),
            });
            break;
        }
        if dir.join("SKILL.md").is_file() {
            found.push(dir);
            continue;
        }
        if depth >= MAX_SCAN_DEPTH {
            continue;
        }
        // Reverse so the stack pops in sorted order.
        for child in sorted_entries(&dir).into_iter().rev() {
            if !is_hidden(&child) && child.is_dir() {
                stack.push((child, depth + 1));
            }
        }
    }
    found
}

fn rel_string(rel: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for c in rel.components() {
        match c {
            Component::Normal(s) => parts.push(s.to_str()?.to_string()),
            _ => return None,
        }
    }
    Some(parts.join("/"))
}

/// List a skill's bundled files. Symlinked directories are not followed; a symlinked file is
/// listed only when it resolves inside the skill directory.
fn list_resources(dir: &Path) -> (Vec<String>, Vec<String>) {
    let mut refs = Vec::new();
    let mut scripts = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(dir.to_path_buf(), 0)];
    while let Some((d, depth)) = stack.pop() {
        for entry in sorted_entries(&d) {
            if refs.len() + scripts.len() >= MAX_FILES_LISTED {
                break;
            }
            if is_hidden(&entry) {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(&entry) else {
                continue;
            };
            let is_file = if meta.file_type().is_symlink() {
                match std::fs::canonicalize(&entry) {
                    Ok(target) if target.starts_with(dir) && target.is_file() => true,
                    _ => continue,
                }
            } else if meta.is_dir() {
                if depth + 1 < MAX_RESOURCE_DEPTH {
                    stack.push((entry, depth + 1));
                }
                continue;
            } else {
                meta.is_file()
            };
            if !is_file {
                continue;
            }
            let Ok(rel) = entry.strip_prefix(dir) else {
                continue;
            };
            let Some(rel) = rel_string(rel) else {
                continue;
            };
            if rel == "SKILL.md" {
                continue;
            }
            if rel.starts_with("scripts/") {
                scripts.push(rel);
            } else {
                refs.push(rel);
            }
        }
    }
    refs.sort();
    scripts.sort();
    (refs, scripts)
}

fn load_one(dir: &Path, source: &str) -> Result<Skill, String> {
    let file = dir.join("SKILL.md");
    let meta =
        std::fs::metadata(&file).map_err(|e| SkillError::Io(e.kind().to_string()).to_string())?;
    if meta.len() > MAX_SKILL_FILE_BYTES as u64 {
        return Err(SkillError::TooLarge {
            max: MAX_SKILL_FILE_BYTES,
        }
        .to_string());
    }
    let bytes =
        std::fs::read(&file).map_err(|e| SkillError::Io(e.kind().to_string()).to_string())?;
    let text = String::from_utf8(bytes).map_err(|_| SkillError::NotUtf8.to_string())?;
    let (fm, body) = parse_skill_md(&text).map_err(|e| e.to_string())?;
    let dir_name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if dir_name != fm.name {
        return Err(format!(
            "name '{}' does not match its directory '{dir_name}'",
            fm.name
        ));
    }
    let canon =
        std::fs::canonicalize(dir).map_err(|e| SkillError::Io(e.kind().to_string()).to_string())?;
    let (refs, scripts) = list_resources(&canon);
    Ok(Skill {
        name: fm.name.clone(),
        description: fm.description.clone(),
        source: source.to_string(),
        dir: canon,
        body,
        frontmatter: fm,
        refs,
        scripts,
    })
}

/// Collapse whitespace and cut to `max` chars (with an ellipsis when cut).
fn one_line(s: &str, max: usize) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        flat
    } else {
        let cut: String = flat.chars().take(max.saturating_sub(1)).collect();
        format!("{}…", cut.trim_end())
    }
}

impl SkillLibrary {
    /// No skills.
    pub fn empty() -> Self {
        SkillLibrary::default()
    }

    /// HUP-S3.3: this library cut down to a persona's skill allowlist. Returns the skills that are
    /// both loaded and allowed, plus the allowlisted names that are not loaded (in allowlist
    /// order), so a client can say which are missing. The load report is kept as is.
    pub fn restricted_to(&self, allow: &[String]) -> (SkillLibrary, Vec<String>) {
        let mut skills = BTreeMap::new();
        let mut missing = Vec::new();
        for name in allow {
            match self.skills.get(name) {
                Some(s) => {
                    skills.insert(name.clone(), s.clone());
                }
                None => {
                    if !missing.contains(name) {
                        missing.push(name.clone());
                    }
                }
            }
        }
        (
            SkillLibrary {
                skills,
                report: self.report.clone(),
            },
            missing,
        )
    }

    /// Load every source, in precedence order (first wins). Never fails: anything refused is in
    /// [`SkillLibrary::report`].
    pub fn load(sources: &[SkillSource]) -> Self {
        let mut lib = SkillLibrary::default();
        // Names that an earlier source holds ambiguously: a later source may not fill them, or
        // precedence would invert.
        let mut ambiguous: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for src in sources {
            if !src.root.is_dir() {
                lib.report.rejected.push(Rejected {
                    path: src.root.clone(),
                    reason: format!("source '{}': not a directory", src.label),
                });
                continue;
            }
            let mut found: BTreeMap<String, Vec<Skill>> = BTreeMap::new();
            let mut accepted = 0usize;
            for dir in discover(&src.root, &mut lib.report) {
                let path = dir.join("SKILL.md");
                if accepted >= MAX_SKILLS_PER_SOURCE {
                    lib.report.rejected.push(Rejected {
                        path,
                        reason: format!(
                            "source '{}' has more than {MAX_SKILLS_PER_SOURCE} skills",
                            src.label
                        ),
                    });
                    continue;
                }
                match load_one(&dir, &src.label) {
                    Ok(skill) => {
                        let copies = found.entry(skill.name.clone()).or_default();
                        // The same directory reached twice (through a symlink) is one skill.
                        if !copies.iter().any(|c| c.dir == skill.dir) {
                            accepted += 1;
                            copies.push(skill);
                        }
                    }
                    Err(reason) => lib.report.rejected.push(Rejected { path, reason }),
                }
            }
            for (name, mut copies) in found {
                if copies.len() > 1 {
                    for c in copies {
                        lib.report.rejected.push(Rejected {
                            path: c.dir.join("SKILL.md"),
                            reason: format!(
                                "duplicate skill name '{name}' in source '{}' (ambiguous; none loaded)",
                                src.label
                            ),
                        });
                    }
                    ambiguous.insert(name);
                    continue;
                }
                let Some(skill) = copies.pop() else { continue };
                if let Some(kept) = lib.skills.get(&name) {
                    lib.report.shadowed.push(Shadowed {
                        name,
                        kept_source: kept.source.clone(),
                        dropped_source: src.label.clone(),
                    });
                } else if ambiguous.contains(&name) {
                    lib.report.rejected.push(Rejected {
                        path: skill.dir.join("SKILL.md"),
                        reason: format!(
                            "skill name '{name}' is ambiguous in a higher-precedence source; not loaded from '{}'",
                            src.label
                        ),
                    });
                } else {
                    lib.skills.insert(name, skill);
                }
            }
        }
        lib
    }

    pub fn get(&self, name: &str) -> Option<&Skill> {
        self.skills.get(name)
    }

    /// Skill names, sorted.
    pub fn names(&self) -> Vec<&str> {
        self.skills.keys().map(String::as_str).collect()
    }

    pub fn len(&self) -> usize {
        self.skills.len()
    }

    pub fn is_empty(&self) -> bool {
        self.skills.is_empty()
    }

    pub fn report(&self) -> &LoadReport {
        &self.report
    }

    /// One line per skill (`- name: description`), sorted by name, cut to fit `budget_tokens` as
    /// counted by `counter`. When skills are left out, a final line says how many.
    pub fn index(&self, budget_tokens: usize, counter: &dyn TokenCounter) -> SkillIndex {
        let lines: Vec<String> = self
            .skills
            .values()
            .map(|s| {
                format!(
                    "- {}: {}",
                    s.name,
                    one_line(&s.description, INDEX_DESC_CHARS)
                )
            })
            .collect();
        let total = lines.len();
        let all = lines.join("\n");
        if counter.count(&all) <= budget_tokens {
            return SkillIndex {
                text: all,
                included: total,
                omitted: 0,
            };
        }
        let footer = |n: usize| format!("- (+{n} more skills not listed)");
        let mut text = String::new();
        let mut included = 0usize;
        for line in &lines {
            let candidate = if text.is_empty() {
                line.clone()
            } else {
                format!("{text}\n{line}")
            };
            let with_footer = format!("{candidate}\n{}", footer(total - included - 1));
            if counter.count(&with_footer) > budget_tokens {
                break;
            }
            text = candidate;
            included += 1;
        }
        let omitted = total - included;
        let foot = footer(omitted);
        let text = if text.is_empty() {
            if counter.count(&foot) <= budget_tokens {
                foot
            } else {
                String::new()
            }
        } else {
            format!("{text}\n{foot}")
        };
        SkillIndex {
            text,
            included,
            omitted,
        }
    }

    /// US-3.2 AC1: the at most `k` skills that best match `query`, ranked by BM25 over each
    /// skill's name and description. A query that matches no skill surfaces none.
    pub fn select(&self, query: &str, k: usize) -> Vec<&Skill> {
        self.select_with(&Bm25Ranker, query, k)
    }

    /// [`SkillLibrary::select`] with another ranker (for example an embedding ranker). The result
    /// is capped at `k` whatever the ranker returns.
    pub fn select_with(&self, ranker: &dyn SkillRanker, query: &str, k: usize) -> Vec<&Skill> {
        let skills: Vec<&Skill> = self.skills.values().collect();
        let docs: Vec<(&str, &str)> = skills
            .iter()
            .map(|s| (s.name.as_str(), s.description.as_str()))
            .collect();
        let mut out: Vec<&Skill> = Vec::new();
        for i in ranker.rank(query, &docs, k) {
            if out.len() >= k {
                break;
            }
            if let Some(s) = skills.get(i) {
                if !out.iter().any(|o| o.name == s.name) {
                    out.push(s);
                }
            }
        }
        out
    }

    /// The system-prompt section for one turn: the skills that match `query` (at most `k`, best
    /// first) and how many are installed in all. `None` when no skill is installed.
    pub fn turn_section(&self, query: &str, k: usize) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        let total = self.len();
        let installed = if total == 1 {
            "1 skill is installed".to_string()
        } else {
            format!("{total} skills are installed")
        };
        let picked = self.select(query, k);
        if picked.is_empty() {
            return Some(format!(
                "## Skills\n{installed}; none matches this request. If the member asks for one by \
                 name, call `{SKILL_LOAD_TOOL}` with that exact name."
            ));
        }
        let lines: Vec<String> = picked
            .iter()
            .map(|s| {
                format!(
                    "- {}: {}",
                    s.name,
                    one_line(&s.description, INDEX_DESC_CHARS)
                )
            })
            .collect();
        Some(format!(
            "## Skills\nSkills are instructions, not actions. {installed}; these match this \
             request best. Before a task one of these covers, call `{SKILL_LOAD_TOOL}` with its \
             exact name to read it; it may list files you can read the same way. Follow it using \
             your tools; every effect still goes through their approval gates.\n{}",
            lines.join("\n")
        ))
    }

    /// The text `skill_load` returns for a skill: its body plus its bundled files.
    pub fn load_body(&self, name: &str) -> Result<String, String> {
        let s = self
            .get(name)
            .ok_or_else(|| format!("no skill named '{name}'"))?;
        let mut out = format!("# Skill: {} (source: {})\n\n{}", s.name, s.source, s.body);
        if !out.ends_with('\n') {
            out.push('\n');
        }
        if !s.refs.is_empty() {
            out.push_str(&format!(
                "\n---\nFiles in this skill (read one with {SKILL_LOAD_TOOL} {{\"name\": \"{}\", \"ref\": \"<path>\"}}):\n",
                s.name
            ));
            for r in &s.refs {
                out.push_str(&format!("- {r}\n"));
            }
        }
        if !s.scripts.is_empty() {
            out.push_str(
                "\nScripts (listed for reference only; they are never executed by Hermes):\n",
            );
            for r in &s.scripts {
                out.push_str(&format!("- {r} [script, not run]\n"));
            }
        }
        Ok(out)
    }

    /// Read one listed bundled file of a skill, confined to the skill's directory.
    pub fn read_ref(&self, name: &str, rel: &str) -> Result<String, String> {
        let s = self
            .get(name)
            .ok_or_else(|| format!("no skill named '{name}'"))?;
        if rel.trim().is_empty() {
            return Err("ref is empty".into());
        }
        if s.scripts.iter().any(|x| x == rel) {
            return Err(format!(
                "'{rel}' is a script; skill scripts are listed for reference only and are never executed or loaded"
            ));
        }
        if !s.refs.iter().any(|x| x == rel) {
            return Err(format!(
                "'{rel}' is not a listed file of skill '{name}' (listed: {})",
                if s.refs.is_empty() {
                    "none".to_string()
                } else {
                    s.refs.join(", ")
                }
            ));
        }
        let path = s.dir.join(rel);
        let canon = std::fs::canonicalize(&path).map_err(|_| format!("'{rel}' is unavailable"))?;
        if !canon.starts_with(&s.dir) {
            return Err(format!("'{rel}' resolves outside the skill"));
        }
        let meta = std::fs::metadata(&canon).map_err(|_| format!("'{rel}' is unavailable"))?;
        if !meta.is_file() {
            return Err(format!("'{rel}' is not a file"));
        }
        if meta.len() > MAX_REF_BYTES as u64 {
            return Err(format!("'{rel}' is too large (over {MAX_REF_BYTES} bytes)"));
        }
        let bytes = std::fs::read(&canon).map_err(|_| format!("'{rel}' is unavailable"))?;
        if bytes.len() > MAX_REF_BYTES {
            return Err(format!("'{rel}' is too large (over {MAX_REF_BYTES} bytes)"));
        }
        String::from_utf8(bytes).map_err(|_| format!("'{rel}' is not a text file"))
    }
}

// ---------------------------------------------------------------------------------------------
// The skill_load tool
// ---------------------------------------------------------------------------------------------

/// The `skill_load` tool offered to the model. Sidecar-hosted, read-only, idempotent.
pub fn skill_load_spec() -> ToolSpec {
    ToolSpec {
        name: SKILL_LOAD_TOOL.to_string(),
        description: "Read a skill's instructions by its exact name from the Skills list. \
                      Pass `ref` to read one of the files the skill lists. Skills are \
                      instructions only; nothing is run."
            .to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "The skill's exact name."},
                "ref": {"type": "string", "description": "Optional: a file path the skill lists, e.g. references/checklist.md."}
            },
            "required": ["name"],
            "additionalProperties": false
        }),
        host: HostKind::Sidecar,
        // Reads text and runs nothing, so it stays callable after taint; skill bodies can be
        // third-party, so what it returns is untrusted and taints the session (HUP-S2.7).
        annotations: ToolAnnotations {
            read_only: true,
            destructive: false,
            idempotent: true,
            open_world: false,
            effect: Some(crate::Effect::None),
            trust: Some(crate::Trust::Untrusted),
        },
    }
}

/// Runs `skill_load` calls against a [`SkillLibrary`].
#[derive(Clone)]
pub struct SkillHost {
    lib: Arc<SkillLibrary>,
}

impl SkillHost {
    pub fn new(lib: Arc<SkillLibrary>) -> Self {
        SkillHost { lib }
    }

    pub fn library(&self) -> &Arc<SkillLibrary> {
        &self.lib
    }
}

impl ToolHost for SkillHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        if call.name != SKILL_LOAD_TOOL {
            return ToolOutcome::Error(format!("'{}' is not a skill tool", call.name));
        }
        let raw = if call.arguments.trim().is_empty() {
            "{}"
        } else {
            &call.arguments
        };
        let args: serde_json::Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(_) => return ToolOutcome::Error("arguments must be a JSON object".into()),
        };
        let Some(name) = args.get("name").and_then(|v| v.as_str()) else {
            return ToolOutcome::Error("`name` (a string) is required".into());
        };
        let result = match args.get("ref") {
            None | Some(serde_json::Value::Null) => self.lib.load_body(name),
            Some(serde_json::Value::String(r)) => self.lib.read_ref(name, r),
            Some(_) => Err("`ref` must be a string".into()),
        };
        match result {
            Ok(s) => ToolOutcome::Ok(s),
            Err(e) => ToolOutcome::Error(e),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Per-turn skill retrieval (US-3.2 AC1)
// ---------------------------------------------------------------------------------------------

/// Ranks skill descriptions against a request. `docs` are `(name, description)` pairs; the result
/// is indices into `docs`, best first, at most `k`.
pub trait SkillRanker: Send + Sync {
    /// Which method ran, for the operator log and tests (for example `bm25-lexical`).
    fn method(&self) -> &'static str;
    fn rank(&self, query: &str, docs: &[(&str, &str)], k: usize) -> Vec<usize>;
}

/// Okapi BM25 over each skill's name (counted three times) and description. Deterministic: equal
/// scores break by position, which is name order in a [`SkillLibrary`]. Only skills that share a
/// term with the query are returned. The sidecar has no embedding model in process, so this
/// lexical ranker is the one that runs; an embedding ranker can implement [`SkillRanker`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Bm25Ranker;

const BM25_K1: f64 = 1.2;
const BM25_B: f64 = 0.75;
const NAME_WEIGHT: usize = 3;

impl SkillRanker for Bm25Ranker {
    fn method(&self) -> &'static str {
        "bm25-lexical"
    }

    fn rank(&self, query: &str, docs: &[(&str, &str)], k: usize) -> Vec<usize> {
        let mut q = crate::words(query);
        q.sort();
        q.dedup();
        if q.is_empty() || docs.is_empty() || k == 0 {
            return Vec::new();
        }
        let terms: Vec<Vec<String>> = docs
            .iter()
            .map(|(name, desc)| {
                let mut t = Vec::new();
                for _ in 0..NAME_WEIGHT {
                    t.extend(crate::words(name));
                }
                t.extend(crate::words(desc));
                t
            })
            .collect();
        let n = terms.len() as f64;
        let avg_len = terms.iter().map(Vec::len).sum::<usize>() as f64 / n;
        let mut scored: Vec<(usize, f64)> = Vec::new();
        for (i, doc) in terms.iter().enumerate() {
            let len = doc.len() as f64;
            let mut score = 0.0;
            for w in &q {
                let tf = doc.iter().filter(|t| *t == w).count() as f64;
                if tf == 0.0 {
                    continue;
                }
                let df = terms.iter().filter(|d| d.contains(w)).count() as f64;
                let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
                let norm = if avg_len > 0.0 {
                    1.0 - BM25_B + BM25_B * len / avg_len
                } else {
                    1.0
                };
                score += idf * tf * (BM25_K1 + 1.0) / (tf + BM25_K1 * norm);
            }
            if score > 0.0 {
                scored.push((i, score));
            }
        }
        scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        scored.into_iter().take(k).map(|(i, _)| i).collect()
    }
}

/// The per-turn skill index: a [`TurnContext`] that puts the at most `k` skills matching the
/// turn's request in the system prompt. A follow-up with no signal of its own ("ok, go ahead") is
/// ranked with the member's previous message instead.
#[derive(Clone)]
pub struct SkillTurnIndex {
    lib: Arc<SkillLibrary>,
    k: usize,
}

impl SkillTurnIndex {
    pub fn new(lib: Arc<SkillLibrary>, k: usize) -> Self {
        SkillTurnIndex { lib, k }
    }

    /// The method that ranks the skills (see [`Bm25Ranker`]).
    pub fn method(&self) -> &'static str {
        Bm25Ranker.method()
    }
}

impl TurnContext for SkillTurnIndex {
    fn section(&self, user: &str, history: &[Message]) -> Option<String> {
        if self.lib.select(user, self.k).is_empty() {
            if let Some(prev) = history.iter().rev().find(|m| m.role == Role::User) {
                if !self.lib.select(&prev.content, self.k).is_empty() {
                    return self.lib.turn_section(&prev.content, self.k);
                }
            }
        }
        self.lib.turn_section(user, self.k)
    }
}
