//! HUP-S5.1: ref-indexed accessibility snapshots.
//!
//! Built from the nodes of CDP `Accessibility.getFullAXTree`. Interactive elements (buttons,
//! links, text fields, ...) get refs `e1`, `e2`, ... in document order; each ref maps to the
//! element's `backendDOMNodeId`, which is how [`crate::service`] clicks or types into it. Nodes
//! that only carry structure are flattened away, text that repeats its parent's name is dropped,
//! page strings are stripped of control characters and truncated, and the whole snapshot is
//! bounded ([`SnapshotLimits`]). Everything in it came from the page: it is untrusted data.

use std::collections::{HashMap, HashSet};

use serde::Serialize;
use serde_json::Value;

/// Bounds on one snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotLimits {
    /// At most this many refs.
    pub max_refs: usize,
    /// At most about this many characters of text.
    pub max_chars: usize,
    /// Any one name or value is cut to this many characters.
    pub max_name_chars: usize,
}

impl Default for SnapshotLimits {
    fn default() -> Self {
        SnapshotLimits {
            max_refs: 150,
            max_chars: 6000,
            max_name_chars: 80,
        }
    }
}

/// One element the model can act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefEntry {
    pub r#ref: String,
    pub role: String,
    pub name: String,
    pub backend_node_id: i64,
    pub disabled: bool,
    /// The element's current value (text fields), cleaned and cut like its name; empty when none.
    pub value: String,
}

/// A snapshot: the text the model reads and the refs it can act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    pub text: String,
    pub refs: Vec<RefEntry>,
    pub truncated: bool,
}

impl Snapshot {
    pub fn find(&self, r: &str) -> Option<&RefEntry> {
        self.refs.iter().find(|e| e.r#ref == r)
    }
}

/// Roles that get a ref.
const INTERACTIVE: &[&str] = &[
    "button",
    "link",
    "textbox",
    "searchbox",
    "checkbox",
    "radio",
    "combobox",
    "listbox",
    "option",
    "menuitem",
    "menuitemcheckbox",
    "menuitemradio",
    "tab",
    "switch",
    "slider",
    "spinbutton",
    "treeitem",
];

/// Roles that only carry structure: never printed, their children are lifted.
const STRUCTURAL: &[&str] = &[
    "generic",
    "none",
    "presentation",
    "LineBreak",
    "InlineTextBox",
    "Section",
    "group",
    "list",
    "listitem",
    "paragraph",
    "div",
    "LayoutTable",
    "LayoutTableRow",
    "LayoutTableCell",
    "Unknown",
];

/// Strip control characters (incl. ESC), collapse whitespace, cut to `max` characters.
pub fn clean(s: &str, max: usize) -> String {
    let mut out = String::new();
    let mut last_space = true;
    for ch in s.chars() {
        if ch.is_control() {
            if matches!(ch, '\n' | '\t' | '\r') && !last_space {
                out.push(' ');
                last_space = true;
            }
            continue;
        }
        if ch.is_whitespace() {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
            continue;
        }
        out.push(ch);
        last_space = false;
    }
    let trimmed = out.trim();
    if trimmed.chars().count() > max {
        let cut: String = trimmed.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    } else {
        trimmed.to_string()
    }
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    let mut cur = v;
    for p in path {
        cur = &cur[*p];
    }
    cur.as_str().unwrap_or_default()
}

fn prop<'a>(node: &'a Value, name: &str) -> Option<&'a Value> {
    node["properties"]
        .as_array()?
        .iter()
        .find(|p| p["name"].as_str() == Some(name))
        .map(|p| &p["value"]["value"])
}

struct Builder<'a> {
    by_id: HashMap<&'a str, &'a Value>,
    limits: SnapshotLimits,
    lines: Vec<String>,
    chars: usize,
    refs: Vec<RefEntry>,
    truncated: bool,
    visited: HashSet<&'a str>,
}

impl<'a> Builder<'a> {
    fn push_line(&mut self, depth: usize, line: String) -> bool {
        let indent = depth.min(12) * 2;
        let len = indent + line.chars().count() + 1;
        if self.chars + len > self.limits.max_chars {
            self.truncated = true;
            return false;
        }
        self.chars += len;
        self.lines.push(format!("{}{line}", " ".repeat(indent)));
        true
    }

    fn walk(&mut self, id: &'a str, depth: usize, parent_name: &str) {
        if self.truncated || !self.visited.insert(id) {
            return;
        }
        let Some(node) = self.by_id.get(id).copied() else {
            return;
        };
        let children: Vec<&'a str> = node["childIds"]
            .as_array()
            .map(|a| a.iter().filter_map(|c| c.as_str()).collect())
            .unwrap_or_default();
        let role = str_at(node, &["role", "value"]);
        let name = clean(str_at(node, &["name", "value"]), self.limits.max_name_chars);
        let ignored = node["ignored"].as_bool().unwrap_or(false);

        if ignored || role.is_empty() || STRUCTURAL.contains(&role) {
            for c in children {
                self.walk(c, depth, parent_name);
            }
            return;
        }
        if role == "StaticText" {
            if !name.is_empty() && name != parent_name {
                self.push_line(depth, format!("text \"{name}\""));
            }
            return;
        }
        if role == "RootWebArea" || role == "WebArea" {
            if !self.push_line(depth, format!("page \"{name}\"")) {
                return;
            }
            for c in children {
                self.walk(c, depth, &name);
            }
            return;
        }
        if INTERACTIVE.contains(&role) {
            let disabled = prop(node, "disabled").and_then(|v| v.as_bool()) == Some(true);
            let backend = node["backendDOMNodeId"].as_i64();
            let mut line = String::new();
            let mut gave_ref = None;
            if let Some(b) = backend {
                if self.refs.len() >= self.limits.max_refs {
                    self.truncated = true;
                    return;
                }
                let r = format!("e{}", self.refs.len() + 1);
                line.push_str(&format!("[{r}] "));
                gave_ref = Some((r, b));
            }
            line.push_str(&format!("{role} \"{name}\""));
            let value = clean(
                str_at(node, &["value", "value"]),
                self.limits.max_name_chars,
            );
            if !value.is_empty() && value != name {
                line.push_str(&format!(" value=\"{value}\""));
            }
            for (p, label) in [
                ("checked", "checked"),
                ("expanded", "expanded"),
                ("selected", "selected"),
            ] {
                if let Some(v) = prop(node, p) {
                    if v.as_bool() == Some(true) || v.as_str() == Some("true") {
                        line.push_str(&format!(" ({label})"));
                    }
                }
            }
            if disabled {
                line.push_str(" (disabled)");
            }
            if !self.push_line(depth, line) {
                return;
            }
            if let Some((r, b)) = gave_ref {
                self.refs.push(RefEntry {
                    r#ref: r,
                    role: role.to_string(),
                    name: name.clone(),
                    backend_node_id: b,
                    disabled,
                    value: value.clone(),
                });
            }
            for c in children {
                self.walk(c, depth + 1, &name);
            }
            return;
        }
        // Any other role: print it when it has a name (headings with their level), and nest.
        if name.is_empty() {
            for c in children {
                self.walk(c, depth, parent_name);
            }
            return;
        }
        let label = match (role, prop(node, "level").and_then(|v| v.as_i64())) {
            ("heading", Some(l)) => format!("heading[{l}]"),
            _ => role.to_string(),
        };
        if !self.push_line(depth, format!("{label} \"{name}\"")) {
            return;
        }
        for c in children {
            self.walk(c, depth + 1, &name);
        }
    }
}

/// Build a snapshot from `Accessibility.getFullAXTree` nodes.
pub fn build_snapshot(nodes: &[Value], limits: SnapshotLimits) -> Snapshot {
    let by_id: HashMap<&str, &Value> = nodes
        .iter()
        .filter_map(|n| n["nodeId"].as_str().map(|id| (id, n)))
        .collect();
    let root = nodes
        .iter()
        .find(|n| n["parentId"].is_null() && n["nodeId"].is_string())
        .and_then(|n| n["nodeId"].as_str());
    let mut b = Builder {
        by_id,
        limits,
        lines: Vec::new(),
        chars: 0,
        refs: Vec::new(),
        truncated: false,
        visited: HashSet::new(),
    };
    match root {
        Some(r) => b.walk(r, 0, ""),
        None => {
            b.lines.push("(the page is empty)".to_string());
        }
    }
    if b.lines.is_empty() {
        b.lines.push("(the page is empty)".to_string());
    }
    if b.truncated {
        b.lines.push(format!(
            "(snapshot truncated at {} refs / {} characters)",
            b.refs.len(),
            b.chars
        ));
    }
    Snapshot {
        text: b.lines.join("\n"),
        refs: b.refs,
        truncated: b.truncated,
    }
}
