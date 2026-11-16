//! HGW-5 — the auto-approve list for sandboxed, offline, project-scoped read and build commands
//! (D-16 as amended; owner decision 2026-10-15 HGW (3)).
//!
//! The list is data ([`DEFAULT_LIST`], `agent-sidecar/policy/auto_approve.toml`, compiled in; a
//! replacement file can be named with `CITRATE_HERMES_AUTO_APPROVE`). This module only answers
//! "does this argv match a rule, and which one". Whether a match may run without a card is
//! decided in [`crate::shell_run`]: the session must be untainted, the OS sandbox enforced, and
//! the folder inside a project root, with the run's writes limited to that project. Everything
//! else asks, as before.
//!
//! Opt-in rules (owner decision 2026-11-16, V1): a rule marked `opt_in` (`node <file>`, `npm run`,
//! `git commit`) is not approved by default. It runs without a card only inside a project the
//! member turned that rule on for ([`ProjectOptIns`], sent by citrate-core as
//! `autoApproveOptIns`). The member's choice is core's; nothing the agent writes can turn one on.

use std::collections::BTreeMap;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

/// The list shipped with the sidecar.
pub const DEFAULT_LIST: &str = include_str!("../policy/auto_approve.toml");
/// `0` turns auto-approval off; an absolute path replaces the shipped list; unset = the shipped
/// list.
pub const AUTO_APPROVE_ENV: &str = "CITRATE_HERMES_AUTO_APPROVE";

const MAX_SCRIPT_NAME: usize = 64;
const MAX_PATTERN: usize = 256;
const MAX_TEXT: usize = 4096;

/// What one argument may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// A relative path that stays inside the folder: no root, no `..`, no `~`, no leading `-`.
    RelativePath,
    /// An npm script name.
    ScriptName,
    /// A package, test or binary name.
    Name,
    /// A test filter: no NUL, no leading `-`, at most 256 bytes.
    Pattern,
    /// Free text (a commit message): no NUL, at most 4096 bytes.
    Text,
    /// Digits only.
    Count,
    /// No argument of this kind is allowed.
    None,
}

impl Kind {
    fn accepts(self, v: &str) -> bool {
        if v.contains('\0') {
            return false;
        }
        match self {
            Kind::RelativePath => relative_path(v),
            Kind::ScriptName => {
                !v.is_empty()
                    && v.len() <= MAX_SCRIPT_NAME
                    && !v.starts_with('-')
                    && v.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-'))
            }
            Kind::Name => {
                !v.is_empty()
                    && v.len() <= MAX_SCRIPT_NAME
                    && !v.starts_with('-')
                    && v.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            }
            Kind::Pattern => !v.is_empty() && v.len() <= MAX_PATTERN && !v.starts_with('-'),
            Kind::Text => v.len() <= MAX_TEXT,
            Kind::Count => !v.is_empty() && v.len() <= 9 && v.bytes().all(|b| b.is_ascii_digit()),
            Kind::None => false,
        }
    }
}

fn relative_path(v: &str) -> bool {
    if v.is_empty() || v.starts_with('-') || v.starts_with('~') {
        return false;
    }
    Path::new(v)
        .components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}

/// One rule of the list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub program: String,
    #[serde(default)]
    pub subcommands: Vec<String>,
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub value_flags: BTreeMap<String, Kind>,
    #[serde(default)]
    pub require_one_of: Vec<String>,
    pub operands: Kind,
    /// When not empty, every operand must be one of these exact values (e.g. the npm script
    /// names `build`, `test`, `lint`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operand_values: Vec<String>,
    #[serde(default)]
    pub min_operands: usize,
    #[serde(default = "default_max_operands")]
    pub max_operands: usize,
    /// V1 (owner decision 2026-11-16): `true` = off unless the member turned this rule on for the
    /// project ([`ProjectOptIns`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub opt_in: bool,
}

fn default_max_operands() -> usize {
    0
}

impl Rule {
    /// Whether `argv` (program first) matches this rule exactly.
    pub fn matches(&self, argv: &[String]) -> bool {
        let Some((program, rest)) = argv.split_first() else {
            return false;
        };
        if *program != self.program {
            return false;
        }
        let mut args = rest.iter();
        if !self.subcommands.is_empty() {
            match args.next() {
                Some(sub) if self.subcommands.iter().any(|s| s == sub) => {}
                _ => return false,
            }
        }
        let mut operands = 0usize;
        let mut seen_flags: Vec<&str> = Vec::new();
        while let Some(a) = args.next() {
            if a == "--" {
                // `--` passes what follows on (to a script, or as paths): never auto-approved.
                return false;
            }
            if a.starts_with('-') && a.len() > 1 {
                if self.flags.iter().any(|f| f == a) {
                    seen_flags.push(a);
                    continue;
                }
                if let Some(kind) = self.value_flags.get(a.as_str()) {
                    match args.next() {
                        Some(v) if kind.accepts(v) => {
                            seen_flags.push(a);
                            continue;
                        }
                        _ => return false,
                    }
                }
                if let Some((flag, v)) = a.split_once('=') {
                    if let Some(kind) = self.value_flags.get(flag) {
                        if kind.accepts(v) {
                            seen_flags.push(flag);
                            continue;
                        }
                    }
                }
                return false;
            }
            if !self.operands.accepts(a)
                || (!self.operand_values.is_empty() && !self.operand_values.iter().any(|v| v == a))
            {
                return false;
            }
            operands += 1;
        }
        if operands < self.min_operands || operands > self.max_operands {
            return false;
        }
        self.require_one_of.is_empty()
            || self
                .require_one_of
                .iter()
                .any(|r| seen_flags.iter().any(|f| f == r))
    }
}

/// The parsed list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoApproveList {
    pub version: u32,
    #[serde(rename = "rule")]
    pub rules: Vec<Rule>,
}

impl AutoApproveList {
    /// Parse and check a list: version 1, unique ids, bare program names, and an operand count
    /// that only allows operands when their kind does.
    pub fn parse(text: &str) -> Result<Self, String> {
        let list: AutoApproveList =
            toml::from_str(text).map_err(|e| format!("the auto-approve list is invalid: {e}"))?;
        if list.version != 1 {
            return Err(format!(
                "the auto-approve list has version {}, expected 1",
                list.version
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        for r in &list.rules {
            if r.id.is_empty() || !ids.insert(r.id.clone()) {
                return Err(format!(
                    "auto-approve rule id {:?} is empty or repeated",
                    r.id
                ));
            }
            if citrate_agent_shell::validate_program_name(&r.program).is_err() {
                return Err(format!(
                    "auto-approve rule {} names {:?}, which is not a bare program name",
                    r.id, r.program
                ));
            }
            if r.operands == Kind::None && (r.min_operands > 0 || r.max_operands > 0) {
                return Err(format!(
                    "auto-approve rule {} allows operands of kind none",
                    r.id
                ));
            }
            if r.min_operands > r.max_operands {
                return Err(format!(
                    "auto-approve rule {} needs more operands than it allows",
                    r.id
                ));
            }
            if r.value_flags.values().any(|k| *k == Kind::None) {
                return Err(format!(
                    "auto-approve rule {} has a value flag of kind none",
                    r.id
                ));
            }
        }
        Ok(list)
    }

    /// The shipped list.
    pub fn shipped() -> Result<Self, String> {
        Self::parse(DEFAULT_LIST)
    }

    /// From `CITRATE_HERMES_AUTO_APPROVE`: `0` = off (`Ok(None)`), unset or empty = the shipped
    /// list, an absolute path = that file. Anything else, or a file that does not load, is an
    /// error (the caller turns auto-approval off and says why).
    pub fn from_env_value(v: Option<&str>) -> Result<Option<Self>, String> {
        match v.map(str::trim) {
            None | Some("") => Self::shipped().map(Some),
            Some("0") => Ok(None),
            Some(p) if Path::new(p).is_absolute() => {
                let text = std::fs::read_to_string(p)
                    .map_err(|e| format!("cannot read the auto-approve list {p}: {e}"))?;
                Self::parse(&text).map(Some)
            }
            Some(other) => Err(format!(
                "{AUTO_APPROVE_ENV} must be 0 or an absolute path, not {other:?}"
            )),
        }
    }

    /// The id of the first rule `argv` matches.
    pub fn matching(&self, argv: &[String]) -> Option<&str> {
        self.matching_rule(argv).map(|r| r.id.as_str())
    }

    /// The first rule `argv` matches.
    pub fn matching_rule(&self, argv: &[String]) -> Option<&Rule> {
        self.rules.iter().find(|r| r.matches(argv))
    }

    /// The ids of the rules that need the member's per-project opt-in.
    pub fn opt_in_ids(&self) -> Vec<&str> {
        self.rules
            .iter()
            .filter(|r| r.opt_in)
            .map(|r| r.id.as_str())
            .collect()
    }
}

/// One entry of `autoApproveOptIns` in a `POST /sessions` body: a project folder the member chose
/// and the opt-in rules they turned on for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OptInDoc {
    pub root: String,
    pub rules: Vec<String>,
}

/// The member's per-project opt-ins for one session, checked against the active list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectOptIns {
    /// (canonical folder, rule ids), in the order given.
    entries: Vec<(std::path::PathBuf, std::collections::BTreeSet<String>)>,
}

/// Most entries `autoApproveOptIns` may carry.
pub const MAX_OPT_INS: usize = 64;

impl ProjectOptIns {
    /// Check `docs` against `list`. Refused: more than [`MAX_OPT_INS`] entries, a relative root,
    /// or a rule id that is not an opt-in rule of the list (a rule that is already approved by
    /// default, or no rule at all, is a caller bug and must not pass silently). A root that does
    /// not exist (a deleted project) is left out: an opt-in can only ever let fewer commands run
    /// without a card, never more.
    pub fn check(docs: &[OptInDoc], list: Option<&AutoApproveList>) -> Result<Self, String> {
        if docs.len() > MAX_OPT_INS {
            return Err(format!(
                "autoApproveOptIns has {} entries, at most {MAX_OPT_INS}",
                docs.len()
            ));
        }
        let known: Vec<&str> = list.map(|l| l.opt_in_ids()).unwrap_or_default();
        let mut entries = Vec::new();
        for d in docs {
            let root = Path::new(&d.root);
            if !root.is_absolute() {
                return Err(format!(
                    "autoApproveOptIns root {:?} is not an absolute path",
                    d.root
                ));
            }
            for r in &d.rules {
                if list.is_some() && !known.contains(&r.as_str()) {
                    return Err(format!(
                        "autoApproveOptIns names {r:?}, which is not an opt-in rule of the auto-approve list"
                    ));
                }
            }
            let Ok(canonical) = root.canonicalize() else {
                continue;
            };
            if !canonical.is_dir() || d.rules.is_empty() {
                continue;
            }
            entries.push((canonical, d.rules.iter().cloned().collect()));
        }
        Ok(ProjectOptIns { entries })
    }

    /// Whether the member turned `rule` on for `project` (a canonical project root): an entry's
    /// folder is the project or holds it.
    pub fn allows(&self, rule: &str, project: &Path) -> bool {
        self.entries
            .iter()
            .any(|(root, rules)| project.starts_with(root) && rules.contains(rule))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    fn list() -> AutoApproveList {
        AutoApproveList::shipped().expect("the shipped list loads")
    }

    #[test]
    fn the_shipped_list_loads_and_covers_the_d16_commands() {
        let l = list();
        for (argv, id) in [
            (v(&["ls"]), "ls"),
            (v(&["ls", "-la", "src"]), "ls"),
            (v(&["pwd"]), "pwd"),
            (v(&["cat", "package.json"]), "cat"),
            (v(&["head", "-n", "40", "src/index.js"]), "head"),
            (v(&["tail", "-n", "20", "build.log"]), "tail"),
            (v(&["wc", "-l", "src/a.ts"]), "wc"),
            (v(&["node", "build.js"]), "node-script"),
            (v(&["npm", "run", "build"]), "npm-run"),
            (v(&["npm", "run", "lint"]), "npm-run"),
            (v(&["npm", "run", "typecheck"]), "npm-run"),
            (v(&["npm", "test"]), "npm-test"),
            (v(&["npx", "tsc", "--noEmit"]), "npx-tsc"),
            (v(&["forge", "build"]), "forge-build-test"),
            (
                v(&["forge", "test", "--match-test", "test_Mint", "-vvv"]),
                "forge-build-test",
            ),
            (v(&["forge", "test", "--mt=test_Mint"]), "forge-build-test"),
            (v(&["cargo", "build", "--offline"]), "cargo-offline"),
            (
                v(&["cargo", "test", "--offline", "-p", "demo", "adds"]),
                "cargo-offline",
            ),
            (v(&["git", "init", "-q"]), "git-init"),
            (v(&["git", "status", "--short"]), "git-status"),
            (v(&["git", "diff", "--stat"]), "git-diff"),
            (v(&["git", "add", "."]), "git-add"),
            (v(&["git", "add", "-A"]), "git-add"),
            (
                v(&["git", "commit", "-m", "init; rm -rf / $(id)"]),
                "git-commit",
            ),
        ] {
            assert_eq!(l.matching(&argv), Some(id), "{argv:?}");
        }
    }

    #[test]
    fn node_npm_run_and_git_commit_are_opt_in_and_nothing_else_is() {
        // V1 (owner decision 2026-11-16): arbitrary code (a project's own script) and commits are
        // off by default; every other shipped rule stays approved by default.
        let l = list();
        let mut ids = l.opt_in_ids();
        ids.sort_unstable();
        assert_eq!(ids, vec!["git-commit", "node-script", "npm-run"]);
        for argv in [
            v(&["node", "build.js"]),
            v(&["npm", "run", "test"]),
            v(&["git", "commit", "-m", "x"]),
        ] {
            assert!(l.matching_rule(&argv).expect("listed").opt_in, "{argv:?}");
        }
        for argv in [v(&["ls"]), v(&["npm", "test"]), v(&["git", "add", "."])] {
            assert!(!l.matching_rule(&argv).expect("listed").opt_in, "{argv:?}");
        }
    }

    #[test]
    fn project_opt_ins_are_checked_against_the_list() {
        let l = list();
        let d = tempfile::tempdir().expect("tmp");
        let proj = d.path().join("proj");
        std::fs::create_dir_all(proj.join("sub")).expect("mkdir");
        let doc = |root: &std::path::Path, rules: &[&str]| OptInDoc {
            root: root.display().to_string(),
            rules: rules.iter().map(|r| r.to_string()).collect(),
        };
        // A default rule, an unknown id or a relative root is refused.
        assert!(ProjectOptIns::check(&[doc(&proj, &["ls"])], Some(&l)).is_err());
        assert!(ProjectOptIns::check(&[doc(&proj, &["rm-rf"])], Some(&l)).is_err());
        assert!(ProjectOptIns::check(
            &[OptInDoc {
                root: "proj".into(),
                rules: vec!["node-script".into()]
            }],
            Some(&l)
        )
        .is_err());
        let many: Vec<OptInDoc> = (0..=MAX_OPT_INS)
            .map(|_| doc(&proj, &["node-script"]))
            .collect();
        assert!(ProjectOptIns::check(&many, Some(&l)).is_err());
        // A folder that no longer exists is left out.
        let gone = ProjectOptIns::check(&[doc(&d.path().join("gone"), &["node-script"])], Some(&l))
            .expect("checked");
        assert!(gone.is_empty());
        // One rule, for this project and the projects inside it, and nowhere else.
        let o = ProjectOptIns::check(&[doc(&proj, &["node-script"])], Some(&l)).expect("checked");
        let canon = proj.canonicalize().expect("canon");
        assert!(o.allows("node-script", &canon));
        assert!(o.allows("node-script", &canon.join("sub")));
        assert!(!o.allows("npm-run", &canon));
        assert!(!o.allows("node-script", d.path()));
    }

    #[test]
    fn network_paths_and_anything_else_are_not_on_the_list() {
        let l = list();
        for argv in [
            v(&["npm", "install"]),
            v(&["npm", "ci"]),
            v(&["npm", "run", "build", "--", "--watch"]),
            v(&["npm", "run"]),
            // HGW-W11 (#77): only the listed script names.
            v(&["npm", "run", "deploy"]),
            v(&["npm", "run", "dev"]),
            v(&["npm", "run", "test:unit"]),
            v(&["npm", "run", "-build"]),
            v(&["npx", "create-next-app", "demo"]),
            v(&["npx", "tsc", "-p", "/etc"]),
            v(&["git", "push"]),
            v(&["git", "clone", "https://example.invalid/r.git"]),
            v(&["git", "fetch"]),
            v(&["git", "-c", "core.hooksPath=x", "commit", "-m", "x"]),
            v(&["git", "commit"]),
            v(&["git", "commit", "--amend", "-m", "x"]),
            v(&["git", "add", "../outside"]),
            v(&["git", "init", "../elsewhere"]),
            v(&["git", "init", "--template=/tmp/t"]),
            v(&["git", "config", "user.name", "x"]),
            v(&["cat", "/etc/passwd"]),
            v(&["cat", "../secret"]),
            v(&["cat", "~/x"]),
            v(&["cat"]),
            v(&["ls", "-R", "/"]),
            v(&["ls", "--color=always"]),
            v(&["head", "-n", "x", "a"]),
            v(&["node", "-e", "require('fs')"]),
            v(&["node", "--eval=1"]),
            v(&["node"]),
            v(&["node", "a.js", "b.js"]),
            v(&["cargo", "build"]),
            v(&["cargo", "test", "--config", "x"]),
            v(&["forge", "test", "--ffi"]),
            v(&["forge", "script", "S"]),
            v(&["forge", "install", "x"]),
            v(&["curl", "https://example.invalid"]),
            v(&["rm", "-rf", "."]),
            v(&["sh", "-c", "ls"]),
            v(&[]),
        ] {
            assert_eq!(l.matching(&argv), None, "{argv:?}");
        }
    }

    #[test]
    fn a_bad_list_is_refused() {
        for bad in [
            "version = 2\n[[rule]]\nid='a'\nprogram='ls'\noperands='none'\n",
            "version = 1\n[[rule]]\nid='a'\nprogram='/bin/ls'\noperands='none'\n",
            "version = 1\n[[rule]]\nid='a'\nprogram='ls'\noperands='none'\nmax_operands=1\n",
            "version = 1\n[[rule]]\nid='a'\nprogram='ls'\noperands='none'\n[[rule]]\nid='a'\nprogram='ls'\noperands='none'\n",
            "version = 1\n[[rule]]\nid='a'\nprogram='ls'\noperands='anything'\n",
            "version = 1\n[[rule]]\nid='a'\nprogram='ls'\noperands='none'\nsurprise=true\n",
            "version = 1\n[[rule]]\nid='a'\nprogram='ls'\noperands='relative-path'\nmin_operands=2\nmax_operands=1\n",
        ] {
            assert!(AutoApproveList::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_env_value_turns_it_off_replaces_it_or_is_refused() {
        assert!(AutoApproveList::from_env_value(None).unwrap().is_some());
        assert!(AutoApproveList::from_env_value(Some("0"))
            .unwrap()
            .is_none());
        assert!(AutoApproveList::from_env_value(Some("relative.toml")).is_err());
        let d = tempfile::tempdir().expect("tmp");
        let f = d.path().join("list.toml");
        std::fs::write(
            &f,
            "version = 1\n[[rule]]\nid='only-ls'\nprogram='ls'\noperands='none'\n",
        )
        .expect("write");
        let l = AutoApproveList::from_env_value(Some(&f.display().to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(l.matching(&v(&["ls"])), Some("only-ls"));
        assert_eq!(l.matching(&v(&["git", "status"])), None);
        assert!(AutoApproveList::from_env_value(Some("/nonexistent/list.toml")).is_err());
    }
}
