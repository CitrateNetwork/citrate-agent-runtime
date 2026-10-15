//! HGW-3 — `project_create`: Hermes makes a new project folder, with the member's approval.
//!
//! One call `{name, template?, params?}`:
//!
//! 1. **Checked before anything is asked.** `name` is one plain folder name (letters, digits,
//!    `.`, `_`, `-`; starts with a letter or digit; at most [`MAX_NAME_LEN`] characters; never
//!    `..`, a path separator or `~`). The projects root (`CITRATE_HERMES_PROJECTS_ROOT`, which
//!    citrate-core passes; default `~/Citrate/Projects`) must exist and be covered by the
//!    session's live read and write folder grants over its whole subtree (citrate-core's
//!    workspace card grants it). `<root>/<name>` must not exist yet. A template id, when given,
//!    is a plain id and needs a configured renderer.
//! 2. **HIC, always.** The call waits on the session's action card (`/actions` routes,
//!    [`crate::action_approvals`]) showing the exact folder, template and parameters. Only an
//!    explicit allow creates anything. A session not opened by an HIC-aware app cannot ask, so it
//!    creates nothing. In a tainted session the one card carries the taint reason too.
//! 3. **Creates** `<root>/<name>` (the grants are checked again first), renders the template into
//!    it when one was asked for ([`TemplateRenderer`]; production runs citrate-core's
//!    `citrate-templates render` program in the OS sandbox, writing only the new folder), writes
//!    the project marker `.citrate/project.json` ([`ProjectMarker`]), and makes the folder one of
//!    the session's project roots, so the file tools may write its build configuration (HGW-2).
//!    A failed render removes the new folder again and reports why.
//! 4. **Returns** the absolute path (`{"ok": true, "path": …, "name": …, "template": …,
//!    "marker": …, "rendered": …}`). citrate-core keeps the path and sends it back in
//!    `projectRoots` when it opens later sessions.
//!
//! The marker is a record for people and for citrate-core; it does not make a folder a project
//! by itself (a cloned repository could carry one). Nothing here signs or holds a key (Rule 3).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::action_approvals::{ActionApprovals, ActionPending};
use crate::grants::SessionGrants;
use citrate_agent_loop::{
    Effect, HostKind, StopFlag, TaintState, ToolAnnotations, ToolCall, ToolHost, ToolOutcome,
    ToolSpec, Trust,
};
use citrate_agent_shell::sandbox::{SandboxMode, SandboxPolicy};
use citrate_agent_shell::{Allowlist, ArgPolicy, RunRequest, ShellPolicy, ShellRunner};

pub const PROJECT_CREATE_TOOL: &str = "project_create";
/// `1` offers `project_create` to sessions opened with folder grants; anything else leaves it off.
pub const PROJECTS_ENV: &str = "CITRATE_HERMES_PROJECTS";
/// The folder new projects go in (absolute). Unset = `$HOME/Citrate/Projects`.
pub const PROJECTS_ROOT_ENV: &str = "CITRATE_HERMES_PROJECTS_ROOT";
/// Absolute path of citrate-core's `citrate-templates` program. Unset = no templates.
pub const TEMPLATE_RENDERER_ENV: &str = "CITRATE_HERMES_TEMPLATE_RENDERER";
/// Absolute path of the bundled templates folder (`templates/` in the app's resources).
pub const TEMPLATES_ROOT_ENV: &str = "CITRATE_HERMES_TEMPLATES_ROOT";
/// The hardware tier passed to the renderer (`T0`, `T1` or `T2`). Unset = `T0`.
pub const TEMPLATE_TIER_ENV: &str = "CITRATE_HERMES_TEMPLATE_TIER";
/// The default projects root, under the member's home.
pub const DEFAULT_PROJECTS_DIR: &str = "Citrate/Projects";
/// The marker, relative to the project folder.
pub const MARKER_DIR: &str = ".citrate";
pub const MARKER_FILE: &str = "project.json";
/// Longest project name.
pub const MAX_NAME_LEN: usize = 64;
/// Most template parameters, and the longest key and value.
pub const MAX_PARAMS: usize = 16;
pub const MAX_PARAM_LEN: usize = 256;
/// How long a render may take.
pub const RENDER_TIMEOUT: Duration = Duration::from_secs(60);

/// What `project_create` needs.
#[derive(Clone)]
pub struct ProjectsConfig {
    /// Where new projects go (absolute).
    pub root: PathBuf,
    /// Renders a bundled template into a new folder; `None` = templates are refused.
    pub renderer: Option<Arc<dyn TemplateRenderer>>,
}

impl std::fmt::Debug for ProjectsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectsConfig")
            .field("root", &self.root)
            .field("renderer", &self.renderer.is_some())
            .finish()
    }
}

impl ProjectsConfig {
    /// `None` unless `CITRATE_HERMES_PROJECTS` is exactly `1` and a projects root is known
    /// (`CITRATE_HERMES_PROJECTS_ROOT`, absolute, or `$HOME/Citrate/Projects`). Templates need
    /// both `CITRATE_HERMES_TEMPLATE_RENDERER` and `CITRATE_HERMES_TEMPLATES_ROOT` (absolute);
    /// `sandbox` is how the renderer runs (production: the OS sandbox when there is one).
    pub fn from_env_vars(
        get: impl Fn(&str) -> Option<String>,
        sandbox: SandboxPolicy,
    ) -> Result<Option<Self>, String> {
        if get(PROJECTS_ENV).as_deref() != Some("1") {
            return Ok(None);
        }
        let root = match get(PROJECTS_ROOT_ENV).filter(|v| !v.trim().is_empty()) {
            Some(r) => {
                let p = PathBuf::from(r);
                if !p.is_absolute() {
                    return Err(format!("{PROJECTS_ROOT_ENV} must be an absolute path"));
                }
                p
            }
            None => match get("HOME").filter(|h| !h.is_empty()) {
                Some(h) => PathBuf::from(h).join(DEFAULT_PROJECTS_DIR),
                None => return Err("no home directory is known for the projects root".into()),
            },
        };
        let renderer = match (
            get(TEMPLATE_RENDERER_ENV).filter(|v| !v.is_empty()),
            get(TEMPLATES_ROOT_ENV).filter(|v| !v.is_empty()),
        ) {
            (None, None) => None,
            (Some(bin), Some(templates)) => {
                let tier = get(TEMPLATE_TIER_ENV).unwrap_or_else(|| "T0".into());
                Some(Arc::new(CliTemplateRenderer::new(
                    PathBuf::from(bin),
                    PathBuf::from(templates),
                    &tier,
                    sandbox,
                )?) as Arc<dyn TemplateRenderer>)
            }
            _ => {
                return Err(format!(
                    "templates need both {TEMPLATE_RENDERER_ENV} and {TEMPLATES_ROOT_ENV}"
                ))
            }
        };
        Ok(Some(ProjectsConfig { root, renderer }))
    }
}

/// HGW-3: renders one bundled template into an empty folder. The interface citrate-core's
/// renderer is called through: `template` is the template id, `params` its parameters, `dest`
/// the new, empty project folder. Returns the renderer's own report (JSON), shown to the model.
pub trait TemplateRenderer: Send + Sync {
    fn render(
        &self,
        template: &str,
        params: &BTreeMap<String, String>,
        dest: &Path,
    ) -> Result<serde_json::Value, String>;
}

/// The production renderer: runs citrate-core's `citrate-templates` program,
///
/// ```text
/// citrate-templates render --root <templates> --template <id> --tier <T0|T1|T2>
///                          --out <dest> [--param key=value]...
/// ```
///
/// which prints a JSON report on stdout (exit 0) or an error on stderr. It runs through the
/// shell runner: argv only, a scrubbed environment, a timeout, and (with the OS sandbox) no
/// network, writes only in `dest`, reads of the templates folder.
pub struct CliTemplateRenderer {
    runner: ShellRunner,
    program: String,
    templates: PathBuf,
    tier: String,
}

impl CliTemplateRenderer {
    pub fn new(
        bin: PathBuf,
        templates: PathBuf,
        tier: &str,
        sandbox: SandboxPolicy,
    ) -> Result<Self, String> {
        if !bin.is_absolute() || !templates.is_absolute() {
            return Err(
                "the template renderer and the templates folder must be absolute paths".into(),
            );
        }
        if !matches!(tier, "T0" | "T1" | "T2") {
            return Err(format!(
                "{TEMPLATE_TIER_ENV} must be T0, T1 or T2, not {tier:?}"
            ));
        }
        let program = bin
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or("the template renderer path names no program")?;
        let dir = bin
            .parent()
            .map(Path::to_path_buf)
            .ok_or("the template renderer path has no folder")?;
        let sandbox = sandbox.with_extra_read_roots(vec![templates.clone()]);
        let policy = ShellPolicy::new(
            Allowlist::empty().allow(&program, ArgPolicy::Any),
            vec![dir],
        )
        .map_err(|e| e.to_string())?
        .with_default_timeout(RENDER_TIMEOUT)
        .with_max_timeout(RENDER_TIMEOUT)
        .with_sandbox(sandbox);
        // The run's only writable folder is the new project (its cwd).
        let runner = ShellRunner::new(policy, |_cwd: &Path| Ok(()));
        Ok(CliTemplateRenderer {
            runner,
            program,
            templates,
            tier: tier.to_string(),
        })
    }
}

impl TemplateRenderer for CliTemplateRenderer {
    fn render(
        &self,
        template: &str,
        params: &BTreeMap<String, String>,
        dest: &Path,
    ) -> Result<serde_json::Value, String> {
        let mut args: Vec<String> = vec![
            "render".into(),
            "--root".into(),
            self.templates.display().to_string(),
            "--template".into(),
            template.into(),
            "--tier".into(),
            self.tier.clone(),
            "--out".into(),
            dest.display().to_string(),
        ];
        for (k, v) in params {
            args.push("--param".into());
            args.push(format!("{k}={v}"));
        }
        let req = RunRequest::new(&self.program, args, dest).timeout(RENDER_TIMEOUT);
        let r = self.runner.run(&req).map_err(|e| e.to_string())?;
        if !r.passed() {
            let why = r.stderr.trim();
            return Err(format!(
                "the template renderer failed (exit {:?}){}",
                r.exit_code,
                if why.is_empty() {
                    String::new()
                } else {
                    format!(": {}", clip(why, 2000))
                }
            ));
        }
        serde_json::from_str(r.stdout.trim())
            .map_err(|_| "the template renderer did not print a JSON report".to_string())
    }
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push_str("...");
        out
    }
}

/// `.citrate/project.json`: what Hermes created, where, when, and from which template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectMarker {
    pub version: u32,
    pub name: String,
    /// The canonical project folder.
    pub root: String,
    pub created_by: String,
    /// Unix seconds.
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub params: BTreeMap<String, String>,
}

/// The tool offered to the model.
pub fn project_create_spec() -> ToolSpec {
    ToolSpec {
        name: PROJECT_CREATE_TOOL.into(),
        description: "Create a new project folder in the member's projects folder, optionally from a bundled template, and get its absolute path. The member approves it first. Inside the new project you may create build files such as package.json, foundry.toml and remappings.txt with the file tools.".into(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "name": {
                    "type": "string", "maxLength": MAX_NAME_LEN,
                    "description": "The folder name: letters, digits, '.', '_' or '-', starting with a letter or digit (for example demo or my-token)."
                },
                "template": {
                    "type": "string",
                    "description": "Optional bundled template id (for example erc20 or hello-mint)."
                },
                "params": {
                    "type": "object", "additionalProperties": {"type": "string"},
                    "description": "Optional template parameters, such as name and symbol."
                }
            },
            "required": ["name"],
        }),
        host: HostKind::Sidecar,
        annotations: ToolAnnotations {
            read_only: false,
            destructive: false,
            idempotent: false,
            open_world: false,
            effect: Some(Effect::Write),
            // The result is the sidecar's own (paths and the renderer's report).
            trust: Some(Trust::Trusted),
        },
    }
}

/// Whether `name` is one plain folder name (see the module docs).
pub fn valid_name(name: &str) -> Result<(), String> {
    let refuse = |why: &str| Err(format!("the project name {name:?} {why}"));
    if name.is_empty() {
        return refuse("is empty");
    }
    if name.chars().count() > MAX_NAME_LEN {
        return refuse(&format!("is longer than {MAX_NAME_LEN} characters"));
    }
    let first = name.chars().next().unwrap_or('.');
    if !first.is_ascii_alphanumeric() {
        return refuse("must start with a letter or a digit");
    }
    if name.contains("..") {
        return refuse("may not contain '..'");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return refuse("may only use letters, digits, '.', '_' and '-' (no path separators)");
    }
    Ok(())
}

fn valid_template(id: &str) -> Result<(), String> {
    if !id.is_empty()
        && id.len() <= MAX_NAME_LEN
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        Ok(())
    } else {
        Err(format!(
            "the template id {id:?} is not a plain id (a-z, 0-9, '-')"
        ))
    }
}

/// The model's request.
struct Request {
    name: String,
    template: Option<String>,
    params: BTreeMap<String, String>,
}

fn parse(raw: &str) -> Result<Request, String> {
    let raw = if raw.trim().is_empty() { "{}" } else { raw };
    let args: serde_json::Map<String, serde_json::Value> = match serde_json::from_str(raw) {
        Ok(serde_json::Value::Object(m)) => m,
        _ => return Err("the arguments must be a JSON object".into()),
    };
    let name = match args.get("name") {
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => return Err("name (the new folder's name) is required".into()),
    };
    valid_name(&name)?;
    let template = match args.get("template") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(t)) if t.is_empty() => None,
        Some(serde_json::Value::String(t)) => {
            valid_template(t)?;
            Some(t.clone())
        }
        Some(_) => return Err("template must be a string".into()),
    };
    let mut params = BTreeMap::new();
    match args.get("params") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::Object(m)) => {
            if m.len() > MAX_PARAMS {
                return Err(format!("at most {MAX_PARAMS} template parameters"));
            }
            for (k, v) in m {
                let v = v
                    .as_str()
                    .ok_or_else(|| format!("template parameter {k} must be a string"))?;
                let key_ok = !k.is_empty()
                    && k.len() <= MAX_PARAM_LEN
                    && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                if !key_ok || v.len() > MAX_PARAM_LEN || v.contains('\0') {
                    return Err(format!(
                        "template parameter {k:?} must be a plain key with a value of at most {MAX_PARAM_LEN} bytes"
                    ));
                }
                params.insert(k.clone(), v.to_string());
            }
        }
        Some(_) => return Err("params must be an object of strings".into()),
    }
    if !params.is_empty() && template.is_none() {
        return Err("params are only for a template".into());
    }
    Ok(Request {
        name,
        template,
        params,
    })
}

/// `project_create` for one session turn.
pub struct ProjectCreateHost {
    cfg: Arc<ProjectsConfig>,
    grants: Arc<SessionGrants>,
    actions: Option<Arc<ActionApprovals>>,
    taint: TaintState,
    stop: StopFlag,
}

impl ProjectCreateHost {
    pub fn new(
        cfg: Arc<ProjectsConfig>,
        grants: Arc<SessionGrants>,
        actions: Option<Arc<ActionApprovals>>,
        taint: TaintState,
        stop: StopFlag,
    ) -> Self {
        ProjectCreateHost {
            cfg,
            grants,
            actions,
            taint,
            stop,
        }
    }

    pub fn handles(name: &str) -> bool {
        name == PROJECT_CREATE_TOOL
    }

    /// The projects root, checked against the grants now: its canonical path.
    fn checked_root(&self) -> Result<PathBuf, String> {
        let root = &self.cfg.root;
        if !root.is_dir() {
            return Err(format!(
                "the projects folder {} does not exist yet; the app creates it when the member lets Hermes work there",
                root.display()
            ));
        }
        self.grants.shell_scope(root).map(|(c, _)| c).map_err(|e| {
            format!(
                "the projects folder {} is not granted for reading and writing ({e}); the member can allow it in the app",
                root.display()
            )
        })
    }

    /// Validate, ask, then create. `reason` names why the card is shown.
    fn ask_and_create(&self, call: &ToolCall, reason: &str) -> ToolOutcome {
        if call.name != PROJECT_CREATE_TOOL {
            return ToolOutcome::Error(format!("'{}' is not project_create", call.name));
        }
        let req = match parse(&call.arguments) {
            Ok(r) => r,
            Err(e) => return ToolOutcome::Error(e),
        };
        if req.template.is_some() && self.cfg.renderer.is_none() {
            return ToolOutcome::Error(
                "this app cannot render templates from Hermes (no template renderer is configured); create the project without a template".into(),
            );
        }
        let root = match self.checked_root() {
            Ok(r) => r,
            Err(e) => return ToolOutcome::Error(e),
        };
        let dest = root.join(&req.name);
        if std::fs::symlink_metadata(&dest).is_ok() {
            return ToolOutcome::Error(format!(
                "{} already exists; pick another name (an existing folder is never reused)",
                dest.display()
            ));
        }
        let Some(actions) = &self.actions else {
            return ToolOutcome::Denied(
                "creating a project needs the member's approval, and no member can be asked in this session (it was not opened by an app that shows approval cards)".into(),
            );
        };
        let mut card = ActionPending::for_call(
            call,
            reason,
            if self.taint.is_tainted() {
                self.taint.sources().unwrap_or_default()
            } else {
                Vec::new()
            },
        );
        card.summary = match &req.template {
            Some(t) => format!(
                "create the project folder {} from the {t} template",
                dest.display()
            ),
            None => format!("create the project folder {}", dest.display()),
        };
        if let Err(why) = actions.request(card, &self.stop) {
            return ToolOutcome::Denied(why);
        }
        if self.stop.is_stopped() {
            return ToolOutcome::Denied("the session was stopped; nothing was created".into());
        }
        // Checked again: a grant revoked while the card was open stops it.
        let root = match self.checked_root() {
            Ok(r) => r,
            Err(e) => return ToolOutcome::Error(e),
        };
        let dest = root.join(&req.name);
        match self.create(&dest, &req) {
            Ok(v) => ToolOutcome::Ok(v.to_string()),
            Err(e) => ToolOutcome::Error(e),
        }
    }

    fn create(&self, dest: &Path, req: &Request) -> Result<serde_json::Value, String> {
        // `create_dir` (not `_all`): the root exists, and an existing folder is never reused.
        std::fs::create_dir(dest)
            .map_err(|e| format!("{} could not be created: {e}", dest.display()))?;
        let rendered = match (&req.template, &self.cfg.renderer) {
            (Some(t), Some(r)) => match r.render(t, &req.params, dest) {
                Ok(report) => Some(report),
                Err(e) => {
                    let _ = std::fs::remove_dir_all(dest);
                    return Err(format!(
                        "the {t} template could not be rendered, so no project was created: {e}"
                    ));
                }
            },
            _ => None,
        };
        let canonical = std::fs::canonicalize(dest).map_err(|e| e.to_string())?;
        let marker = ProjectMarker {
            version: 1,
            name: req.name.clone(),
            root: canonical.display().to_string(),
            created_by: "hermes".into(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            template: req.template.clone(),
            params: req.params.clone(),
        };
        let marker_dir = canonical.join(MARKER_DIR);
        let written = std::fs::create_dir_all(&marker_dir)
            .and_then(|()| {
                std::fs::write(
                    marker_dir.join(MARKER_FILE),
                    serde_json::to_vec_pretty(&marker).unwrap_or_default(),
                )
            })
            .map_err(|e| format!("the project marker could not be written: {e}"));
        if let Err(e) = written {
            let _ = std::fs::remove_dir_all(&canonical);
            return Err(e);
        }
        self.grants.add_project_root(&canonical)?;
        Ok(serde_json::json!({
            "ok": true,
            "tool": PROJECT_CREATE_TOOL,
            "name": req.name,
            "path": canonical,
            "template": req.template,
            "marker": marker_dir.join(MARKER_FILE),
            "rendered": rendered,
            "note": "This folder is a project: the file tools may create its build files (package.json, foundry.toml, remappings.txt, ...). Env files stay the member's.",
        }))
    }
}

impl ToolHost for ProjectCreateHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        let reason = match self.taint.record() {
            Some(r) => format!(
                "creating a project folder needs your approval, and this session read untrusted content (from {})",
                r.source
            ),
            None => "creating a project folder needs your approval".to_string(),
        };
        self.ask_and_create(call, &reason)
    }

    fn honors_explicit_approval(&self) -> bool {
        self.actions.is_some()
    }

    /// The one card is the explicit approval; it carries the loop's reason.
    fn execute_with_explicit_approval(&self, call: &ToolCall, reason: &str) -> ToolOutcome {
        self.ask_and_create(call, reason)
    }
}

/// How the renderer runs in production: the OS sandbox when this machine has one.
pub fn production_render_sandbox() -> SandboxPolicy {
    SandboxPolicy::new(SandboxMode::Preferred)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_one_plain_folder_name() {
        for ok in ["demo", "my-token", "App_2", "v1.0", "a"] {
            assert!(valid_name(ok).is_ok(), "{ok}");
        }
        for bad in [
            "", "..", "../x", "a/b", "a\\b", ".hidden", "-x", "~x", "a..b", "a b", "a;b", "é",
            "/abs",
        ] {
            assert!(valid_name(bad).is_err(), "{bad:?}");
        }
        assert!(valid_name(&"x".repeat(MAX_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn parse_checks_template_and_params() {
        assert!(parse(
            r#"{"name":"d","template":"erc20","params":{"name":"Demo","symbol":"DMO"}}"#
        )
        .is_ok());
        assert!(parse(r#"{"name":"d","template":"../x"}"#).is_err());
        assert!(
            parse(r#"{"name":"d","params":{"a":"b"}}"#).is_err(),
            "params need a template"
        );
        assert!(parse(r#"{"name":"d","template":"erc20","params":{"a b":"c"}}"#).is_err());
        assert!(parse(r#"{"name":"d","template":"erc20","params":{"a":1}}"#).is_err());
        assert!(parse(r#"{"template":"erc20"}"#).is_err());
        assert!(parse("[]").is_err());
    }

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn config_is_off_unless_the_flag_is_exactly_1_and_defaults_under_home() {
        let off = SandboxPolicy::off;
        assert!(
            ProjectsConfig::from_env_vars(vars(&[("HOME", "/h")]), off())
                .unwrap()
                .is_none()
        );
        assert!(ProjectsConfig::from_env_vars(
            vars(&[(PROJECTS_ENV, "true"), ("HOME", "/h")]),
            off()
        )
        .unwrap()
        .is_none());
        let c = ProjectsConfig::from_env_vars(vars(&[(PROJECTS_ENV, "1"), ("HOME", "/h")]), off())
            .unwrap()
            .unwrap();
        assert_eq!(c.root, PathBuf::from("/h/Citrate/Projects"));
        assert!(c.renderer.is_none());
        let c = ProjectsConfig::from_env_vars(
            vars(&[
                (PROJECTS_ENV, "1"),
                (PROJECTS_ROOT_ENV, "/w/p"),
                ("HOME", "/h"),
            ]),
            off(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(c.root, PathBuf::from("/w/p"));
        assert!(ProjectsConfig::from_env_vars(
            vars(&[
                (PROJECTS_ENV, "1"),
                (PROJECTS_ROOT_ENV, "rel"),
                ("HOME", "/h")
            ]),
            off()
        )
        .is_err());
        assert!(
            ProjectsConfig::from_env_vars(
                vars(&[
                    (PROJECTS_ENV, "1"),
                    ("HOME", "/h"),
                    (TEMPLATE_RENDERER_ENV, "/bin/r")
                ]),
                off()
            )
            .is_err(),
            "a renderer needs the templates folder too"
        );
        let c = ProjectsConfig::from_env_vars(
            vars(&[
                (PROJECTS_ENV, "1"),
                ("HOME", "/h"),
                (TEMPLATE_RENDERER_ENV, "/opt/c/citrate-templates"),
                (TEMPLATES_ROOT_ENV, "/opt/c/templates"),
            ]),
            off(),
        )
        .unwrap()
        .unwrap();
        assert!(c.renderer.is_some());
        assert!(ProjectsConfig::from_env_vars(
            vars(&[
                (PROJECTS_ENV, "1"),
                ("HOME", "/h"),
                (TEMPLATE_RENDERER_ENV, "/opt/c/citrate-templates"),
                (TEMPLATES_ROOT_ENV, "/opt/c/templates"),
                (TEMPLATE_TIER_ENV, "T9"),
            ]),
            off()
        )
        .is_err());
    }

    #[test]
    fn the_spec_is_a_trusted_sidecar_write_tool() {
        let s = project_create_spec();
        assert_eq!(s.name, PROJECT_CREATE_TOOL);
        assert_eq!(s.host, HostKind::Sidecar);
        assert_eq!(s.annotations.effect, Some(Effect::Write));
        assert_eq!(s.annotations.trust, Some(Trust::Trusted));
        assert_eq!(s.parameters["required"], serde_json::json!(["name"]));
    }
}
