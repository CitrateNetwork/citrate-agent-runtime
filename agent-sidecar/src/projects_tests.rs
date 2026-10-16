//! HGW-3 — `project_create`: a new project folder in the member's projects folder, after the
//! member approves it, optionally rendered from a bundled template, that the file tools may then
//! set up (build configuration included).
//!
//! BDD map:
//! - `project_create_asks_then_creates_the_folder_and_marker_and_the_project_is_writable`
//! - `bad_names_are_refused_before_anything_is_asked`
//! - `an_existing_folder_is_never_reused`
//! - `the_projects_root_must_exist_and_be_granted`
//! - `a_declined_card_creates_nothing`
//! - `without_an_hic_aware_app_nothing_is_created`
//! - `in_a_tainted_session_one_card_carries_the_taint_reason`
//! - `a_template_is_rendered_into_the_new_folder_and_a_failed_render_leaves_nothing`
//! - `the_cli_renderer_calls_the_program_with_the_documented_argv` (+ Seatbelt on macOS)

#![cfg(unix)]

use super::hgw_support::*;
use super::projects::*;
use super::*;
use citrate_agent_loop::AssistantTurn;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn projects_root(fx: &Fx) -> PathBuf {
    let r = fx.home().join("Projects");
    std::fs::create_dir_all(&r).expect("projects root");
    r
}

fn create_call(id: &str, args: serde_json::Value) -> citrate_agent_loop::ToolCall {
    tool_call(id, PROJECT_CREATE_TOOL, args)
}

/// One render request: the template, its parameters and the destination.
type Rendered = (String, BTreeMap<String, String>, PathBuf);

/// A renderer that writes `README.md` (and records what it was asked), or fails.
struct FakeRenderer {
    fail: bool,
    seen: std::sync::Mutex<Vec<Rendered>>,
}
impl TemplateRenderer for FakeRenderer {
    fn render(
        &self,
        template: &str,
        params: &BTreeMap<String, String>,
        dest: &Path,
    ) -> Result<serde_json::Value, String> {
        self.seen.lock().unwrap_or_else(|p| p.into_inner()).push((
            template.into(),
            params.clone(),
            dest.to_path_buf(),
        ));
        // The destination is the new, empty folder.
        assert_eq!(std::fs::read_dir(dest).map(|d| d.count()).unwrap_or(99), 0);
        std::fs::write(dest.join("README.md"), format!("# {template}\n"))
            .map_err(|e| e.to_string())?;
        if self.fail {
            return Err("unknown parameter `colour`".into());
        }
        Ok(serde_json::json!({"files": ["README.md"]}))
    }
}

struct Run {
    s: Arc<sessions::Session>,
    answered: Vec<Answered>,
}

async fn run(
    fx: &Fx,
    calls: Vec<citrate_agent_loop::ToolCall>,
    cfg: ProjectsConfig,
    roots: &[PathBuf],
    hic_aware: bool,
    decide: impl Fn(&'static str, &serde_json::Value) -> bool,
) -> Run {
    let mut turns: Vec<AssistantTurn> = calls
        .into_iter()
        .map(|c| AssistantTurn::tools(vec![c]))
        .collect();
    turns.push(AssistantTurn::text("ok"));
    let mgr = Arc::new(manager_with(fx, turns, Some(shell_open())).with_projects(Arc::new(cfg)));
    let id = mgr
        .create(create_req(fx.rw_doc_for(roots), hic_aware))
        .expect("session");
    let s = mgr.get(&id).expect("session");
    let app = app_for(mgr.clone());
    mgr.send(&id, "make a project".into(), None).expect("send");
    let answered = member_answers(&app, &s, &id, decide).await;
    Run { s, answered }
}

fn plain(root: PathBuf) -> ProjectsConfig {
    ProjectsConfig {
        root,
        renderer: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn project_create_asks_then_creates_the_folder_and_marker_and_the_project_is_writable() {
    let fx = Fx::new("pc-create");
    let root = projects_root(&fx);
    let demo = root.join("demo");
    let demo_shown = demo.clone();
    let r = run(
        &fx,
        vec![
            create_call("c1", serde_json::json!({"name": "demo"})),
            fs_write("c2", &demo.join("package.json"), "{\"name\":\"demo\"}\n"),
        ],
        plain(root.clone()),
        std::slice::from_ref(&root),
        true,
        move |route, card| {
            if route == "actions" {
                assert!(
                    !demo_shown.exists(),
                    "nothing is created before the member decides"
                );
            }
            let _ = card;
            true
        },
    )
    .await;
    assert_eq!(r.answered.len(), 1, "{:?}", r.answered);
    let card = &r.answered[0].card;
    assert_eq!(card["tool"], PROJECT_CREATE_TOOL);
    assert!(
        card["summary"]
            .as_str()
            .unwrap_or_default()
            .contains(&demo.display().to_string()),
        "the card shows the exact folder: {card}"
    );
    let res = result_of(&r.s, "c1").await;
    assert_eq!(res["status"], "ok", "{res}");
    let body: serde_json::Value =
        serde_json::from_str(res["content"].as_str().unwrap_or_default()).expect("json");
    assert_eq!(body["path"], serde_json::json!(demo));
    assert!(demo.is_dir());
    let marker: ProjectMarker =
        serde_json::from_slice(&std::fs::read(demo.join(".citrate/project.json")).expect("marker"))
            .expect("marker json");
    assert_eq!(marker.name, "demo");
    assert_eq!(marker.root, demo.display().to_string());
    assert_eq!(marker.created_by, "hermes");
    // The new folder is a project root: its build configuration is the agent's to write.
    assert_eq!(result_of(&r.s, "c2").await["status"], "ok");
    assert!(demo.join("package.json").is_file());
    assert_eq!(r.s.grants().expect("grants").project_roots(), vec![demo]);
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_names_are_refused_before_anything_is_asked() {
    let fx = Fx::new("pc-names");
    let root = projects_root(&fx);
    let long = "x".repeat(65);
    let names = ["../escape", "a/b", ".hidden", "", "..", long.as_str()];
    let calls = names
        .iter()
        .enumerate()
        .map(|(i, n)| create_call(&format!("c{i}"), serde_json::json!({ "name": n })))
        .collect();
    let r = run(
        &fx,
        calls,
        plain(root.clone()),
        std::slice::from_ref(&root),
        true,
        |_, _| true,
    )
    .await;
    assert!(r.answered.is_empty(), "{:?}", r.answered);
    for i in 0..names.len() {
        let res = result_of(&r.s, &format!("c{i}")).await;
        assert_eq!(res["status"], "error", "{res}");
    }
    assert!(!fx.home().join("escape").exists());
    assert_eq!(std::fs::read_dir(&root).expect("root").count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_existing_folder_is_never_reused() {
    let fx = Fx::new("pc-exists");
    let root = projects_root(&fx);
    std::fs::create_dir_all(root.join("demo")).expect("existing");
    std::fs::write(root.join("demo/keep.txt"), "mine").expect("keep");
    let r = run(
        &fx,
        vec![create_call("c1", serde_json::json!({"name": "demo"}))],
        plain(root.clone()),
        std::slice::from_ref(&root),
        true,
        |_, _| true,
    )
    .await;
    assert!(r.answered.is_empty());
    let res = result_of(&r.s, "c1").await;
    assert!(
        res["content"]
            .as_str()
            .unwrap_or_default()
            .contains("already exists"),
        "{res}"
    );
    assert!(!root.join("demo/.citrate").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_projects_root_must_exist_and_be_granted() {
    let fx = Fx::new("pc-root");
    let missing = fx.home().join("NotThere");
    let r = run(
        &fx,
        vec![create_call("c1", serde_json::json!({"name": "demo"}))],
        plain(missing.clone()),
        &[fx.proj()],
        true,
        |_, _| true,
    )
    .await;
    let res = result_of(&r.s, "c1").await;
    assert!(
        res["content"]
            .as_str()
            .unwrap_or_default()
            .contains("does not exist"),
        "{res}"
    );
    assert!(!missing.exists());
    // Exists, but is not granted.
    let root = projects_root(&fx);
    let r = run(
        &fx,
        vec![create_call("c1", serde_json::json!({"name": "demo"}))],
        plain(root.clone()),
        &[fx.proj()],
        true,
        |_, _| true,
    )
    .await;
    let res = result_of(&r.s, "c1").await;
    assert!(
        res["content"]
            .as_str()
            .unwrap_or_default()
            .contains("not granted"),
        "{res}"
    );
    assert!(r.answered.is_empty());
    assert!(!root.join("demo").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declined_card_creates_nothing() {
    let fx = Fx::new("pc-decline");
    let root = projects_root(&fx);
    let r = run(
        &fx,
        vec![create_call("c1", serde_json::json!({"name": "demo"}))],
        plain(root.clone()),
        std::slice::from_ref(&root),
        true,
        |_, _| false,
    )
    .await;
    assert_eq!(r.answered.len(), 1);
    assert_eq!(result_of(&r.s, "c1").await["status"], "denied");
    assert!(!root.join("demo").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn without_an_hic_aware_app_nothing_is_created() {
    let fx = Fx::new("pc-headless");
    let root = projects_root(&fx);
    let r = run(
        &fx,
        vec![create_call("c1", serde_json::json!({"name": "demo"}))],
        plain(root.clone()),
        std::slice::from_ref(&root),
        false,
        |_, _| true,
    )
    .await;
    let res = result_of(&r.s, "c1").await;
    assert_eq!(res["status"], "denied", "{res}");
    assert!(res["content"]
        .as_str()
        .unwrap_or_default()
        .contains("no member can be asked"));
    assert!(!root.join("demo").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn in_a_tainted_session_one_card_carries_the_taint_reason() {
    let fx = Fx::new("pc-taint");
    let root = projects_root(&fx);
    let r = run(
        &fx,
        vec![
            shell("c0", &["echo", "x"], &root),
            create_call("c1", serde_json::json!({"name": "demo"})),
        ],
        plain(root.clone()),
        std::slice::from_ref(&root),
        true,
        |_, _| true,
    )
    .await;
    let actions: Vec<&Answered> = r.answered.iter().filter(|a| a.route == "actions").collect();
    assert_eq!(actions.len(), 1, "one card, not two: {:?}", r.answered);
    let reason = actions[0].card["hicReason"].as_str().unwrap_or_default();
    assert!(reason.contains("shell_run"), "{reason}");
    assert_eq!(result_of(&r.s, "c1").await["status"], "ok");
    assert!(root.join("demo/.citrate/project.json").is_file());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_template_is_rendered_into_the_new_folder_and_a_failed_render_leaves_nothing() {
    let fx = Fx::new("pc-template");
    let root = projects_root(&fx);
    let ok = Arc::new(FakeRenderer {
        fail: false,
        seen: Default::default(),
    });
    let r = run(
        &fx,
        vec![create_call(
            "c1",
            serde_json::json!({"name": "tok", "template": "erc20", "params": {"name": "Demo", "symbol": "DMO"}}),
        )],
        ProjectsConfig {
            root: root.clone(),
            renderer: Some(ok.clone()),
        },
        std::slice::from_ref(&root),
        true,
        |_, _| true,
    )
    .await;
    let res = result_of(&r.s, "c1").await;
    assert_eq!(res["status"], "ok", "{res}");
    assert!(r.answered[0].card["summary"]
        .as_str()
        .unwrap_or_default()
        .contains("erc20"));
    let seen = ok.seen.lock().expect("seen").clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "erc20");
    assert_eq!(seen[0].1.get("symbol").map(String::as_str), Some("DMO"));
    assert_eq!(seen[0].2, root.join("tok"));
    assert!(root.join("tok/README.md").is_file());
    let marker: ProjectMarker =
        serde_json::from_slice(&std::fs::read(root.join("tok/.citrate/project.json")).expect("m"))
            .expect("marker");
    assert_eq!(marker.template.as_deref(), Some("erc20"));
    // A render that fails removes the new folder and says why.
    let bad = Arc::new(FakeRenderer {
        fail: true,
        seen: Default::default(),
    });
    let r = run(
        &fx,
        vec![create_call(
            "c1",
            serde_json::json!({"name": "broken", "template": "erc20"}),
        )],
        ProjectsConfig {
            root: root.clone(),
            renderer: Some(bad),
        },
        std::slice::from_ref(&root),
        true,
        |_, _| true,
    )
    .await;
    let res = result_of(&r.s, "c1").await;
    assert_eq!(res["status"], "error", "{res}");
    assert!(
        res["content"]
            .as_str()
            .unwrap_or_default()
            .contains("colour"),
        "{res}"
    );
    assert!(!root.join("broken").exists());
    // Without a renderer a template is refused before asking.
    let r = run(
        &fx,
        vec![create_call(
            "c1",
            serde_json::json!({"name": "t2", "template": "erc20"}),
        )],
        plain(root.clone()),
        std::slice::from_ref(&root),
        true,
        |_, _| true,
    )
    .await;
    assert!(r.answered.is_empty());
    assert!(!root.join("t2").exists());
}

/// A stand-in for citrate-core's `citrate-templates` program: records its argv and writes a file.
fn fake_cli(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let bin = dir.join("citrate-templates");
    std::fs::write(
        &bin,
        "#!/bin/sh\nout=''\nprev=''\nfor a in \"$@\"; do if [ \"$prev\" = --out ]; then out=\"$a\"; fi; prev=\"$a\"; done\nprintf '%s\\n' \"$@\" > \"$out/argv.txt\"\necho '{\"files\":[\"argv.txt\"]}'\n",
    )
    .expect("script");
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    bin
}

fn check_cli(sandbox: citrate_agent_shell::sandbox::SandboxPolicy) {
    let fx = Fx::new("pc-cli");
    let tools = fx.base.join("app");
    let templates = tools.join("templates");
    std::fs::create_dir_all(&templates).expect("templates");
    let bin = fake_cli(&tools);
    let dest = fx.proj().join("new");
    std::fs::create_dir(&dest).expect("dest");
    let r = CliTemplateRenderer::new(bin, templates.clone(), "T1", sandbox).expect("renderer");
    let mut params = BTreeMap::new();
    params.insert("name".to_string(), "Demo".to_string());
    let report = r.render("erc20", &params, &dest).expect("render");
    assert_eq!(report["files"], serde_json::json!(["argv.txt"]));
    let argv = std::fs::read_to_string(dest.join("argv.txt")).expect("argv");
    let lines: Vec<&str> = argv.lines().collect();
    assert_eq!(
        lines,
        vec![
            "render",
            "--root",
            &templates.display().to_string(),
            "--template",
            "erc20",
            "--tier",
            "T1",
            "--out",
            &dest.display().to_string(),
            "--param",
            "name=Demo",
        ]
    );
}

#[test]
fn the_cli_renderer_calls_the_program_with_the_documented_argv() {
    check_cli(citrate_agent_shell::sandbox::SandboxPolicy::off());
}

#[cfg(target_os = "macos")]
#[test]
fn the_cli_renderer_runs_under_seatbelt_and_writes_only_the_new_folder() {
    use citrate_agent_shell::sandbox::{SandboxMode, SandboxPolicy};
    check_cli(SandboxPolicy::new(SandboxMode::Required));
}
