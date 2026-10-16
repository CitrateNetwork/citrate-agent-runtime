//! HGW-2 — project write policy: inside a project root, Hermes's file tools may create and change
//! build configuration (`package.json`, `foundry.toml`, `remappings.txt`, `tsconfig.json`, …);
//! everywhere else the member still edits it. `.env*` files stay the member's everywhere, and the
//! file tools never write inside `.git/` (git itself does, through the sandboxed `shell_run`).
//!
//! A project root is a folder citrate-core names in `projectRoots` when it opens the session (a
//! project Hermes created earlier, or a folder the member marked as a project) or one this
//! session's `project_create` made. A marker file alone never makes a folder a project.
//!
//! BDD map:
//! - `build_config_is_writable_inside_a_project_root_and_nowhere_else`
//! - `env_files_stay_the_members_even_inside_a_project`
//! - `a_marker_file_alone_does_not_make_a_project`
//! - `the_file_tools_never_write_inside_git`
//! - `project_roots_must_be_absolute_existing_folders_inside_the_grants`

#![cfg(unix)]

use super::hgw_support::*;
use super::*;
use citrate_agent_loop::AssistantTurn;

fn file_write(id: &str, path: &std::path::Path, content: &str) -> citrate_agent_loop::ToolCall {
    tool_call(
        id,
        grants::FILE_WRITE_TOOL,
        serde_json::json!({ "path": path, "content": content }),
    )
}

async fn run_calls(
    fx: &Fx,
    calls: Vec<citrate_agent_loop::ToolCall>,
    extra: serde_json::Value,
    roots: &[std::path::PathBuf],
) -> Vec<serde_json::Value> {
    let ids: Vec<String> = calls.iter().map(|c| c.id.clone()).collect();
    let mut turns: Vec<AssistantTurn> = calls
        .into_iter()
        .map(|c| AssistantTurn::tools(vec![c]))
        .collect();
    turns.push(AssistantTurn::text("ok"));
    let mgr = Arc::new(manager_with(fx, turns, None));
    let id = mgr
        .create(create_req_with(fx.rw_doc_for(roots), true, extra).expect("req"))
        .expect("session");
    let s = mgr.get(&id).expect("session");
    mgr.send(&id, "go".into(), None).expect("send");
    let mut out = Vec::new();
    for c in ids {
        out.push(result_of(&s, &c).await);
    }
    wait_done(&s).await;
    out
}

fn content(r: &serde_json::Value) -> String {
    r["content"].as_str().unwrap_or_default().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn build_config_is_writable_inside_a_project_root_and_nowhere_else() {
    let fx = Fx::new("proj-config");
    let proj = fx.proj();
    let other = fx.other();
    let res = run_calls(
        &fx,
        vec![
            fs_write("c1", &proj.join("package.json"), "{\"name\":\"demo\"}\n"),
            file_write("c2", &proj.join("foundry.toml"), "[profile.default]\n"),
            fs_write(
                "c3",
                &proj.join("remappings.txt"),
                "forge-std/=lib/forge-std/src/\n",
            ),
            fs_write("c4", &proj.join("tsconfig.json"), "{}\n"),
            fs_write("c5", &proj.join("src/Makefile"), "all:\n"),
            fs_write("c6", &other.join("package.json"), "{}\n"),
            file_write("c7", &other.join("foundry.toml"), "x\n"),
        ],
        serde_json::json!({ "projectRoots": [proj] }),
        &[proj.clone(), other.clone()],
    )
    .await;
    for (i, r) in res.iter().take(5).enumerate() {
        assert_eq!(r["status"], "ok", "call {}: {r}", i + 1);
    }
    assert_eq!(
        std::fs::read_to_string(proj.join("package.json")).expect("package.json"),
        "{\"name\":\"demo\"}\n"
    );
    assert!(proj.join("foundry.toml").exists());
    assert!(proj.join("remappings.txt").exists());
    for r in &res[5..] {
        assert_ne!(r["status"], "ok", "{r}");
        let c = content(r);
        assert!(c.contains("build configuration"), "{c}");
        assert!(c.contains("project"), "the refusal points at projects: {c}");
    }
    assert!(!other.join("package.json").exists());
    assert!(!other.join("foundry.toml").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn without_project_roots_build_config_is_refused_as_before() {
    let fx = Fx::new("proj-none");
    let proj = fx.proj();
    let res = run_calls(
        &fx,
        vec![fs_write("c1", &proj.join("package.json"), "{}\n")],
        serde_json::json!({}),
        std::slice::from_ref(&proj),
    )
    .await;
    assert_ne!(res[0]["status"], "ok");
    assert!(content(&res[0]).contains("build configuration"));
    assert!(!proj.join("package.json").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn env_files_stay_the_members_even_inside_a_project() {
    let fx = Fx::new("proj-env");
    let proj = fx.proj();
    let res = run_calls(
        &fx,
        vec![
            fs_write("c1", &proj.join(".env"), "KEY=1\n"),
            file_write("c2", &proj.join(".env.local"), "KEY=1\n"),
        ],
        serde_json::json!({ "projectRoots": [proj] }),
        std::slice::from_ref(&proj),
    )
    .await;
    for r in &res {
        assert_ne!(r["status"], "ok", "{r}");
    }
    assert!(!proj.join(".env").exists());
    assert!(!proj.join(".env.local").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_marker_file_alone_does_not_make_a_project() {
    let fx = Fx::new("proj-marker");
    let other = fx.other();
    std::fs::create_dir_all(other.join(".citrate")).expect("marker dir");
    std::fs::write(
        other.join(".citrate/project.json"),
        serde_json::json!({"version": 1, "name": "other", "root": other}).to_string(),
    )
    .expect("marker");
    let res = run_calls(
        &fx,
        vec![fs_write("c1", &other.join("package.json"), "{}\n")],
        serde_json::json!({ "projectRoots": [fx.proj()] }),
        &[fx.proj(), other.clone()],
    )
    .await;
    assert_ne!(res[0]["status"], "ok", "{}", res[0]);
    assert!(!other.join("package.json").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_file_tools_never_write_inside_git() {
    let fx = Fx::new("proj-git");
    let proj = fx.proj();
    std::fs::create_dir_all(proj.join(".git/hooks")).expect("git dir");
    let res = run_calls(
        &fx,
        vec![
            fs_write("c1", &proj.join(".git/hooks/pre-commit"), "#!/bin/sh\n"),
            file_write("c2", &proj.join(".git/config"), "[core]\n"),
            fs_write("c3", &fx.other().join(".git/HEAD"), "ref: x\n"),
        ],
        serde_json::json!({ "projectRoots": [proj] }),
        &[proj.clone(), fx.other()],
    )
    .await;
    for r in &res {
        assert_ne!(r["status"], "ok", "{r}");
        assert!(content(r).contains(".git"), "{r}");
    }
    assert!(!proj.join(".git/hooks/pre-commit").exists());
    assert!(!proj.join(".git/config").exists());
}

#[test]
fn project_roots_must_be_absolute_existing_folders_inside_the_grants() {
    let fx = Fx::new("proj-roots");
    let mgr = manager_with(&fx, vec![], None);
    let doc = fx.rw_doc();
    for bad in [
        serde_json::json!(["relative/dir"]),
        serde_json::json!([fx.proj().join("missing")]),
        serde_json::json!([fx.other()]),
    ] {
        let req = create_req_with(
            doc.clone(),
            true,
            serde_json::json!({ "projectRoots": bad }),
        )
        .expect("req");
        assert!(
            matches!(mgr.create(req), Err(sessions::SessionError::Invalid(_))),
            "{bad}"
        );
    }
    // Without a grant document there are no project roots.
    let mut req = create_req_with(
        serde_json::Value::Null,
        true,
        serde_json::json!({ "projectRoots": [fx.proj()] }),
    )
    .expect("req");
    req.grants = None;
    assert!(matches!(
        mgr.create(req),
        Err(sessions::SessionError::Invalid(_))
    ));
    let ok = create_req_with(
        doc,
        true,
        serde_json::json!({ "projectRoots": [fx.proj()] }),
    )
    .expect("req");
    let id = mgr
        .create(ok)
        .expect("a granted, existing project root is accepted");
    let s = mgr.get(&id).expect("session");
    assert_eq!(s.grants().expect("grants").project_roots(), vec![fx.proj()]);
}
