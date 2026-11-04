//! CORE-A2 (r1007 planset, 03 CORE-A): the `agent-chain` crate's tools (`deploy_contract`,
//! `query_contract`, `explain_tx`, `check_balance`, `send_tx`, `run_inference`, ...) answered
//! every call by echoing its arguments back, and nothing in the federation depended on them
//! (Rule 1: no stubs in production paths). The crate is retired; chain reads and decoding live in
//! Citrate Core's agent tools (citrate-core `src-tauri/src/contract_intel.rs`).
//!
//! These tripwires keep it retired: the crate is not a workspace member, and no workspace source
//! defines an `AgentTool` under one of the retired echo tools' names.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(".."))
}

/// The `members = [...]` entries of the workspace manifest.
fn workspace_members() -> Vec<String> {
    let manifest =
        std::fs::read_to_string(workspace_root().join("Cargo.toml")).expect("workspace Cargo.toml");
    let start = manifest.find("members = [").expect("a members list");
    let rest = &manifest[start + "members = [".len()..];
    let end = rest.find(']').expect("the members list closes");
    rest[..end]
        .lines()
        .map(|l| {
            l.split('#')
                .next()
                .unwrap_or("")
                .trim()
                .trim_end_matches(',')
                .trim_matches('"')
                .to_string()
        })
        .filter(|l| !l.is_empty())
        .collect()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "target" || n == "tests") {
                continue;
            }
            rust_sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn the_echo_only_agent_chain_crate_is_not_a_workspace_member() {
    let members = workspace_members();
    assert!(
        members.len() > 5,
        "could not read the workspace members: {members:?}"
    );
    assert!(
        !members.iter().any(|m| m == "agent-chain"),
        "agent-chain is a workspace member again; its tools echoed their inputs (Rule 1)"
    );
    assert!(
        !workspace_root().join("agent-chain").exists(),
        "the agent-chain directory is back"
    );
}

#[test]
fn no_workspace_crate_defines_a_retired_echo_tool() {
    const RETIRED: [&str; 7] = [
        "check_balance",
        "send_tx",
        "deploy_contract",
        "query_contract",
        "list_models",
        "run_inference",
        "explain_tx",
    ];
    let mut files = Vec::new();
    for m in workspace_members() {
        rust_sources(&workspace_root().join(&m).join("src"), &mut files);
    }
    assert!(!files.is_empty());
    let mut offenders = Vec::new();
    for f in files {
        let src = std::fs::read_to_string(&f).unwrap_or_default();
        for name in RETIRED {
            if src.contains(&format!("fn name(&self) -> &str {{ \"{name}\" }}")) {
                offenders.push(format!("{}: {name}", f.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a retired echo tool is defined again (give it a real data source and a new name, or delete it): {offenders:?}"
    );
}
