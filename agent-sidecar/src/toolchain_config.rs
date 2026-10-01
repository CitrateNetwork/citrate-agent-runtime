//! Project build configuration checks for the toolchain tools.
//!
//! The toolchain runs with a fixed argv and a scrubbed environment, but the programs also read
//! configuration from the project itself. Forge does not take `ffi` or `fs_permissions` from the
//! environment, and has no flag that turns them off, so a project whose configuration asks for
//! more than the agent toolchain allows is refused before anything runs, with the reason. The
//! member reviews and changes such configuration; the agent toolchain never runs with it.
//!
//! Checked, in the project folder (and, for `foundry.toml`, the nearest one above it, which is
//! the one forge uses when the project has none):
//!
//! * `foundry.toml`, every profile: `ffi` must be absent or `false`; each `fs_permissions` entry
//!   must be `read` (or `none`) on a relative path inside the project; `solc` / `solc_version`
//!   must be a version number, not a program path. A file that does not parse is refused.
//! * `.env` and `.env.*`: forge loads them into its own environment, so they are refused.
//! * `slither.config.json`, `medusa.json`, `hardhat.config.*`, `truffle-config.*`, `truffle.js`:
//!   settings for other build front ends; refused while present (pending owner review of a
//!   narrower rule).
//!
//! Nothing here returns file contents to the model: a refusal names the file and the setting.
//!
//! [`build_config_file`] is the matching rule for the agent's file tools: build configuration
//! (the files above, plus `foundry.toml`, `remappings.txt`, `package.json`, `aderyn.toml`,
//! make/just files and `.cargo/config*`) is edited by the member, never created, changed, moved
//! or removed by the agent.

use std::path::{Component, Path, PathBuf};

/// Largest `foundry.toml` this check reads.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

const FOUNDRY_TOML: &str = "foundry.toml";

/// Whether `name` (a file name, any case) is a build front-end config the toolchain refuses to
/// run beside.
fn other_build_config(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "slither.config.json"
        || n == "medusa.json"
        || n == "truffle.js"
        || n.starts_with("hardhat.config.")
        || n.starts_with("truffle-config.")
}

/// Whether `name` (any case) is an env file forge would load.
fn env_file(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == ".env" || n.starts_with(".env.")
}

/// Whether `path` names build configuration the agent's file tools leave to the member. Returns
/// the file name for the refusal. Matching is on the last component, any case.
pub(crate) fn build_config_file(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().into_owned();
    let n = name.to_ascii_lowercase();
    let in_cargo_dir = path
        .parent()
        .and_then(|p| p.file_name())
        .is_some_and(|d| d.eq_ignore_ascii_case(".cargo"));
    let hit = env_file(&n)
        || other_build_config(&n)
        || matches!(
            n.as_str(),
            "foundry.toml"
                | "remappings.txt"
                | "package.json"
                | "aderyn.toml"
                | "makefile"
                | "gnumakefile"
                | "justfile"
        )
        || (in_cargo_dir && n.starts_with("config"));
    hit.then_some(name)
}

/// The refusal the file tools give for [`build_config_file`].
pub(crate) fn build_config_refusal(name: &str) -> String {
    format!(
        "{name} is build configuration, which the member edits; the agent's file tools do not create, change, move or remove it"
    )
}

/// Refuse (with the reason) when the project's build configuration asks for more than the agent
/// toolchain allows. `project` is the canonical project folder.
pub(crate) fn check_project_config(project: &Path) -> Result<(), String> {
    check_folder_entries(project)?;
    if let Some(dir) = nearest_foundry_dir(project)? {
        if dir != project {
            check_folder_entries(&dir)?;
        }
        check_foundry_toml(&dir.join(FOUNDRY_TOML))?;
    }
    Ok(())
}

fn check_folder_entries(dir: &Path) -> Result<(), String> {
    let rd = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot check the project folder {}: {e}", dir.display()))?;
    let mut names: Vec<String> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    for name in names {
        if env_file(&name) {
            return Err(format!(
                "the project has a {name} file, which forge loads into its environment; the agent toolchain does not run beside env files. The member can review and move it, then try again"
            ));
        }
        if other_build_config(&name) {
            return Err(format!(
                "the project has {name}, a build configuration the agent toolchain does not run with; the member can review and remove it, then try again"
            ));
        }
    }
    Ok(())
}

/// The folder whose `foundry.toml` forge would use: the project or its nearest ancestor that has
/// one. `None` when there is none (forge then uses its defaults).
fn nearest_foundry_dir(project: &Path) -> Result<Option<PathBuf>, String> {
    for dir in project.ancestors() {
        match std::fs::symlink_metadata(dir.join(FOUNDRY_TOML)) {
            Ok(_) => return Ok(Some(dir.to_path_buf())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(format!(
                    "cannot check {}: {e}",
                    dir.join(FOUNDRY_TOML).display()
                ))
            }
        }
    }
    Ok(None)
}

fn check_foundry_toml(path: &Path) -> Result<(), String> {
    let shown = path.display();
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("cannot check {shown}: {e}"))?;
    if !meta.file_type().is_file() {
        return Err(format!(
            "{shown} is not a regular file, so the agent toolchain does not run with it"
        ));
    }
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(format!(
            "{shown} is larger than {MAX_CONFIG_BYTES} bytes, so it was not checked and nothing ran"
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    let value: toml::Value = toml::from_str(&text).map_err(|_| {
        format!("{shown} could not be parsed as TOML, so it was not checked and nothing ran")
    })?;
    check_table_value(&value, "", &shown.to_string())
}

/// Walk every table (all profiles and their sub-tables).
fn check_table_value(v: &toml::Value, at: &str, file: &str) -> Result<(), String> {
    match v {
        toml::Value::Table(t) => {
            for (k, val) in t {
                let here = if at.is_empty() {
                    k.clone()
                } else {
                    format!("{at}.{k}")
                };
                match k.replace('-', "_").as_str() {
                    "ffi" => {
                        if val.as_bool() != Some(false) {
                            return Err(format!(
                                "{file} turns on ffi ({here}), which lets tests run programs on this machine; the agent toolchain does not run with it. The member can set it to false, then try again"
                            ));
                        }
                    }
                    "fs_permissions" => check_fs_permissions(val, &here, file)?,
                    "solc" | "solc_version" => {
                        if !val.as_str().is_some_and(version_like) {
                            return Err(format!(
                                "{file} sets the compiler ({here}) to something other than a version number; the agent toolchain only runs with the configured compiler"
                            ));
                        }
                    }
                    _ => check_table_value(val, &here, file)?,
                }
            }
            Ok(())
        }
        toml::Value::Array(items) => {
            for item in items {
                check_table_value(item, at, file)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// `0.8.36`, optionally prefixed by `=` or `^`.
fn version_like(s: &str) -> bool {
    let s = s.trim_start_matches(['=', '^']);
    !s.is_empty()
        && s.split('.').count() <= 3
        && s.split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn check_fs_permissions(v: &toml::Value, at: &str, file: &str) -> Result<(), String> {
    let refuse = || {
        Err(format!(
            "{file} sets fs_permissions ({at}) beyond reading inside the project; the agent toolchain only runs with read access to project paths. The member can narrow it, then try again"
        ))
    };
    let Some(items) = v.as_array() else {
        return refuse();
    };
    for item in items {
        let Some(t) = item.as_table() else {
            return refuse();
        };
        let access_ok = match t.get("access") {
            Some(toml::Value::String(a)) => a == "read" || a == "none",
            Some(toml::Value::Boolean(b)) => !b,
            _ => false,
        };
        let path_ok = t
            .get("path")
            .and_then(|p| p.as_str())
            .is_some_and(project_relative);
        if !access_ok || !path_ok {
            return refuse();
        }
    }
    Ok(())
}

/// A relative path that stays inside the project (no root, no `..`, no `~`).
fn project_relative(p: &str) -> bool {
    if p.trim().is_empty() || p.starts_with('~') {
        return false;
    }
    Path::new(p)
        .components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}
