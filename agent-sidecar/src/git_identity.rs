//! HGW (owner decision 2026-10-15): who a commit made through `shell_run` names, and the
//! `Co-authored-by: Hermes` trailer it carries.
//!
//! - **Author and committer** are the member's: the identity the app passes
//!   ([`GIT_USER_NAME_ENV`] + [`GIT_USER_EMAIL_ENV`], both set and valid), else the member's own
//!   global git config (`user.name` / `user.email`, read once with the real git outside the
//!   sandbox, [`member_git_config_identity`]), else `Hermes <hermes@citrate.invalid>`. They reach
//!   git as `GIT_AUTHOR_*` / `GIT_COMMITTER_*`, which outrank every git config file.
//! - **The trailer**: `git commit` gets `--trailer "Co-authored-by: Hermes <…>"` added after the
//!   subcommand, and command-scope config (which outranks the repository's) keeps git adding it
//!   (`trailer.ifmissing = add`, …) and keeps the comment character `#`.
//! - **Not the model's to change**, so these are refused before the member is asked, saying why:
//!   `-c` / `--config-env` for `user.*`, `author.*`, `committer.*`, `trailer.*`, `include*`,
//!   `core.commentChar` / `core.commentString`, `commit.cleanup`; and in `git commit`,
//!   `--author`, `--cleanup`, `-C` / `-c` / `--reuse-message` / `--reedit-message` (which reuse
//!   another commit's author); and `git commit-tree`. Trailer config a run writes into the
//!   repository is reverted after it ([`citrate_agent_shell`]'s git-state pass).
//!
//! Honest scope: a commit made by another git subcommand (`merge`, `cherry-pick`, `revert`,
//! `am`) carries the member's identity but no trailer; a program other than git (for example a
//! member-approved `sh -c "git commit"`) gets neither. A repository whose config, from before the
//! run, aliases another trailer token to `Co-authored-by` with its own `ifMissing` can still
//! suppress the trailer.

use std::path::{Path, PathBuf};

/// The fallback author and committer.
pub const GIT_AGENT_NAME: &str = "Hermes";
pub const GIT_AGENT_EMAIL: &str = "hermes@citrate.invalid";
/// The trailer every `git commit` through `shell_run` carries.
pub const HERMES_CO_AUTHOR_TRAILER: &str = "Co-authored-by: Hermes <hermes@citrate.invalid>";
/// The member's commit identity, passed by the app (citrate-core). Both must be set.
pub const GIT_USER_NAME_ENV: &str = "CITRATE_HERMES_GIT_USER_NAME";
pub const GIT_USER_EMAIL_ENV: &str = "CITRATE_HERMES_GIT_USER_EMAIL";
/// Longest name or address used.
const MAX_IDENTITY_BYTES: usize = 256;

/// Where a [`GitIdentity`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySource {
    /// Passed by the app.
    App,
    /// The member's own global git config.
    MemberGitConfig,
    /// Neither was set: Hermes.
    Hermes,
}

/// The author and committer of commits made through `shell_run`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitIdentity {
    pub name: String,
    pub email: String,
    pub source: IdentitySource,
}

impl GitIdentity {
    /// A plain name (no control characters, no `<` or `>`) and a plain address (`local@domain`,
    /// no spaces), each at most 256 bytes.
    pub fn new(name: &str, email: &str, source: IdentitySource) -> Result<Self, String> {
        let name = name.trim();
        let email = email.trim();
        let plain = |s: &str| !s.chars().any(|c| c.is_control() || c == '<' || c == '>');
        if name.is_empty() || name.len() > MAX_IDENTITY_BYTES || !plain(name) {
            return Err(
                "the git user name must be 1 to 256 bytes with no <, > or control characters"
                    .into(),
            );
        }
        let address = email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty());
        if email.len() > MAX_IDENTITY_BYTES
            || !address
            || !plain(email)
            || email.chars().any(char::is_whitespace)
        {
            return Err("the git user email must be an address (local@domain) of at most 256 bytes, with no spaces, <, > or control characters".into());
        }
        Ok(GitIdentity {
            name: name.to_string(),
            email: email.to_string(),
            source,
        })
    }

    pub fn hermes() -> Self {
        GitIdentity {
            name: GIT_AGENT_NAME.into(),
            email: GIT_AGENT_EMAIL.into(),
            source: IdentitySource::Hermes,
        }
    }

    /// The app's identity when valid, else the member's git config's (asked only then), else
    /// Hermes.
    pub fn resolve(
        app: Option<(String, String)>,
        member_git_config: impl FnOnce() -> Option<(String, String)>,
    ) -> Self {
        if let Some(id) = app.and_then(|(n, e)| Self::new(&n, &e, IdentitySource::App).ok()) {
            return id;
        }
        member_git_config()
            .and_then(|(n, e)| Self::new(&n, &e, IdentitySource::MemberGitConfig).ok())
            .unwrap_or_else(Self::hermes)
    }

    /// The variables a git run gets.
    pub(crate) fn env(&self) -> [(&'static str, &str); 4] {
        [
            ("GIT_AUTHOR_NAME", self.name.as_str()),
            ("GIT_AUTHOR_EMAIL", self.email.as_str()),
            ("GIT_COMMITTER_NAME", self.name.as_str()),
            ("GIT_COMMITTER_EMAIL", self.email.as_str()),
        ]
    }
}

/// The member's `user.name` and `user.email` from their global git config (`~/.gitconfig`,
/// `~/.config/git/config`), read with the first `git` on `search_path`, outside the sandbox, with
/// an empty environment but `HOME` (no system config, no repository). `None` unless both are set.
pub fn member_git_config_identity(
    search_path: &[PathBuf],
    home: &Path,
) -> Option<(String, String)> {
    let exe = if cfg!(windows) { "git.exe" } else { "git" };
    let git = search_path
        .iter()
        .map(|d| d.join(exe))
        .find(|p| p.is_file())?;
    let get = |key: &str| -> Option<String> {
        let mut cmd = std::process::Command::new(&git);
        cmd.args(["config", "--global", "--get", key])
            .env_clear()
            .env("HOME", home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .current_dir(home)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        #[cfg(windows)]
        if let Ok(v) = std::env::var("SystemRoot") {
            cmd.env("SystemRoot", v);
        }
        let out = cmd.output().ok()?;
        if !out.status.success() {
            return None;
        }
        let v = String::from_utf8(out.stdout).ok()?.trim().to_string();
        (!v.is_empty()).then_some(v)
    };
    Some((get("user.name")?, get("user.email")?))
}

/// Command-scope config every git run gets: hooks and the fsmonitor off (HGW-W11, #77), and the
/// trailer kept (HGW, owner decision 2026-10-15). It outranks the repository's own config.
pub(crate) const GIT_COMMAND_CONFIG: [(&str, &str); 7] = [
    ("core.hooksPath", "/dev/null"),
    ("core.fsmonitor", "false"),
    ("core.commentChar", "#"),
    ("trailer.ifmissing", "add"),
    ("trailer.ifexists", "addIfDifferent"),
    ("trailer.co-authored-by.ifmissing", "add"),
    ("trailer.co-authored-by.ifexists", "addIfDifferent"),
];

/// Every variable a git run may be given (the identity, and [`GIT_COMMAND_CONFIG`] as
/// `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n`).
pub(crate) const GIT_REQUEST_ENV: [&str; 19] = [
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_0",
    "GIT_CONFIG_VALUE_0",
    "GIT_CONFIG_KEY_1",
    "GIT_CONFIG_VALUE_1",
    "GIT_CONFIG_KEY_2",
    "GIT_CONFIG_VALUE_2",
    "GIT_CONFIG_KEY_3",
    "GIT_CONFIG_VALUE_3",
    "GIT_CONFIG_KEY_4",
    "GIT_CONFIG_VALUE_4",
    "GIT_CONFIG_KEY_5",
    "GIT_CONFIG_VALUE_5",
    "GIT_CONFIG_KEY_6",
    "GIT_CONFIG_VALUE_6",
];

/// [`GIT_COMMAND_CONFIG`] as environment variables.
pub(crate) fn command_config_env() -> Vec<(String, String)> {
    let mut out = vec![(
        "GIT_CONFIG_COUNT".to_string(),
        GIT_COMMAND_CONFIG.len().to_string(),
    )];
    for (i, (k, v)) in GIT_COMMAND_CONFIG.iter().enumerate() {
        out.push((format!("GIT_CONFIG_KEY_{i}"), (*k).to_string()));
        out.push((format!("GIT_CONFIG_VALUE_{i}"), (*v).to_string()));
    }
    out
}

/// git's global options that take the next argument as their value.
const GLOBAL_VALUE_OPTIONS: [&str; 8] = [
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
    "--config-env",
    "--attr-source",
];
/// `git commit` long options that take the next argument as their value (unless written `=`).
const COMMIT_VALUE_OPTIONS: [&str; 12] = [
    "--message",
    "--file",
    "--author",
    "--date",
    "--template",
    "--reuse-message",
    "--reedit-message",
    "--fixup",
    "--squash",
    "--cleanup",
    "--trailer",
    "--pathspec-from-file",
];
/// `git commit` long options that would change the author or could drop the trailer.
const COMMIT_REFUSED: [&str; 4] = [
    "--author",
    "--cleanup",
    "--reuse-message",
    "--reedit-message",
];

fn refusal(what: &str) -> String {
    format!(
        "the commit's author (the member's identity) and its \"{HERMES_CO_AUTHOR_TRAILER}\" trailer are set by Citrate, so {what} is not accepted; run the command without it"
    )
}

/// A `-c` / `--config-env` key the model may not set for a git run.
fn refused_config_key(spec: &str) -> bool {
    let key = spec.split('=').next().unwrap_or("").to_ascii_lowercase();
    ["user.", "author.", "committer.", "trailer.", "include."]
        .iter()
        .any(|p| key.starts_with(p))
        || key.starts_with("includeif.")
        || matches!(
            key.as_str(),
            "core.commentchar" | "core.commentstring" | "commit.cleanup"
        )
}

/// The long option of `list` that `name` (no `=`) names, git's unique-prefix rule included.
fn long_option<'a>(name: &str, list: &[&'a str]) -> Option<&'a str> {
    if name.len() <= 2 {
        return None;
    }
    let hits: Vec<&'a str> = list
        .iter()
        .copied()
        .filter(|o| o.starts_with(name))
        .collect();
    match hits.as_slice() {
        [one] => Some(one),
        _ => list.iter().copied().find(|o| *o == name),
    }
}

/// The arguments (after `git`) a git run actually gets: `--trailer` added to `git commit`, or a
/// refusal naming what would change the author or drop the trailer.
pub(crate) fn git_args(args: &[String]) -> Result<Vec<String>, String> {
    let mut i = 0;
    let sub = loop {
        let Some(a) = args.get(i) else {
            return Ok(args.to_vec());
        };
        if a == "-c" || a == "--config-env" {
            if let Some(spec) = args.get(i + 1) {
                if refused_config_key(spec) {
                    return Err(refusal(&format!("{a} {spec}")));
                }
            }
            i += 2;
        } else if let Some(spec) = a.strip_prefix("--config-env=") {
            if refused_config_key(spec) {
                return Err(refusal(a));
            }
            i += 1;
        } else if GLOBAL_VALUE_OPTIONS.contains(&a.as_str()) {
            i += 2;
        } else if a.starts_with('-') {
            i += 1;
        } else {
            break i;
        }
    };
    match args[sub].as_str() {
        "commit-tree" => Err(refusal("git commit-tree (make commits with git commit)")),
        "commit" => {
            let rest = &args[sub + 1..];
            let mut j = 0;
            while let Some(a) = rest.get(j) {
                j += 1;
                if a == "--" {
                    break;
                }
                if let Some(long) = a.strip_prefix("--").map(|_| a.as_str()) {
                    let (name, inline_value) = match long.split_once('=') {
                        Some((n, _)) => (n, true),
                        None => (long, false),
                    };
                    if let Some(o) = long_option(name, &COMMIT_REFUSED) {
                        return Err(refusal(&format!("{a} ({o})")));
                    }
                    if !inline_value && long_option(name, &COMMIT_VALUE_OPTIONS).is_some() {
                        j += 1;
                    }
                } else if let Some(short) = a.strip_prefix('-').filter(|s| !s.is_empty()) {
                    // A bundle of short options: the first that takes a value takes the rest
                    // (or the next argument).
                    for (k, c) in short.char_indices() {
                        match c {
                            'C' | 'c' => {
                                return Err(refusal(&format!(
                                    "{a} (-{c} reuses another commit's author)"
                                )))
                            }
                            'm' | 'F' | 't' => {
                                if k + c.len_utf8() == short.len() {
                                    j += 1;
                                }
                                break;
                            }
                            _ => {}
                        }
                    }
                }
            }
            let mut out = args[..=sub].to_vec();
            out.push("--trailer".into());
            out.push(HERMES_CO_AUTHOR_TRAILER.into());
            out.extend_from_slice(rest);
            Ok(out)
        }
        _ => Ok(args.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn commit_gets_the_trailer_after_the_subcommand_and_nothing_else_changes() {
        assert_eq!(
            git_args(&v(&["-C", "x", "commit", "-q", "-m", "m", "--", "a"])).unwrap(),
            v(&[
                "-C",
                "x",
                "commit",
                "--trailer",
                HERMES_CO_AUTHOR_TRAILER,
                "-q",
                "-m",
                "m",
                "--",
                "a"
            ])
        );
        for other in [
            v(&["status", "--short"]),
            v(&["init", "-q"]),
            v(&["-c", "color.ui=never", "log"]),
            v(&["--version"]),
        ] {
            assert_eq!(git_args(&other).unwrap(), other);
        }
    }

    #[test]
    fn option_values_are_not_mistaken_for_options() {
        // A message that looks like a refused option is just a message.
        for ok in [
            v(&["commit", "-m", "--author=x"]),
            v(&["commit", "-am", "-C"]),
            v(&["commit", "--message", "--cleanup=scissors"]),
            v(&["commit", "--mess", "--author"]),
            v(&["commit", "-m-C"]),
            v(&[
                "commit",
                "--trailer",
                "Reviewed-by: A <a@x.invalid>",
                "-m",
                "x",
            ]),
            v(&["commit", "-m", "x", "--", "--author"]),
            v(&["commit", "--amend", "--reset-author", "--no-edit"]),
        ] {
            assert!(git_args(&ok).is_ok(), "{ok:?}");
        }
    }

    #[test]
    fn author_changes_and_trailer_drops_are_refused_with_abbreviations() {
        for bad in [
            v(&["commit", "--auth=A <a@x.invalid>", "-m", "x"]),
            v(&["commit", "--clean", "verbatim", "-m", "x"]),
            v(&["commit", "-C", "HEAD"]),
            v(&["commit", "-qc", "HEAD"]),
            v(&["commit", "--reuse-message=HEAD"]),
            v(&["commit", "--reedit", "HEAD"]),
            v(&["-c", "include.path=../x", "commit", "-m", "x"]),
            v(&["-c", "includeIf.gitdir:/.path=../x", "commit", "-m", "x"]),
            v(&["-c", "trailer.x.key=Co-authored-by", "commit", "-m", "x"]),
            v(&["--config-env", "committer.email=E", "commit", "-m", "x"]),
            v(&["-c", "core.commentString=C", "commit", "-m", "x"]),
        ] {
            let e = git_args(&bad).expect_err(&format!("{bad:?}"));
            assert!(e.contains("author"), "{e}");
        }
    }

    #[test]
    fn the_command_config_env_is_numbered_and_allowed() {
        let env = command_config_env();
        assert_eq!(env[0], ("GIT_CONFIG_COUNT".into(), "7".into()));
        for (k, _) in &env {
            assert!(GIT_REQUEST_ENV.contains(&k.as_str()), "{k}");
        }
        for (k, _) in GitIdentity::hermes().env() {
            assert!(GIT_REQUEST_ENV.contains(&k), "{k}");
        }
    }
}
