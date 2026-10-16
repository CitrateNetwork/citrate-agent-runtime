//! US-2.2 AC1 red-green suite for the OS sandbox layer.
//!
//! On macOS these tests run real programs (`/bin/sh`, `/usr/bin/curl`) under Seatbelt
//! (`sandbox-exec`) and prove, against the OS: no network, no writes outside the granted folder,
//! writes inside it and in the scratch HOME allowed, no reads of the member's other folders.
//! The Linux (bubblewrap) path is proven here at the argv level; the run proof on Linux is a
//! separate machine run (see the crate docs).
#![cfg(unix)] // Real Unix binaries and Unix sandboxes; the Windows suite is tests/windows.rs.

use citrate_agent_shell::sandbox::{
    bwrap_command, seatbelt_profile, Backend, SandboxMode, SandboxPolicy, SandboxSpec,
};
use citrate_agent_shell::{Allowlist, ArgPolicy, RunRequest, ShellError, ShellPolicy, ShellRunner};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

fn sys_path() -> Vec<PathBuf> {
    vec![PathBuf::from("/bin"), PathBuf::from("/usr/bin")]
}

fn allow() -> Allowlist {
    Allowlist::empty()
        .allow("sh", ArgPolicy::Any)
        .allow("curl", ArgPolicy::Any)
        .allow("echo", ArgPolicy::Any)
        .allow("git", ArgPolicy::Any)
}

/// `base/grant` (the granted folder, with `sub/`), `base/other` (not granted).
struct Fx {
    _dir: tempfile::TempDir,
    base: PathBuf,
}

impl Fx {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().canonicalize().expect("canonical");
        std::fs::create_dir_all(base.join("grant/sub")).expect("grant");
        std::fs::create_dir_all(base.join("other")).expect("other");
        std::fs::write(base.join("other/private.txt"), "not granted").expect("seed");
        Fx { _dir: dir, base }
    }
    fn grant(&self) -> PathBuf {
        self.base.join("grant")
    }
    fn other(&self) -> PathBuf {
        self.base.join("other")
    }
}

/// A runner whose only writable folder is `root` (plus the scratch HOME).
fn scoped(root: PathBuf, sandbox: SandboxPolicy) -> ShellRunner {
    let policy = ShellPolicy::new(allow(), sys_path())
        .expect("policy")
        .with_sandbox(sandbox);
    ShellRunner::with_scope(policy, move |cwd: &Path| {
        if cwd.starts_with(&root) {
            Ok(vec![root.clone()])
        } else {
            Err("outside the grant".to_string())
        }
    })
}

fn sh(cmd: &str, cwd: &Path) -> RunRequest {
    RunRequest::new("sh", vec!["-c".into(), cmd.into()], cwd)
}

// ------------------------------------------------------------------------------------------
// Fail closed, and say so when not enforced
// ------------------------------------------------------------------------------------------

#[test]
fn required_mode_without_a_backend_refuses_and_runs_nothing() {
    let fx = Fx::new();
    let r = scoped(
        fx.grant(),
        SandboxPolicy::new(SandboxMode::Required)
            .with_backend(Err("no sandbox program on this machine".into())),
    );
    let marker = fx.grant().join("ran.txt");
    let err = r
        .run(&sh(
            &format!("echo x > '{}'", marker.display()),
            &fx.grant(),
        ))
        .unwrap_err();
    match &err {
        ShellError::SandboxUnavailable { reason } => {
            assert!(reason.contains("no sandbox program"), "{reason}")
        }
        other => panic!("expected SandboxUnavailable, got {other:?}"),
    }
    assert_eq!(err.kind(), "sandbox_unavailable");
    assert!(
        !marker.exists(),
        "nothing may run when the sandbox is required"
    );
    // plan() refuses the same way, so an approval card is never shown for it.
    assert!(matches!(
        r.plan(&sh("true", &fx.grant())),
        Err(ShellError::SandboxUnavailable { .. })
    ));
}

#[test]
fn preferred_mode_without_a_backend_runs_and_reports_not_enforced() {
    let fx = Fx::new();
    let r = scoped(
        fx.grant(),
        SandboxPolicy::new(SandboxMode::Preferred).with_backend(Err("none here".into())),
    );
    let rep = r.run(&sh("echo ok", &fx.grant())).expect("run");
    assert_eq!(rep.stdout, "ok\n");
    assert!(!rep.sandbox.enforced);
    assert_eq!(rep.sandbox.backend, "none");
    assert_eq!(rep.sandbox.network, "allowed");
    assert!(
        rep.sandbox.summary.contains("none here"),
        "{}",
        rep.sandbox.summary
    );
}

#[test]
fn off_mode_reports_not_enforced() {
    let fx = Fx::new();
    let r = scoped(fx.grant(), SandboxPolicy::new(SandboxMode::Off));
    let rep = r.run(&sh("echo ok", &fx.grant())).expect("run");
    assert!(!rep.sandbox.enforced);
    assert_eq!(rep.sandbox.backend, "none");
    let j = rep.to_json();
    assert_eq!(j["sandbox"]["enforced"], false);
}

#[test]
fn a_scope_whose_write_roots_do_not_hold_the_cwd_is_refused() {
    let fx = Fx::new();
    let other = fx.other();
    let policy = ShellPolicy::new(allow(), sys_path()).expect("policy");
    let r = ShellRunner::with_scope(policy, move |_cwd: &Path| Ok(vec![other.clone()]));
    let err = r.plan(&sh("true", &fx.grant())).unwrap_err();
    assert!(matches!(err, ShellError::CwdRefused { .. }), "{err:?}");
}

#[test]
fn relative_write_roots_are_refused() {
    let fx = Fx::new();
    let policy = ShellPolicy::new(allow(), sys_path()).expect("policy");
    let r = ShellRunner::with_scope(policy, |_cwd: &Path| Ok(vec![PathBuf::from("rel")]));
    assert!(matches!(
        r.plan(&sh("true", &fx.grant())),
        Err(ShellError::CwdRefused { .. })
    ));
}

#[test]
fn new_keeps_the_cwd_as_the_only_write_root() {
    let fx = Fx::new();
    let policy = ShellPolicy::new(allow(), sys_path()).expect("policy");
    let r = ShellRunner::new(policy, |_p: &Path| Ok(()));
    let plan = r.plan(&sh("true", &fx.grant())).expect("plan");
    assert_eq!(plan.write_roots, vec![fx.grant()]);
}

// ------------------------------------------------------------------------------------------
// Profile generation (pure)
// ------------------------------------------------------------------------------------------

fn spec(fx: &Fx) -> SandboxSpec {
    SandboxSpec {
        write_roots: vec![fx.grant()],
        read_roots: vec![PathBuf::from("/opt/tool/bin")],
        scratch: fx.base.join("scratch"),
        cwd: fx.grant().join("sub"),
        masked_files: vec![fx.grant().join(".env")],
    }
}

#[test]
fn seatbelt_profile_denies_by_default_and_never_allows_network() {
    let p = seatbelt_profile(2, 3);
    assert!(p.starts_with("(version 1)"));
    assert!(p.contains("(deny default)"));
    assert!(
        !p.contains("network"),
        "the profile must not allow any network operation"
    );
    for i in 0..2 {
        assert!(p.contains(&format!("(param \"R{i}\")")), "{p}");
    }
    for i in 0..3 {
        assert!(p.contains(&format!("(param \"W{i}\")")), "{p}");
    }
    // Paths are passed as parameters, never spliced into the profile text.
    assert!(!p.contains("/Users/"));
    // The credential/hook denials come after the allows (the later rule wins).
    let allow_w = p.find("(allow file-write*").expect("write allow");
    let deny_hooks = p.find(".git/hooks").expect("hooks deny");
    assert!(deny_hooks > allow_w);
    assert!(p.contains("\\.env"));
    // HGW-2: `.git/config` is writable inside a write root (git init and git config work); the
    // hooks stay closed: no non-sample hook file, no removing or symlinking the hooks folder.
    assert!(!p.contains(".git/config"), "{p}");
    assert!(p.contains("require-not"), "{p}");
    assert!(p.contains("\\.sample$"), "{p}");
    assert!(p.contains("vnode-type SYMLINK"), "{p}");
}

#[test]
fn bwrap_command_isolates_network_and_binds_only_the_grant_writable() {
    let fx = Fx::new();
    let s = spec(&fx);
    let argv = bwrap_command(
        &s,
        Path::new("/usr/bin/forge"),
        &["test".to_string(), "--json".to_string()],
    );
    let a: Vec<String> = argv
        .iter()
        .map(|x: &OsString| x.to_string_lossy().into_owned())
        .collect();
    let has = |seq: &[&str]| a.windows(seq.len()).any(|w| w == seq);
    assert!(has(&["--unshare-all"]), "{a:?}");
    assert!(!a.iter().any(|x| x == "--share-net"), "{a:?}");
    assert!(has(&["--die-with-parent"]));
    let g = fx.grant().to_string_lossy().into_owned();
    assert!(has(&["--bind", &g, &g]), "{a:?}");
    let sc = s.scratch.to_string_lossy().into_owned();
    assert!(has(&["--bind", &sc, &sc]), "{a:?}");
    assert!(has(&["--ro-bind-try", "/opt/tool/bin", "/opt/tool/bin"]));
    assert!(has(&["--ro-bind-try", "/usr", "/usr"]));
    let env = fx.grant().join(".env").to_string_lossy().into_owned();
    assert!(has(&["--ro-bind", "/dev/null", &env]), "{a:?}");
    let cwd = s.cwd.to_string_lossy().into_owned();
    assert!(has(&["--chdir", &cwd]));
    // The program and its argv come last, after the separator, unchanged.
    let tail = &a[a.len() - 4..];
    assert_eq!(tail, &["--", "/usr/bin/forge", "test", "--json"]);
    // The member's home is never bound.
    assert!(!a.iter().any(|x| x == "/home" || x == "/Users"));
    // The writable bind of the grant comes before the masks over it.
    let bind_at = a.iter().position(|x| x == &g).expect("bind");
    let mask_at = a.iter().position(|x| x == &env).expect("mask");
    assert!(mask_at > bind_at);
    // HGW-2: an existing hooks folder stays read-only; `.git/config` is writable (git config).
    let hooks = fx.grant().join(".git/hooks").to_string_lossy().into_owned();
    assert!(has(&["--ro-bind-try", &hooks, &hooks]), "{a:?}");
    assert!(!a.iter().any(|x| x.ends_with(".git/config")), "{a:?}");
}

/// Owner decision 2026-10-15 (runtime, 1): risky git state a run adds is REVERTED after the run
/// (and reported in `git_warnings`): every listed risky key, new hook files, a symlinked hooks
/// folder. Normal config the run adds survives; what was there before the run is untouched.
#[test]
fn new_risky_git_state_is_reverted_after_a_run_and_normal_config_survives() {
    let fx = Fx::new();
    let repo = fx.grant().join("repo");
    std::fs::create_dir_all(repo.join(".git/hooks")).expect("repo");
    // Already there before the run (the member's own): untouched and not reported.
    std::fs::write(repo.join(".git/hooks/pre-push"), "#!/bin/sh\n").expect("hook");
    let before = "[core]\n\tbare = false\n\teditor = vim\n[alias]\n\tst = status\n";
    std::fs::write(repo.join(".git/config"), before).expect("config");
    let risky = r#"[core]
	hooksPath = .h
	fsmonitor = ./fsm.sh
	sshCommand = ssh -o ProxyCommand=evil
	pager = less; evil
	editor = evil-editor
[alias]
	x = !sh -c id
	co = checkout
[filter "lfs"]
	smudge = evil %f
[diff]
	external = evil-diff
[diff "bin"]
	textconv = evil-conv
[merge "ours"]
	driver = evil-merge %A
[credential]
	helper = evil-cred
[include]
	path = ../evil.inc
[includeIf "gitdir:~/"]
	path = ~/.evil
[url "file:///tmp/evil"]
	insteadOf = https://github.com/
[url "https://mirror.example.invalid/"]
	insteadOf = https://github.com/
[protocol "ext"]
	allow = always
[gpg]
	program = evil-gpg
[user]
	name = Member
	email = member@example.invalid
[remote "origin"]
	url = https://example.invalid/r.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
[core]
	autocrlf = input
"#;
    std::fs::write(fx.grant().join("risky.txt"), risky).expect("risky");
    let r = scoped(fx.grant(), SandboxPolicy::new(SandboxMode::Off));
    let cmd =
        "cat ../risky.txt >> .git/config; echo '#!/bin/sh' > .git/hooks/post-checkout; echo ok";
    let rep = r.run(&sh(cmd, &repo)).expect("run");
    assert_eq!(rep.exit_code, Some(0), "{}", rep.stderr);
    let after = std::fs::read_to_string(repo.join(".git/config")).expect("config");
    for gone in [
        "hooksPath",
        "fsmonitor",
        "sshCommand",
        "less; evil",
        "evil-editor",
        "!sh -c id",
        "checkout",
        "smudge",
        "evil-diff",
        "textconv",
        "evil-merge",
        "evil-cred",
        "evil.inc",
        "~/.evil",
        "file:///tmp/evil",
        "allow = always",
        "evil-gpg",
    ] {
        assert!(!after.contains(gone), "{gone} survived:\n{after}");
    }
    for kept in [
        "bare = false",
        "editor = vim",
        "st = status",
        "name = Member",
        "email = member@example.invalid",
        "url = https://example.invalid/r.git",
        "remote = origin",
        "autocrlf = input",
        "https://mirror.example.invalid/",
    ] {
        assert!(after.contains(kept), "{kept} was removed:\n{after}");
    }
    assert!(
        !repo.join(".git/hooks/post-checkout").exists(),
        "a new hook is removed"
    );
    assert!(
        repo.join(".git/hooks/pre-push").exists(),
        "the member's own hook stays"
    );
    let w = rep.git_warnings.join("\n");
    for k in [
        "core.hookspath",
        "core.fsmonitor",
        "core.sshcommand",
        "core.pager",
        "core.editor",
        "alias.x",
        "alias.co",
        "filter.lfs.smudge",
        "diff.external",
        "diff.bin.textconv",
        "merge.ours.driver",
        "credential.helper",
        "include.path",
        "includeif.gitdir:~/.path",
        "url.file:///tmp/evil.insteadof",
        "protocol.ext.allow",
        "gpg.program",
        "post-checkout",
    ] {
        assert!(w.contains(k), "{k} not reported: {w}");
    }
    assert!(w.contains("reverted"), "{w}");
    assert!(!w.contains("pre-push") && !w.contains("user.name"), "{w}");
    // The repo still works with what is left.
    assert!(
        rep.git_warnings.iter().all(|l| !l.contains("could not")),
        "{w}"
    );
    // A run that changes nothing about git reports nothing.
    let rep = r.run(&sh("echo quiet", &repo)).expect("run");
    assert!(rep.git_warnings.is_empty(), "{:?}", rep.git_warnings);
    let v = rep.to_json();
    assert!(
        v.get("git_warnings").is_none(),
        "empty warnings are not serialized: {v}"
    );
}

/// A brand-new repository's risky config and a symlinked config are reverted too.
#[test]
fn a_new_repo_or_a_swapped_config_is_reverted() {
    let fx = Fx::new();
    let r = scoped(fx.grant(), SandboxPolicy::new(SandboxMode::Off));
    let fresh = fx.grant().join("fresh");
    std::fs::create_dir_all(&fresh).expect("fresh");
    let cmd = "mkdir -p .git/hooks && printf '[core]\\n\\trepositoryformatversion = 0\\n\\thooksPath = x\\n' > .git/config";
    let rep = r.run(&sh(cmd, &fresh)).expect("run");
    assert_eq!(rep.exit_code, Some(0), "{}", rep.stderr);
    let cfg = std::fs::read_to_string(fresh.join(".git/config")).expect("config");
    assert!(
        cfg.contains("repositoryformatversion") && !cfg.contains("hooksPath"),
        "{cfg}"
    );
    // A config swapped for a symlink goes back to what it was.
    let repo = fx.grant().join("swap");
    std::fs::create_dir_all(repo.join(".git")).expect("repo");
    std::fs::write(repo.join(".git/config"), "[user]\n\tname = M\n").expect("cfg");
    std::fs::write(fx.grant().join("evil.cfg"), "[core]\n\thooksPath = /tmp\n").expect("evil");
    let rep = r
        .run(&sh(
            "rm .git/config && ln -s ../../evil.cfg .git/config",
            &repo,
        ))
        .expect("run");
    assert_eq!(rep.exit_code, Some(0), "{}", rep.stderr);
    let m = std::fs::symlink_metadata(repo.join(".git/config")).expect("meta");
    assert!(!m.file_type().is_symlink());
    assert_eq!(
        std::fs::read_to_string(repo.join(".git/config")).expect("cfg"),
        "[user]\n\tname = M\n"
    );
    assert!(
        rep.git_warnings.join("\n").contains("symbolic link"),
        "{:?}",
        rep.git_warnings
    );
}

/// A `.git` the run turned into a pointer (a `gitdir:` file or a symbolic link) to a git folder
/// outside the write roots is reported with the risky state found there and left as it was
/// (the run could not have written there). A pointer into the write roots is followed and the
/// folder it points at is cleaned like any other repository.
#[test]
fn a_git_pointer_outside_the_write_roots_is_reported_and_one_inside_is_cleaned() {
    let fx = Fx::new();
    let r = scoped(fx.grant(), SandboxPolicy::new(SandboxMode::Off));
    let elsewhere = fx.other().join("elsewhere");
    std::fs::create_dir_all(elsewhere.join("hooks")).expect("dir");
    std::fs::write(elsewhere.join("config"), "[core]\n\thooksPath = /tmp/h\n").expect("cfg");
    std::fs::write(elsewhere.join("hooks/post-checkout"), "#!/bin/sh\n").expect("hook");
    let proj = fx.grant().join("proj");
    std::fs::create_dir_all(&proj).expect("proj");
    let cmd = format!("printf 'gitdir: {}\\n' > .git", elsewhere.display());
    let rep = r.run(&sh(&cmd, &proj)).expect("run");
    assert_eq!(rep.exit_code, Some(0), "{}", rep.stderr);
    let w = rep.git_warnings.join("\n");
    assert!(
        w.contains("core.hookspath") && w.contains("post-checkout"),
        "{w}"
    );
    assert!(w.contains("not changed"), "{w}");
    assert!(
        std::fs::read_to_string(elsewhere.join("config"))
            .expect("cfg")
            .contains("hooksPath"),
        "the folder pointed at, outside the write roots, is left as it was"
    );
    assert!(elsewhere.join("hooks/post-checkout").exists());
    // The same pointer, already there before the next run, is not reported again.
    let rep = r.run(&sh("echo quiet", &proj)).expect("run");
    assert!(rep.git_warnings.is_empty(), "{:?}", rep.git_warnings);
    #[cfg(unix)]
    {
        let linked = fx.grant().join("linked");
        std::fs::create_dir_all(&linked).expect("linked");
        let cmd = format!("ln -s '{}' .git", elsewhere.display());
        let rep = r.run(&sh(&cmd, &linked)).expect("run");
        assert_eq!(rep.exit_code, Some(0), "{}", rep.stderr);
        let w = rep.git_warnings.join("\n");
        assert!(w.contains("core.hookspath"), "{w}");
    }

    // Inside the write roots: a git folder the run made and pointed at is cleaned. (A pointer at
    // a folder git would not use as a repository is not followed: git refuses it.)
    let inner = fx.grant().join("inner");
    std::fs::create_dir_all(&inner).expect("inner");
    let cmd = "mkdir -p ../gd/hooks ../gd/objects ../gd/refs && echo 'ref: refs/heads/main' > ../gd/HEAD && printf '[core]\\n\\tbare = false\\n\\thooksPath = /tmp/h\\n' > ../gd/config && echo x > ../gd/hooks/post-checkout && printf 'gitdir: ../gd\\n' > .git";
    let rep = r.run(&sh(cmd, &inner)).expect("run");
    assert_eq!(rep.exit_code, Some(0), "{}", rep.stderr);
    let gd = fx.grant().join("gd");
    let cfg = std::fs::read_to_string(gd.join("config")).expect("cfg");
    assert!(
        cfg.contains("bare = false") && !cfg.contains("hooksPath"),
        "{cfg}"
    );
    assert!(!gd.join("hooks/post-checkout").exists());
    let w = rep.git_warnings.join("\n");
    assert!(
        w.contains("reverted") && w.contains("core.hookspath"),
        "{w}"
    );

    // A worktree's `commondir` into the write roots: the common folder is cleaned too.
    let wt = fx.grant().join("wt");
    std::fs::create_dir_all(wt.join(".git")).expect("wt");
    let cmd = "mkdir -p ../common/hooks ../common/objects ../common/refs && echo 'ref: refs/heads/main' > ../common/HEAD && printf '[alias]\\n\\tx = !id\\n' > ../common/config && printf '../../common\\n' > .git/commondir";
    let rep = r.run(&sh(cmd, &wt)).expect("run");
    assert_eq!(rep.exit_code, Some(0), "{}", rep.stderr);
    let cfg = std::fs::read_to_string(fx.grant().join("common/config")).expect("cfg");
    assert!(!cfg.contains("!id"), "{cfg}");
}

/// Every repository in the write roots is covered, however deep, and including ones the run
/// creates: a nested repository, one beside the run's folder, a bare repository.
#[test]
fn repositories_anywhere_in_the_write_roots_are_cleaned() {
    let fx = Fx::new();
    // The member's own repository beside the run's folder, with its own hook and alias.
    let sib = fx.grant().join("sib");
    std::fs::create_dir_all(sib.join(".git/hooks")).expect("sib");
    std::fs::write(sib.join(".git/hooks/pre-push"), "#!/bin/sh\n").expect("hook");
    std::fs::write(sib.join(".git/config"), "[alias]\n\tst = status\n").expect("cfg");
    let r = scoped(fx.grant(), SandboxPolicy::new(SandboxMode::Off));
    let cmd = "mkdir -p ../deep/a/b/c/.git/hooks && printf '[core]\\n\\thooksPath = .h\\n' > ../deep/a/b/c/.git/config && echo x > ../deep/a/b/c/.git/hooks/post-checkout \
        && printf '[alias]\\n\\tx = !id\\n' >> ../sib/.git/config && echo x > ../sib/.git/hooks/post-merge \
        && mkdir -p ../bare.git/objects ../bare.git/refs ../bare.git/hooks && echo 'ref: refs/heads/main' > ../bare.git/HEAD \
        && printf '[core]\\n\\tbare = true\\n\\tfsmonitor = ./f\\n' > ../bare.git/config && echo x > ../bare.git/hooks/pre-receive";
    let rep = r.run(&sh(cmd, &fx.grant().join("sub"))).expect("run");
    assert_eq!(rep.exit_code, Some(0), "{}", rep.stderr);
    let g = fx.grant();
    let deep = std::fs::read_to_string(g.join("deep/a/b/c/.git/config")).expect("cfg");
    assert!(!deep.contains("hooksPath"), "{deep}");
    assert!(!g.join("deep/a/b/c/.git/hooks/post-checkout").exists());
    let sibc = std::fs::read_to_string(sib.join(".git/config")).expect("cfg");
    assert!(
        sibc.contains("st = status") && !sibc.contains("!id"),
        "{sibc}"
    );
    assert!(
        sib.join(".git/hooks/pre-push").exists(),
        "the member's own hook stays"
    );
    assert!(!sib.join(".git/hooks/post-merge").exists());
    let bare = std::fs::read_to_string(g.join("bare.git/config")).expect("cfg");
    assert!(
        bare.contains("bare = true") && !bare.contains("fsmonitor"),
        "{bare}"
    );
    assert!(!g.join("bare.git/hooks/pre-receive").exists());
    let w = rep.git_warnings.join("\n");
    for k in [
        "core.hookspath",
        "alias.x",
        "core.fsmonitor",
        "post-checkout",
        "post-merge",
        "pre-receive",
    ] {
        assert!(w.contains(k), "{k} not reported: {w}");
    }
    assert!(!w.contains("pre-push") && !w.contains("alias.st"), "{w}");
}

/// The other files git reads config and hooks from: `config.worktree`, a linked worktree's
/// `config.worktree`, and a submodule's own git folder under `.git/modules/`.
#[test]
fn worktree_config_and_submodule_git_folders_are_cleaned() {
    let fx = Fx::new();
    let repo = fx.grant().join("r");
    std::fs::create_dir_all(repo.join(".git/hooks")).expect("repo");
    std::fs::write(repo.join(".git/config"), "[core]\n\tbare = false\n").expect("cfg");
    let r = scoped(fx.grant(), SandboxPolicy::new(SandboxMode::Off));
    let cmd = "printf '[extensions]\\n\\tworktreeConfig = true\\n' >> .git/config && printf '[core]\\n\\thooksPath = .h\\n[user]\\n\\tname = W\\n' > .git/config.worktree \
        && mkdir -p .git/worktrees/w && printf '[alias]\\n\\tx = !id\\n' > .git/worktrees/w/config.worktree \
        && mkdir -p .git/modules/lib/sub/hooks .git/modules/lib/sub/objects .git/modules/lib/sub/refs && echo 'ref: refs/heads/main' > .git/modules/lib/sub/HEAD \
        && printf '[core]\\n\\tsshCommand = evil\\n' > .git/modules/lib/sub/config && echo x > .git/modules/lib/sub/hooks/post-merge";
    let rep = r.run(&sh(cmd, &repo)).expect("run");
    assert_eq!(rep.exit_code, Some(0), "{}", rep.stderr);
    let wt = std::fs::read_to_string(repo.join(".git/config.worktree")).expect("cfg");
    assert!(wt.contains("name = W") && !wt.contains("hooksPath"), "{wt}");
    let lw = std::fs::read_to_string(repo.join(".git/worktrees/w/config.worktree")).expect("cfg");
    assert!(!lw.contains("!id"), "{lw}");
    let sm = std::fs::read_to_string(repo.join(".git/modules/lib/sub/config")).expect("cfg");
    assert!(!sm.contains("sshCommand"), "{sm}");
    assert!(!repo.join(".git/modules/lib/sub/hooks/post-merge").exists());
    let w = rep.git_warnings.join("\n");
    for k in ["core.hookspath", "alias.x", "core.sshcommand", "post-merge"] {
        assert!(w.contains(k), "{k} not reported: {w}");
    }
}

#[test]
fn backend_names_are_stable() {
    assert_eq!(
        Backend::Seatbelt {
            exe: PathBuf::from("/usr/bin/sandbox-exec")
        }
        .name(),
        "seatbelt"
    );
    assert_eq!(
        Backend::Bwrap {
            exe: PathBuf::from("/usr/bin/bwrap")
        }
        .name(),
        "bwrap"
    );
}

// ------------------------------------------------------------------------------------------
// macOS: the real thing (Seatbelt via sandbox-exec)
// ------------------------------------------------------------------------------------------

/// Real git, run in the grant: risky state in a nested repository, a bare repository,
/// `config.worktree` and a submodule git folder. Hook writes the sandbox refuses are allowed to
/// fail (`|| true`); whatever lands must not survive the run.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const GIT_EVERYWHERE: &str = "set -e; git init -q . \
 && mkdir -p a/b && git init -q a/b && git -C a/b config core.hooksPath .h \
 && git init -q --bare bare.git && git -C bare.git config alias.x '!id' \
 && { echo '#!/bin/sh' > bare.git/hooks/post-receive || true; } \
 && git config extensions.worktreeConfig true && git config --worktree core.fsmonitor ./f \
 && mkdir -p .git/modules/m/objects .git/modules/m/refs .git/modules/m/hooks && echo 'ref: refs/heads/main' > .git/modules/m/HEAD \
 && printf '[core]\\n\\tsshCommand = evil\\n' > .git/modules/m/config \
 && { echo x > .git/modules/m/hooks/post-checkout || true; }";

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn assert_git_everywhere_cleaned(g: &Path, warnings: &[String]) {
    let read = |p: &str| std::fs::read_to_string(g.join(p)).unwrap_or_default();
    assert!(
        !read("a/b/.git/config").contains("hooksPath"),
        "{}",
        read("a/b/.git/config")
    );
    assert!(
        !read("bare.git/config").contains("!id"),
        "{}",
        read("bare.git/config")
    );
    assert!(!g.join("bare.git/hooks/post-receive").exists());
    assert!(
        !read(".git/config.worktree").contains("fsmonitor"),
        "{}",
        read(".git/config.worktree")
    );
    assert!(!read(".git/modules/m/config").contains("sshCommand"));
    assert!(!g.join(".git/modules/m/hooks/post-checkout").exists());
    let w = warnings.join("\n");
    for k in [
        "core.hookspath",
        "alias.x",
        "core.fsmonitor",
        "core.sshcommand",
    ] {
        assert!(w.contains(k), "{k} not reported: {w}");
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::net::TcpListener;

    fn required() -> SandboxPolicy {
        SandboxPolicy::new(SandboxMode::Required)
    }

    #[test]
    fn the_seatbelt_backend_is_detected_on_this_mac() {
        let b = citrate_agent_shell::sandbox::detect().expect("sandbox-exec works on macOS");
        assert_eq!(b.name(), "seatbelt");
    }

    #[test]
    fn writes_inside_the_grant_are_allowed() {
        let fx = Fx::new();
        let r = scoped(fx.grant(), required());
        let f = fx.grant().join("sub/out.txt");
        let rep = r
            .run(&sh(
                &format!("echo built > '{}'", f.display()),
                &fx.grant().join("sub"),
            ))
            .expect("run");
        assert_eq!(rep.exit_code, Some(0), "stderr: {}", rep.stderr);
        assert!(rep.sandbox.enforced);
        assert_eq!(rep.sandbox.backend, "seatbelt");
        assert_eq!(rep.sandbox.network, "denied");
        assert_eq!(std::fs::read_to_string(&f).expect("written"), "built\n");
    }

    #[test]
    fn writes_outside_the_grant_are_denied() {
        let fx = Fx::new();
        let r = scoped(fx.grant(), required());
        let f = fx.other().join("escape.txt");
        let rep = r
            .run(&sh(&format!("echo x > '{}'", f.display()), &fx.grant()))
            .expect("run");
        assert_ne!(rep.exit_code, Some(0));
        assert!(
            rep.stderr.contains("Operation not permitted"),
            "{}",
            rep.stderr
        );
        assert!(!f.exists(), "the write outside the grant must not happen");
        // Control: the same command without the sandbox does write (the test bites).
        let open = scoped(fx.grant(), SandboxPolicy::new(SandboxMode::Off));
        let rep = open
            .run(&sh(&format!("echo x > '{}'", f.display()), &fx.grant()))
            .expect("run");
        assert_eq!(rep.exit_code, Some(0));
        assert!(f.exists());
    }

    #[test]
    fn the_scratch_home_is_writable() {
        let fx = Fx::new();
        let r = scoped(fx.grant(), required());
        let rep = r
            .run(&sh(
                "echo x > \"$HOME/cache\" && cat \"$HOME/cache\"",
                &fx.grant(),
            ))
            .expect("run");
        assert_eq!(rep.exit_code, Some(0), "stderr: {}", rep.stderr);
        assert_eq!(rep.stdout, "x\n");
    }

    #[test]
    fn reads_outside_the_grant_are_denied() {
        let fx = Fx::new();
        let r = scoped(fx.grant(), required());
        let rep = r
            .run(&sh(
                &format!("cat '{}'", fx.other().join("private.txt").display()),
                &fx.grant(),
            ))
            .expect("run");
        assert_ne!(rep.exit_code, Some(0));
        assert!(!rep.stdout.contains("not granted"));
    }

    #[test]
    fn network_is_denied() {
        let fx = Fx::new();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();
        let url = format!("http://127.0.0.1:{port}/");
        let r = scoped(fx.grant(), required());
        let rep = r
            .run(&RunRequest::new(
                "curl",
                vec!["-sS".into(), "-m".into(), "3".into(), url.clone()],
                &fx.grant(),
            ))
            .expect("run");
        assert_ne!(rep.exit_code, Some(0), "curl must fail under the sandbox");
        assert!(
            listener.accept().is_err(),
            "no connection may reach the listener from inside the sandbox"
        );
        // Control: without the sandbox the same request connects (the test bites).
        let open = scoped(fx.grant(), SandboxPolicy::new(SandboxMode::Off));
        let _ = open.run(&RunRequest::new(
            "curl",
            vec!["-sS".into(), "-m".into(), "1".into(), url],
            &fx.grant(),
        ));
        listener.set_nonblocking(false).expect("blocking");
        let (_conn, _) = listener.accept().expect("the unsandboxed run connected");
    }

    #[test]
    fn git_hooks_and_env_files_in_the_grant_are_not_writable() {
        let fx = Fx::new();
        std::fs::create_dir_all(fx.grant().join(".git/hooks")).expect("hooks");
        let r = scoped(fx.grant(), required());
        let hook = fx.grant().join(".git/hooks/pre-commit");
        let env = fx.grant().join(".env");
        for target in [&hook, &env] {
            let rep = r
                .run(&sh(
                    &format!("echo x > '{}'", target.display()),
                    &fx.grant(),
                ))
                .expect("run");
            assert_ne!(rep.exit_code, Some(0), "{}", target.display());
            assert!(!target.exists(), "{}", target.display());
        }
    }

    /// HGW-2: `git init`, `git add` and `git commit` work inside the grant under Seatbelt (they
    /// write `.git/config` and the sample hooks), and nothing lands outside it.
    #[test]
    fn git_init_add_and_commit_work_inside_the_grant() {
        let fx = Fx::new();
        let r = scoped(fx.grant(), required());
        let cmd = "git init -q . && echo hi > a.txt && git add a.txt && git -c user.name=Hermes -c user.email=hermes@example.invalid commit -q -m init && git config user.name Hermes && git log --oneline | wc -l";
        let rep = r.run(&sh(cmd, &fx.grant())).expect("run");
        assert!(rep.sandbox.enforced);
        assert_eq!(rep.exit_code, Some(0), "stderr: {}", rep.stderr);
        assert_eq!(rep.stdout.trim(), "1");
        assert!(fx.grant().join(".git/config").is_file());
        assert!(rep.git_warnings.is_empty(), "{:?}", rep.git_warnings);
    }

    /// Owner decision 2026-10-15: real git under Seatbelt setting risky config is reverted after
    /// the run; the identity and remote it set survive.
    #[test]
    fn git_config_set_by_real_git_under_seatbelt_is_reverted() {
        let fx = Fx::new();
        let r = scoped(fx.grant(), required());
        let cmd = "git init -q . && git config core.hooksPath .h && git config alias.x '!id' && git config user.name M && git remote add origin https://example.invalid/r.git";
        let rep = r.run(&sh(cmd, &fx.grant())).expect("run");
        assert_eq!(rep.exit_code, Some(0), "{}", rep.stderr);
        let cfg = std::fs::read_to_string(fx.grant().join(".git/config")).expect("config");
        assert!(!cfg.contains("hooksPath") && !cfg.contains("!id"), "{cfg}");
        assert!(
            cfg.contains("name = M") && cfg.contains("example.invalid"),
            "{cfg}"
        );
        let w = rep.git_warnings.join("\n");
        assert!(w.contains("core.hookspath") && w.contains("alias.x"), "{w}");
    }

    /// HGW-2: with `.git` writable, hooks stay closed: no hook file but samples, no renaming a
    /// sample into a hook, no removing the hooks folder, no symlinking a new one in.
    #[test]
    fn git_hooks_stay_closed_when_git_is_writable() {
        let fx = Fx::new();
        let r = scoped(fx.grant(), required());
        let rep = r.run(&sh("git init -q .", &fx.grant())).expect("init");
        assert_eq!(rep.exit_code, Some(0), "stderr: {}", rep.stderr);
        let hooks = fx.grant().join(".git/hooks");
        for cmd in [
            "echo x > .git/hooks/pre-commit",
            "mv .git/hooks/pre-commit.sample .git/hooks/pre-commit",
            "cp .git/hooks/pre-commit.sample .git/hooks/post-merge",
        ] {
            let rep = r.run(&sh(cmd, &fx.grant())).expect("run");
            assert_ne!(rep.exit_code, Some(0), "{cmd}");
        }
        assert!(!hooks.join("pre-commit").exists());
        assert!(!hooks.join("post-merge").exists());
        let _ = r.run(&sh("rm -rf .git/hooks", &fx.grant())).expect("rm");
        assert!(hooks.is_dir(), "the hooks folder cannot be removed");
        let _ = r
            .run(&sh("mv .git/hooks .git/h2", &fx.grant()))
            .expect("mv");
        assert!(hooks.is_dir(), "the hooks folder cannot be moved away");
        std::fs::create_dir_all(fx.grant().join("sub/fresh/.git")).expect("fresh");
        let rep = r
            .run(&sh(
                "mkdir -p ../../h && ln -s ../../h .git/hooks",
                &fx.grant().join("sub/fresh"),
            ))
            .expect("ln");
        assert_ne!(rep.exit_code, Some(0));
        assert!(!fx.grant().join("sub/fresh/.git/hooks").exists());
        // The sample a fresh `git init` writes is fine.
        assert!(hooks.join("pre-commit.sample").exists() || hooks.is_dir());
    }

    /// Real git under Seatbelt: a nested repository, a bare repository (whose `hooks/` is not
    /// under `.git/`), `config.worktree` and a submodule git folder are all cleaned after the run.
    #[test]
    fn git_state_anywhere_in_the_grant_is_cleaned_under_seatbelt() {
        let fx = Fx::new();
        let r = scoped(fx.grant(), required());
        let rep = r.run(&sh(GIT_EVERYWHERE, &fx.grant())).expect("run");
        assert!(rep.sandbox.enforced);
        assert_eq!(rep.exit_code, Some(0), "stderr: {}", rep.stderr);
        assert_git_everywhere_cleaned(&fx.grant(), &rep.git_warnings);
    }

    /// A hook written through a differently cased `.git` (the Mac's file system ignores case)
    /// does not survive the run.
    #[test]
    fn a_hook_written_through_a_differently_cased_git_folder_does_not_survive() {
        let fx = Fx::new();
        let r = scoped(fx.grant(), required());
        let rep = r.run(&sh("git init -q .", &fx.grant())).expect("init");
        assert_eq!(rep.exit_code, Some(0), "stderr: {}", rep.stderr);
        let _ = r
            .run(&sh(
                "echo x > .GIT/hooks/pre-commit; echo x > .Git/hooks/post-checkout; true",
                &fx.grant(),
            ))
            .expect("run");
        let hooks: Vec<String> = std::fs::read_dir(fx.grant().join(".git/hooks"))
            .expect("hooks")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.ends_with(".sample"))
            .collect();
        assert!(hooks.is_empty(), "{hooks:?}");
    }

    /// HGW-W2 (#75): `.env.example` and `.env.sample` (template files, not secrets) are readable;
    /// `.env` and `.env.local` stay unreadable and unwritable.
    #[test]
    fn env_example_files_are_readable_and_real_env_files_are_not() {
        let fx = Fx::new();
        for (name, body) in [
            (".env.example", "RPC_URL=\n"),
            (".env.sample", "KEY=\n"),
            (".env", "SECRET=1\n"),
            (".env.local", "SECRET=2\n"),
        ] {
            std::fs::write(fx.grant().join(name), body).expect("seed");
        }
        let r = scoped(fx.grant(), required());
        let rep = r
            .run(&sh("cat .env.example .env.sample", &fx.grant()))
            .expect("run");
        assert_eq!(rep.exit_code, Some(0), "{}", rep.stderr);
        assert_eq!(rep.stdout, "RPC_URL=\nKEY=\n");
        for secret in [".env", ".env.local"] {
            let rep = r
                .run(&sh(&format!("cat {secret}"), &fx.grant()))
                .expect("run");
            assert_ne!(rep.exit_code, Some(0), "{secret}");
            assert!(!rep.stdout.contains("SECRET"), "{secret}");
        }
    }

    #[test]
    fn plan_shows_the_sandbox_before_anything_runs() {
        let fx = Fx::new();
        let r = scoped(fx.grant(), required());
        let plan = r.plan(&sh("true", &fx.grant())).expect("plan");
        assert!(plan.sandbox.enforced);
        assert_eq!(plan.sandbox.backend, "seatbelt");
        assert!(plan
            .sandbox
            .writable
            .contains(&fx.grant().to_string_lossy().into_owned()));
        assert!(
            plan.sandbox.summary.contains("no network"),
            "{}",
            plan.sandbox.summary
        );
    }
}

// ------------------------------------------------------------------------------------------
// Linux: the real thing (bubblewrap). Runs where bwrap can create a sandbox; the Linux CI lane
// sets CITRATE_REQUIRE_BWRAP=1 so a missing or broken bwrap fails instead of skipping.
// ------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    fn required() -> Option<SandboxPolicy> {
        match citrate_agent_shell::sandbox::detect() {
            Ok(_) => Some(SandboxPolicy::new(SandboxMode::Required)),
            Err(why) => {
                assert!(
                    std::env::var("CITRATE_REQUIRE_BWRAP").as_deref() != Ok("1"),
                    "CITRATE_REQUIRE_BWRAP=1 but bwrap is unusable here: {why}"
                );
                eprintln!("skipping the bwrap run test: {why}");
                None
            }
        }
    }

    #[test]
    fn writes_outside_the_grant_are_denied_under_bwrap() {
        let Some(p) = required() else { return };
        let fx = Fx::new();
        let r = scoped(fx.grant(), p);
        let f = fx.other().join("escape.txt");
        let rep = r
            .run(&sh(&format!("echo x > '{}'", f.display()), &fx.grant()))
            .expect("run");
        assert!(rep.sandbox.enforced);
        assert_ne!(rep.exit_code, Some(0));
        assert!(!f.exists());
        let ok = fx.grant().join("in.txt");
        let rep = r
            .run(&sh(&format!("echo x > '{}'", ok.display()), &fx.grant()))
            .expect("run");
        assert_eq!(rep.exit_code, Some(0), "{}", rep.stderr);
        assert!(ok.exists());
    }

    #[test]
    fn git_init_add_and_commit_work_inside_the_grant_under_bwrap() {
        let Some(p) = required() else { return };
        if !Path::new("/usr/bin/git").exists() {
            eprintln!("skipping: no /usr/bin/git");
            return;
        }
        let fx = Fx::new();
        let r = scoped(fx.grant(), p);
        let cmd = "git init -q . && echo hi > a.txt && git add a.txt && git -c user.name=Hermes -c user.email=hermes@example.invalid commit -q -m init && git config user.name Hermes && git log --oneline | wc -l";
        let rep = r.run(&sh(cmd, &fx.grant())).expect("run");
        assert_eq!(rep.exit_code, Some(0), "stderr: {}", rep.stderr);
        assert_eq!(rep.stdout.trim(), "1");
    }

    #[test]
    fn git_state_anywhere_in_the_grant_is_cleaned_under_bwrap() {
        let Some(p) = required() else { return };
        if !Path::new("/usr/bin/git").exists() {
            eprintln!("skipping: no /usr/bin/git");
            return;
        }
        let fx = Fx::new();
        let r = scoped(fx.grant(), p);
        let rep = r.run(&sh(GIT_EVERYWHERE, &fx.grant())).expect("run");
        assert!(rep.sandbox.enforced);
        assert_eq!(rep.exit_code, Some(0), "stderr: {}", rep.stderr);
        assert_git_everywhere_cleaned(&fx.grant(), &rep.git_warnings);
    }

    #[test]
    fn network_is_unshared_under_bwrap() {
        let Some(p) = required() else { return };
        let fx = Fx::new();
        let r = scoped(fx.grant(), p);
        // Only a loopback interface exists in a fresh network namespace.
        let rep = r
            .run(&sh(
                "cat /proc/net/dev | tail -n +3 | cut -d: -f1 | tr -d ' '",
                &fx.grant(),
            ))
            .expect("run");
        assert_eq!(rep.exit_code, Some(0), "{}", rep.stderr);
        let ifaces: Vec<&str> = rep.stdout.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(ifaces, vec!["lo"], "{ifaces:?}");
    }
}
