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

/// HGW-2: a run that leaves git in a state that would run a program the next time the member uses
/// git in a terminal (a hook, `core.hooksPath`, `core.fsmonitor`, an alias that runs a shell…) is
/// reported in `git_warnings`. What was already there before the run is not reported again.
#[test]
fn new_risky_git_state_is_reported_after_a_run() {
    let fx = Fx::new();
    let repo = fx.grant().join("repo");
    std::fs::create_dir_all(repo.join(".git/hooks")).expect("repo");
    // Already there before the run (a member's own hook manager): not reported.
    std::fs::write(repo.join(".git/hooks/pre-push"), "#!/bin/sh\n").expect("hook");
    std::fs::write(repo.join(".git/config"), "[core]\n\tbare = false\n").expect("config");
    let r = scoped(fx.grant(), SandboxPolicy::new(SandboxMode::Off));
    let cmd = "printf '[core]\\n\\thooksPath = .h\\n[alias]\\n\\tx = !sh -c id\\n' >> .git/config; echo '#!/bin/sh' > .git/hooks/post-checkout; echo ok";
    let rep = r.run(&sh(cmd, &repo)).expect("run");
    assert_eq!(rep.exit_code, Some(0), "{}", rep.stderr);
    let w = rep.git_warnings.join("\n");
    assert!(w.contains("core.hookspath"), "{w}");
    assert!(w.contains("alias.x"), "{w}");
    assert!(w.contains("post-checkout"), "{w}");
    assert!(
        !w.contains("pre-push"),
        "pre-existing state is not reported: {w}"
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
