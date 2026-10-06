//! HUP-S2.2 red-green suite for the shell allowlist runner.
//!
//! These tests exec real system binaries (`/bin/echo`, `/bin/sleep`, `/bin/sh`,
//! `/usr/bin/printenv`, `/usr/bin/seq`, `/usr/bin/git`) through a test allowlist, so they
//! prove the runner's behaviour against the OS, not against a fake.
#![cfg(unix)] // Real Unix binaries and Unix sandboxes; the Windows suite is tests/windows.rs.

use citrate_agent_shell::{Allowlist, ArgPolicy, RunRequest, ShellError, ShellPolicy, ShellRunner};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn sys_path() -> Vec<PathBuf> {
    vec![PathBuf::from("/bin"), PathBuf::from("/usr/bin")]
}

fn test_allowlist() -> Allowlist {
    Allowlist::empty()
        .allow("echo", ArgPolicy::Any)
        .allow("sleep", ArgPolicy::Any)
        .allow("sh", ArgPolicy::Any)
        .allow("printenv", ArgPolicy::Any)
        .allow("seq", ArgPolicy::Any)
        .allow("pwd", ArgPolicy::Any)
        .allow("definitely-not-a-real-tool", ArgPolicy::Any)
}

fn open_runner(policy: ShellPolicy) -> ShellRunner {
    ShellRunner::new(policy, |_p: &Path| Ok(()))
}

fn runner() -> ShellRunner {
    open_runner(ShellPolicy::new(test_allowlist(), sys_path()).expect("policy"))
}

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn req(program: &str, args: &[&str], cwd: &Path) -> RunRequest {
    RunRequest::new(program, args.iter().map(|s| s.to_string()).collect(), cwd)
}

// ---------------------------------------------------------------- allowlist

#[test]
fn allowed_program_runs_and_reports() {
    let d = tmp();
    let r = runner()
        .run(&req("echo", &["hello"], d.path()))
        .expect("run");
    assert_eq!(r.exit_code, Some(0));
    assert!(r.passed());
    assert!(!r.timed_out);
    assert_eq!(r.stdout, "hello\n");
    assert_eq!(r.resolved_path, PathBuf::from("/bin/echo"));
    assert_eq!(r.args, vec!["hello".to_string()]);
}

#[test]
fn program_not_on_allowlist_is_refused() {
    let d = tmp();
    let err = runner()
        .run(&req("rm", &["-rf", "x"], d.path()))
        .unwrap_err();
    assert!(
        matches!(err, ShellError::ProgramNotAllowed { .. }),
        "{err:?}"
    );
}

#[test]
fn hello_mint_allowlist_has_the_toolchain_and_nothing_generic() {
    let a = Allowlist::hello_mint();
    for p in [
        "forge", "anvil", "cast", "slither", "aderyn", "medusa", "solc", "node", "npm", "npx",
        "pnpm", "git",
    ] {
        assert!(a.contains(p), "hello-mint allowlist must contain {p}");
    }
    for p in [
        "sh",
        "bash",
        "zsh",
        "env",
        "curl",
        "wget",
        "rm",
        "cat",
        "ls",
        "cp",
        "mv",
        "python",
        "python3",
        "sudo",
        "osascript",
        "security",
        "ssh",
    ] {
        assert!(!a.contains(p), "hello-mint allowlist must not contain {p}");
    }
}

#[test]
fn shell_metacharacter_program_names_are_refused() {
    let d = tmp();
    let r = runner();
    for bad in [
        "echo;rm",
        "echo && ls",
        "echo|sh",
        "$(id)",
        "`id`",
        "echo>out",
        "echo\nrm",
        "echo hello",
        "",
        "-echo",
        ".echo",
        "ech\0o",
        "~/echo",
        "ech*",
    ] {
        let err = r.run(&req(bad, &[], d.path())).unwrap_err();
        assert!(
            matches!(err, ShellError::InvalidProgramName { .. }),
            "{bad:?} must be an invalid name, got {err:?}"
        );
    }
}

#[test]
fn path_shaped_program_names_are_refused() {
    let d = tmp();
    let r = runner();
    for bad in ["/bin/echo", "./echo", "../bin/echo", "bin/echo", "..\\echo"] {
        let err = r.run(&req(bad, &[], d.path())).unwrap_err();
        assert!(
            matches!(err, ShellError::InvalidProgramName { .. }),
            "{bad:?} must be refused, got {err:?}"
        );
    }
}

#[test]
fn arguments_are_argv_literals_never_shell_expanded() {
    let d = tmp();
    let r = runner()
        .run(&req(
            "echo",
            &["$(id)", ";", "`whoami`", "a|b", "*"],
            d.path(),
        ))
        .expect("run");
    assert_eq!(r.stdout, "$(id) ; `whoami` a|b *\n");
}

#[test]
fn nul_byte_in_an_argument_is_refused() {
    let d = tmp();
    let err = runner().run(&req("echo", &["a\0b"], d.path())).unwrap_err();
    assert!(matches!(err, ShellError::ArgumentRefused { .. }), "{err:?}");
}

// ---------------------------------------------------------------- git read-only

fn git_runner() -> ShellRunner {
    open_runner(ShellPolicy::new(Allowlist::hello_mint(), sys_path()).expect("policy"))
}

#[test]
fn git_read_only_subcommand_runs() {
    let d = tmp();
    // Not a repository: git runs and reports a non-zero exit, which is still a report.
    let r = git_runner()
        .run(&req("git", &["status"], d.path()))
        .expect("run");
    assert!(r.exit_code.is_some());
    assert!(!r.timed_out);
}

#[test]
fn git_mutating_subcommands_and_global_options_are_refused() {
    let d = tmp();
    let g = git_runner();
    for args in [
        vec!["push", "origin", "main"],
        vec!["commit", "-m", "x"],
        vec!["init"],
        vec!["config", "user.name", "x"],
        vec!["-c", "core.pager=sh", "status"],
        vec!["--git-dir=/tmp/x", "status"],
        vec!["checkout", "main"],
        vec!["reset", "--hard"],
        vec![],
    ] {
        let err = g.run(&req("git", &args, d.path())).unwrap_err();
        assert!(
            matches!(err, ShellError::ArgumentRefused { .. }),
            "git {args:?} must be refused, got {err:?}"
        );
    }
}

#[test]
fn git_read_only_subcommand_with_a_write_flag_is_refused() {
    let d = tmp();
    let g = git_runner();
    for args in [
        vec!["diff", "--output=/tmp/x"],
        vec!["log", "--output", "/tmp/x"],
        vec!["diff", "--ext-diff"],
        vec!["diff", "--no-index", "/etc/hosts", "x"],
        vec!["show", "--textconv"],
    ] {
        let err = g.run(&req("git", &args, d.path())).unwrap_err();
        assert!(
            matches!(err, ShellError::ArgumentRefused { .. }),
            "git {args:?} must be refused, got {err:?}"
        );
    }
}

// ---------------------------------------------------------------- environment

#[test]
fn environment_is_scrubbed_to_the_allowlist() {
    std::env::set_var("CITRATE_SHELL_TEST_SECRET", "do-not-leak");
    let d = tmp();
    let r = runner().run(&req("printenv", &[], d.path())).expect("run");
    assert!(r.passed(), "{r:?}");
    assert!(
        !r.stdout.contains("CITRATE_SHELL_TEST_SECRET"),
        "{}",
        r.stdout
    );
    assert!(!r.stdout.contains("do-not-leak"));
    assert!(r.stdout.contains("PATH=/bin:/usr/bin\n"), "{}", r.stdout);
    let real_home = std::env::var("HOME").unwrap_or_default();
    let home_line = r
        .stdout
        .lines()
        .find(|l| l.starts_with("HOME="))
        .expect("HOME is set to a scratch dir")
        .to_string();
    assert_ne!(home_line, format!("HOME={real_home}"));
    // Nothing outside the fixed + pass-through set appears.
    for line in r.stdout.lines() {
        let key = line.split('=').next().unwrap_or("");
        assert!(
            ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "NO_COLOR"]
                .contains(&key),
            "unexpected env var {key} reached the child"
        );
    }
}

#[test]
fn scratch_home_is_removed_after_the_run() {
    let d = tmp();
    let r = runner()
        .run(&req("printenv", &["HOME"], d.path()))
        .expect("run");
    let home = PathBuf::from(r.stdout.trim());
    assert!(home.is_absolute());
    assert!(!home.exists(), "scratch HOME {home:?} must be cleaned up");
}

#[test]
fn request_env_must_be_on_the_policy_allowlist() {
    let d = tmp();
    let policy = ShellPolicy::new(test_allowlist(), sys_path())
        .expect("policy")
        .with_request_env_allow(&["FOUNDRY_PROFILE"]);
    let r = open_runner(policy);
    let ok = r
        .run(&req("printenv", &["FOUNDRY_PROFILE"], d.path()).env("FOUNDRY_PROFILE", "ci"))
        .expect("run");
    assert_eq!(ok.stdout, "ci\n");
    let err = r
        .run(&req("printenv", &[], d.path()).env("LD_PRELOAD", "/tmp/x.so"))
        .unwrap_err();
    assert!(matches!(err, ShellError::EnvRefused { .. }), "{err:?}");
    // A request cannot override the fixed PATH / HOME even if it names them.
    let err = r
        .run(&req("printenv", &[], d.path()).env("PATH", "/tmp"))
        .unwrap_err();
    assert!(matches!(err, ShellError::EnvRefused { .. }), "{err:?}");
}

// ---------------------------------------------------------------- timeout

#[test]
fn timeout_kills_a_sleeping_child() {
    let d = tmp();
    let t0 = Instant::now();
    let r = runner()
        .run(&req("sleep", &["30"], d.path()).timeout(Duration::from_millis(300)))
        .expect("run");
    assert!(r.timed_out);
    assert!(!r.passed());
    assert_eq!(r.exit_code, None);
    assert_eq!(r.signal, Some(libc_sigkill()));
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "took {:?}",
        t0.elapsed()
    );
}

fn libc_sigkill() -> i32 {
    9
}

fn pid_alive(pid: i32) -> bool {
    // `ps -p` exits 0 only if the pid exists and is not a reaped zombie on macOS/Linux.
    let out = std::process::Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .expect("ps");
    let stat = String::from_utf8_lossy(&out.stdout).trim().to_string();
    out.status.success() && !stat.is_empty() && !stat.starts_with('Z')
}

#[test]
fn timeout_kills_the_whole_process_group() {
    let d = tmp();
    let t0 = Instant::now();
    let r = runner()
        .run(
            &req("sh", &["-c", "sleep 30 & echo $!; wait"], d.path())
                .timeout(Duration::from_millis(500)),
        )
        .expect("run");
    assert!(r.timed_out);
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "took {:?}",
        t0.elapsed()
    );
    let grandchild: i32 = r.stdout.trim().parse().expect("grandchild pid");
    let deadline = Instant::now() + Duration::from_secs(3);
    while pid_alive(grandchild) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !pid_alive(grandchild),
        "grandchild {grandchild} survived the timeout"
    );
}

#[test]
fn requested_timeout_is_clamped_to_the_policy_max() {
    let d = tmp();
    let policy = ShellPolicy::new(test_allowlist(), sys_path())
        .expect("policy")
        .with_max_timeout(Duration::from_millis(400));
    let t0 = Instant::now();
    let r = open_runner(policy)
        .run(&req("sleep", &["30"], d.path()).timeout(Duration::from_secs(3600)))
        .expect("run");
    assert!(r.timed_out);
    assert_eq!(r.timeout_ms, 400);
    assert!(t0.elapsed() < Duration::from_secs(5));
}

// ---------------------------------------------------------------- output capture

#[test]
fn stdout_is_capped_with_a_truncation_marker() {
    let d = tmp();
    let policy = ShellPolicy::new(test_allowlist(), sys_path())
        .expect("policy")
        .with_output_caps(1000, 1000);
    let r = open_runner(policy)
        .run(&req("seq", &["1", "20000"], d.path()))
        .expect("run");
    assert!(r.passed());
    assert!(r.stdout_truncated);
    assert!(!r.stderr_truncated);
    assert_eq!(r.stdout_bytes, 108_894, "seq 1 20000 emits 108894 bytes");
    assert!(r.stdout.starts_with("1\n2\n3\n"));
    assert!(
        r.stdout.contains("[truncated: 107894 bytes omitted]"),
        "{}",
        &r.stdout[900..]
    );
    assert!(r.stdout.len() < 1100);
}

#[test]
fn stderr_is_captured_separately_and_capped() {
    let d = tmp();
    let policy = ShellPolicy::new(test_allowlist(), sys_path())
        .expect("policy")
        .with_output_caps(1000, 10);
    let r = open_runner(policy)
        .run(&req(
            "sh",
            &["-c", "echo out; echo 0123456789abcdef 1>&2; exit 7"],
            d.path(),
        ))
        .expect("run");
    assert_eq!(r.exit_code, Some(7));
    assert!(!r.passed());
    assert_eq!(r.stdout, "out\n");
    assert!(r.stderr_truncated);
    assert!(r.stderr.starts_with("0123456789"));
    assert_eq!(r.stderr_bytes, 17);
}

// ---------------------------------------------------------------- cwd

#[test]
fn cwd_check_refusal_blocks_the_run() {
    let d = tmp();
    let r = ShellRunner::new(
        ShellPolicy::new(test_allowlist(), sys_path()).expect("policy"),
        |_p: &Path| Err("outside every folder grant".to_string()),
    );
    let err = r.run(&req("echo", &["x"], d.path())).unwrap_err();
    match err {
        ShellError::CwdRefused { reason, .. } => assert!(reason.contains("folder grant")),
        other => panic!("expected CwdRefused, got {other:?}"),
    }
}

#[test]
fn cwd_check_sees_the_canonical_path_and_the_child_runs_there() {
    let d = tmp();
    let inner = d.path().join("a");
    std::fs::create_dir(&inner).expect("mkdir");
    let canonical = std::fs::canonicalize(&inner).expect("canon");
    let want = canonical.clone();
    let r = ShellRunner::new(
        ShellPolicy::new(test_allowlist(), sys_path()).expect("policy"),
        move |p: &Path| {
            if p == want {
                Ok(())
            } else {
                Err(format!("unexpected {p:?}"))
            }
        },
    );
    // Reach the dir through a `..` hop; the check must see the resolved path.
    let dotted = inner.join("..").join("a");
    let rep = r.run(&req("pwd", &["-P"], &dotted)).expect("run");
    assert_eq!(PathBuf::from(rep.stdout.trim()), canonical);
    assert_eq!(rep.cwd, canonical);
}

#[test]
fn relative_or_missing_cwd_is_refused() {
    let r = runner();
    let err = r
        .run(&req("echo", &[], Path::new("relative/dir")))
        .unwrap_err();
    assert!(matches!(err, ShellError::CwdRefused { .. }), "{err:?}");
    let err = r
        .run(&req("echo", &[], Path::new("/definitely/not/here/xyz")))
        .unwrap_err();
    assert!(matches!(err, ShellError::CwdRefused { .. }), "{err:?}");
}

// ---------------------------------------------------------------- resolution

#[test]
fn allowlisted_program_missing_from_the_search_path_is_not_found() {
    let d = tmp();
    let err = runner()
        .run(&req("definitely-not-a-real-tool", &[], d.path()))
        .unwrap_err();
    assert!(matches!(err, ShellError::ProgramNotFound { .. }), "{err:?}");
}

#[test]
fn non_executable_file_on_the_search_path_is_not_resolved() {
    let bin = tmp();
    std::fs::write(
        bin.path().join("definitely-not-a-real-tool"),
        b"#!/bin/sh\necho hi\n",
    )
    .expect("write");
    let policy =
        ShellPolicy::new(test_allowlist(), vec![bin.path().to_path_buf()]).expect("policy");
    let d = tmp();
    let err = open_runner(policy)
        .run(&req("definitely-not-a-real-tool", &[], d.path()))
        .unwrap_err();
    assert!(matches!(err, ShellError::ProgramNotFound { .. }), "{err:?}");
}

#[test]
fn relative_search_path_entries_are_rejected() {
    let err =
        ShellPolicy::new(test_allowlist(), vec![PathBuf::from("node_modules/.bin")]).unwrap_err();
    assert!(matches!(err, ShellError::InvalidPolicy { .. }), "{err:?}");
}

// ---------------------------------------------------------------- verifier input

#[test]
fn run_report_serializes_for_verifiers() {
    let d = tmp();
    let r = runner().run(&req("echo", &["hi"], d.path())).expect("run");
    let v = r.to_json();
    assert_eq!(v["exit_code"], serde_json::json!(0));
    assert_eq!(v["timed_out"], serde_json::json!(false));
    assert_eq!(v["passed"], serde_json::json!(true));
    assert_eq!(v["program"], serde_json::json!("echo"));
    assert_eq!(v["stdout"], serde_json::json!("hi\n"));
    assert!(v["duration_ms"].is_u64());
}

// ------------------------------------------------- git read-only: review hardening

#[test]
fn git_options_that_read_files_outside_the_cwd_are_refused() {
    let d = tmp();
    let g = git_runner();
    for args in [
        vec!["blame", "--contents", "/etc/hosts", "f"],
        vec!["blame", "--contents=/etc/hosts", "f"],
        vec!["blame", "--ignore-revs-file", "/etc/hosts", "f"],
        vec!["blame", "-S", "/etc/hosts", "f"],
        vec!["blame", "-wS", "/etc/hosts", "f"],
    ] {
        let err = g.plan(&req("git", &args, d.path())).unwrap_err();
        assert!(
            matches!(err, ShellError::ArgumentRefused { .. }),
            "git {args:?} must be refused, got {err:?}"
        );
    }
}

#[test]
fn abbreviated_forms_of_denied_git_options_are_refused() {
    let d = tmp();
    let g = git_runner();
    for args in [
        vec!["blame", "--con", "/etc/hosts", "f"],
        vec!["blame", "--conte=/etc/hosts", "f"],
        vec!["blame", "--ignore-rev", "/etc/hosts", "f"],
        vec!["blame", "--textc", "f"],
        vec!["diff", "--outp=/tmp/x"],
        vec!["diff", "--ext-d"],
    ] {
        let err = g.plan(&req("git", &args, d.path())).unwrap_err();
        assert!(
            matches!(err, ShellError::ArgumentRefused { .. }),
            "git {args:?} must be refused, got {err:?}"
        );
    }
}

#[test]
fn ordinary_git_read_options_still_plan() {
    let d = tmp();
    let g = git_runner();
    for args in [
        vec!["log", "--oneline", "--stat", "--", "f"],
        vec!["log", "-Sneedle"],
        vec!["diff", "--text", "--name-only", "--cc"],
        vec!["ls-files", "--exclude-standard"],
        vec!["blame", "-w", "-L", "1,5", "f"],
    ] {
        g.plan(&req("git", &args, d.path()))
            .unwrap_or_else(|e| panic!("git {args:?} should plan, got {e:?}"));
    }
}

#[test]
fn git_blame_does_not_run_textconv_drivers() {
    let d = tmp();
    let repo = d.path();
    let git = |args: &[&str]| {
        let st = std::process::Command::new("/usr/bin/git")
            .args(args)
            .current_dir(repo)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .expect("git");
        assert!(st.success(), "git {args:?}");
    };
    git(&["init", "-q"]);
    std::fs::write(repo.join("f"), "a\n").expect("write");
    git(&["add", "f"]);
    git(&[
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@t",
        "commit",
        "-qm",
        "m",
    ]);
    let marker = repo.join("textconv-ran");
    git(&[
        "config",
        "diff.probe.textconv",
        &format!("touch {} ; cat", marker.display()),
    ]);
    std::fs::write(repo.join(".git/info/attributes"), "f diff=probe\n").expect("attrs");

    let plan = git_runner()
        .plan(&req("git", &["blame", "f"], repo))
        .expect("plan");
    assert!(plan.args.iter().any(|a| a == "--no-textconv"), "{plan:?}");

    let r = git_runner()
        .run(&req("git", &["blame", "f"], repo))
        .expect("run");
    assert_eq!(r.exit_code, Some(0), "{r:?}");
    assert!(!marker.exists(), "blame ran a repository textconv driver");
}

// ---------------------------------------------------------------- scratch HOME links (HUP-S6)

#[test]
fn home_links_appear_in_the_scratch_home_and_leave_with_it() {
    let d = tmp();
    let target = d.path().join("solc-0.8.36");
    std::fs::write(&target, "#!/bin/sh\n").expect("target");
    let policy = ShellPolicy::new(test_allowlist(), sys_path())
        .expect("policy")
        .with_home_links(vec![(
            PathBuf::from(".svm/0.8.36/solc-0.8.36"),
            target.clone(),
        )])
        .expect("links");
    let r = open_runner(policy)
        .run(&req(
            "sh",
            &[
                "-c",
                "readlink \"$HOME/.svm/0.8.36/solc-0.8.36\"; printenv HOME",
            ],
            d.path(),
        ))
        .expect("run");
    let mut lines = r.stdout.lines();
    assert_eq!(
        lines.next().map(PathBuf::from),
        Some(target),
        "{}",
        r.stdout
    );
    let home = PathBuf::from(lines.next().unwrap_or_default());
    assert!(!home.exists(), "the scratch HOME and its links are removed");
}

#[test]
fn home_links_must_stay_inside_home_and_point_at_absolute_targets() {
    for (rel, target) in [
        ("../escape", "/bin/sh"),
        ("/abs/path", "/bin/sh"),
        ("", "/bin/sh"),
        (".svm/x", "relative/solc"),
    ] {
        let r = ShellPolicy::new(test_allowlist(), sys_path())
            .expect("policy")
            .with_home_links(vec![(PathBuf::from(rel), PathBuf::from(target))]);
        assert!(
            matches!(r, Err(ShellError::InvalidPolicy { .. })),
            "{rel} -> {target}"
        );
    }
}

#[test]
fn a_helper_programs_python_environment_is_readable_only_when_named() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmp();
    let base = d.path().canonicalize().expect("canonical");
    // A pipx-style venv with crytic-compile, linked from a bin folder on the search path.
    let env = base.join("venvs/slither");
    std::fs::create_dir_all(env.join("bin")).expect("venv");
    std::fs::write(env.join("pyvenv.cfg"), "home = /usr/bin\n").expect("cfg");
    let entry = env.join("bin/crytic-compile");
    std::fs::write(&entry, "#!/bin/sh\n").expect("entry");
    std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let local_bin = base.join("local-bin");
    std::fs::create_dir_all(&local_bin).expect("bin");
    std::os::unix::fs::symlink(&entry, local_bin.join("crytic-compile")).expect("link");
    let mut path = sys_path();
    path.push(local_bin);
    let plan = |helpers: &[&str]| {
        open_runner(
            ShellPolicy::new(test_allowlist(), path.clone())
                .expect("policy")
                .with_helper_programs(helpers),
        )
        .plan(&req("echo", &["x"], d.path()))
        .expect("plan")
        .read_roots
    };
    assert!(
        plan(&["crytic-compile"]).contains(&env),
        "the helper's venv is readable"
    );
    assert!(!plan(&[]).contains(&env), "not without naming the helper");
    // The allowlist is unchanged: the helper itself cannot be run.
    let r = open_runner(
        ShellPolicy::new(test_allowlist(), path.clone())
            .expect("policy")
            .with_helper_programs(&["crytic-compile"]),
    )
    .run(&req("crytic-compile", &["."], d.path()));
    assert!(matches!(r, Err(ShellError::ProgramNotAllowed { .. })));
}
