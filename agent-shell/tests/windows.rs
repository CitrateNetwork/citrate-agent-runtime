//! Windows red-green suite for the shell allowlist runner.
//!
//! Real system programs (`cmd.exe`, `PING.EXE`, `hostname.exe` from `%SystemRoot%\System32`)
//! run through the real runner, so these prove the Windows process-tree, environment, cwd and
//! scratch-directory behaviour against the OS. They run in the `windows-latest` CI job.
#![cfg(windows)]

use citrate_agent_shell::sandbox::{SandboxMode, SandboxPolicy};
use citrate_agent_shell::{Allowlist, ArgPolicy, RunRequest, ShellError, ShellPolicy, ShellRunner};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn runner() -> ShellRunner {
    let allow = Allowlist::empty()
        .allow("cmd", ArgPolicy::Any)
        .allow("ping", ArgPolicy::Any)
        .allow("hostname", ArgPolicy::Any);
    ShellRunner::new(
        ShellPolicy::new(allow, ShellPolicy::default_search_path()).expect("policy"),
        |_p: &Path| Ok(()),
    )
}

fn req(program: &str, args: &[&str], cwd: &Path) -> RunRequest {
    RunRequest::new(program, args.iter().map(|s| s.to_string()).collect(), cwd)
}

#[test]
fn a_system_program_resolves_runs_and_reports() {
    let d = tempfile::tempdir().expect("tempdir");
    let r = runner().run(&req("hostname", &[], d.path())).expect("run");
    assert!(r.passed(), "{r:?}");
    assert_eq!(r.exit_code, Some(0));
    assert_eq!(r.signal, None);
    assert!(r
        .resolved_path
        .to_string_lossy()
        .to_ascii_lowercase()
        .ends_with("\\system32\\hostname.exe"));
    assert!(!r.stdout.trim().is_empty());
}

#[test]
fn timeout_terminates_the_job_and_reports_it() {
    let d = tempfile::tempdir().expect("tempdir");
    let t = Instant::now();
    let r = runner()
        .run(&req("ping", &["-n", "60", "127.0.0.1"], d.path()).timeout(Duration::from_millis(500)))
        .expect("run");
    assert!(r.timed_out, "{r:?}");
    assert!(!r.passed());
    assert_eq!(r.signal, None, "Windows has no signals");
    assert_eq!(r.exit_code, Some(1), "TerminateJobObject exit code");
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
}

#[test]
fn a_grandchild_left_behind_is_reaped_with_the_job() {
    // cmd starts a background ping that inherits stdout, then exits at once. Without the job
    // the ping would hold the pipe for ~60s and the capture would end incomplete after the
    // drain grace; with it, the post-exit reap ends the ping and the pipe closes.
    let d = tempfile::tempdir().expect("tempdir");
    let t = Instant::now();
    let r = runner()
        .run(&req(
            "cmd",
            &[
                "/d",
                "/c",
                "start",
                "/b",
                "ping",
                "-n",
                "60",
                "127.0.0.1",
                "&",
                "exit",
                "0",
            ],
            d.path(),
        ))
        .expect("run");
    assert!(!r.timed_out, "{r:?}");
    assert!(!r.output_incomplete, "grandchild survived: {r:?}");
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
}

#[test]
fn environment_is_scrubbed_and_scratch_is_private_to_the_run() {
    let d = tempfile::tempdir().expect("tempdir");
    let r = runner()
        .run(&req("cmd", &["/d", "/c", "set"], d.path()))
        .expect("run");
    assert!(r.passed(), "{r:?}");
    let get = |name: &str| {
        r.stdout.lines().find_map(|l| {
            let (k, v) = l.split_once('=')?;
            k.eq_ignore_ascii_case(name)
                .then(|| v.trim_end().to_string())
        })
    };
    let home = PathBuf::from(get("HOME").expect("HOME"));
    for name in [
        "USERPROFILE",
        "TEMP",
        "TMP",
        "TMPDIR",
        "APPDATA",
        "LOCALAPPDATA",
    ] {
        assert_eq!(get(name).map(PathBuf::from), Some(home.clone()), "{name}");
    }
    assert!(
        get("SystemRoot").is_some(),
        "SystemRoot must reach the child"
    );
    assert_eq!(get("NO_COLOR").as_deref(), Some("1"));
    let path = get("PATH").expect("PATH");
    assert!(path.contains(';') && !path.contains("\\?\\"), "{path}");
    // Host identity variables are not passed through.
    assert_eq!(get("USERNAME"), None);
    assert_eq!(get("USERDOMAIN"), None);
    assert!(
        !home.exists(),
        "scratch {home:?} must be removed after the run"
    );
}

#[test]
fn the_child_cwd_is_a_plain_drive_path() {
    let d = tempfile::tempdir().expect("tempdir");
    let r = runner()
        .run(&req("cmd", &["/d", "/c", "cd"], d.path()))
        .expect("run");
    assert!(r.passed(), "{r:?}");
    let cwd = r.stdout.trim();
    assert!(!cwd.starts_with("\\\\?\\"), "{cwd}");
    let want = std::fs::canonicalize(d.path()).expect("canon");
    assert_eq!(std::fs::canonicalize(cwd).expect("canon cwd"), want);
}

#[test]
fn scripts_are_never_resolved() {
    let d = tempfile::tempdir().expect("tempdir");
    std::fs::write(d.path().join("tool.cmd"), b"@echo pwned").expect("write");
    let r = ShellRunner::new(
        ShellPolicy::new(
            Allowlist::empty().allow("tool", ArgPolicy::Any),
            vec![d.path().to_path_buf()],
        )
        .expect("policy"),
        |_p: &Path| Ok(()),
    );
    assert!(matches!(
        r.run(&req("tool", &[], d.path())),
        Err(ShellError::ProgramNotFound { .. })
    ));
}

#[test]
fn required_sandbox_is_refused_on_windows() {
    let d = tempfile::tempdir().expect("tempdir");
    let allow = Allowlist::empty().allow("hostname", ArgPolicy::Any);
    let r = ShellRunner::new(
        ShellPolicy::new(allow, ShellPolicy::default_search_path())
            .expect("policy")
            .with_sandbox(SandboxPolicy::new(SandboxMode::Required)),
        |_p: &Path| Ok(()),
    );
    match r.run(&req("hostname", &[], d.path())) {
        Err(ShellError::SandboxUnavailable { reason }) => {
            assert!(reason.contains("Windows"), "{reason}")
        }
        other => panic!("expected SandboxUnavailable, got {other:?}"),
    }
}
