//! Windows red-green suite for the shell allowlist runner.
//!
//! Real system programs (`cmd.exe`, `PING.EXE`, `hostname.exe` from `%SystemRoot%\System32`)
//! run through the real runner, so these prove the Windows process-tree, environment, cwd and
//! scratch-directory behaviour against the OS. They run in the `windows-latest` CI job.
#![cfg(windows)]

use citrate_agent_shell::sandbox::{SandboxMode, SandboxPolicy, SandboxSummary};
use citrate_agent_shell::{
    Allowlist, ArgPolicy, RunReport, RunRequest, ShellError, ShellPolicy, ShellRunner,
};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const HELPER_MODE: &str = "CITRATE_SHELL_WINDOWS_HELPER_MODE";
const DESCENDANT_ROLE: &str = "CITRATE_SHELL_WINDOWS_DESCENDANT";

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

fn helper_runner() -> (ShellRunner, String) {
    let exe = std::env::current_exe().expect("current test executable");
    let program = exe
        .file_name()
        .expect("test executable name")
        .to_string_lossy()
        .into_owned();
    let search_path = vec![exe
        .parent()
        .expect("test executable directory")
        .to_path_buf()];
    let policy = ShellPolicy::new(
        Allowlist::empty().allow(&program, ArgPolicy::Any),
        search_path,
    )
    .expect("helper policy")
    .with_request_env_allow(&[HELPER_MODE]);
    (ShellRunner::new(policy, |_p: &Path| Ok(())), program)
}

fn helper_request(program: &str, mode: &str, cwd: &Path, timeout: Duration) -> RunRequest {
    req(
        program,
        &[
            "--exact",
            "windows_job_leader_helper",
            "--nocapture",
            "--test-threads=1",
        ],
        cwd,
    )
    .env(HELPER_MODE, mode)
    .timeout(timeout)
}

fn scratch_from_output(output: &str) -> PathBuf {
    output
        .lines()
        .find_map(|line| {
            line.find("SCRATCH=")
                .map(|at| PathBuf::from(line[at + "SCRATCH=".len()..].trim()))
        })
        .expect("helper reported its scratch path")
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < deadline, "timed out waiting for {path:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn windows_job_leader_helper() {
    let Ok(mode) = std::env::var(HELPER_MODE) else {
        return;
    };
    let scratch = PathBuf::from(std::env::var_os("HOME").expect("helper HOME"));
    println!("\nSCRATCH={}", scratch.display());
    std::io::stdout().flush().expect("flush scratch path");

    let mut descendant = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "windows_job_descendant_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(DESCENDANT_ROLE, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn descendant helper");
    wait_for_file(&scratch.join("descendant-ready"));
    println!("LEADER_READY");
    std::io::stdout().flush().expect("flush leader marker");

    match mode.as_str() {
        "normal" => drop(descendant),
        "timeout" => {
            let _keep_process_handle_open = &mut descendant;
            std::thread::sleep(Duration::from_secs(60));
        }
        other => panic!("unknown helper mode {other:?}"),
    }
}

#[test]
fn windows_job_descendant_helper() {
    if std::env::var(DESCENDANT_ROLE).as_deref() != Ok("1") {
        return;
    }
    let scratch = PathBuf::from(std::env::var_os("HOME").expect("descendant HOME"));
    let _exclusive = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(scratch.join("exclusive-handle"))
        .expect("open exclusive scratch handle");
    println!("DESCENDANT_READY");
    std::io::stdout().flush().expect("flush descendant marker");
    std::fs::write(scratch.join("descendant-ready"), b"ready").expect("write ready marker");
    std::thread::sleep(Duration::from_secs(60));
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
    assert!(r.cleanup_error.is_none(), "{r:?}");
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
}

#[test]
fn normal_leader_exit_reaps_descendant_before_scratch_removal() {
    let d = tempfile::tempdir().expect("tempdir");
    let (runner, program) = helper_runner();
    let started = Instant::now();
    let r = runner
        .run(&helper_request(
            &program,
            "normal",
            d.path(),
            Duration::from_secs(20),
        ))
        .expect("run");
    let scratch = scratch_from_output(&r.stdout);

    assert!(r.passed(), "{r:?}");
    assert!(!r.timed_out, "{r:?}");
    assert!(!r.output_incomplete, "{r:?}");
    assert!(r.cleanup_error.is_none(), "{r:?}");
    assert!(r.stdout.contains("LEADER_READY"), "{r:?}");
    assert!(!scratch.exists(), "scratch {scratch:?} survived the run");
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "run took {:?}",
        started.elapsed()
    );
}

#[test]
fn timeout_reaps_descendant_before_scratch_removal() {
    let d = tempfile::tempdir().expect("tempdir");
    let (runner, program) = helper_runner();
    let started = Instant::now();
    let r = runner
        .run(&helper_request(
            &program,
            "timeout",
            d.path(),
            Duration::from_secs(20),
        ))
        .expect("run");
    let scratch = scratch_from_output(&r.stdout);

    assert!(r.timed_out, "{r:?}");
    assert!(!r.passed(), "{r:?}");
    assert_eq!(r.exit_code, Some(1), "{r:?}");
    assert!(!r.output_incomplete, "{r:?}");
    assert!(r.cleanup_error.is_none(), "{r:?}");
    assert!(r.stdout.contains("LEADER_READY"), "{r:?}");
    assert!(!scratch.exists(), "scratch {scratch:?} survived the run");
    assert!(
        started.elapsed() < Duration::from_secs(40),
        "run took {:?}",
        started.elapsed()
    );
}

#[test]
fn cleanup_error_makes_serialized_report_fail() {
    let report = RunReport {
        program: "tool".into(),
        resolved_path: PathBuf::from("tool.exe"),
        args: Vec::new(),
        cwd: PathBuf::from("C:\\work"),
        exit_code: Some(0),
        signal: None,
        timed_out: false,
        timeout_ms: 20_000,
        duration_ms: 10,
        stdout: String::new(),
        stderr: String::new(),
        stdout_bytes: 0,
        stderr_bytes: 0,
        stdout_truncated: false,
        stderr_truncated: false,
        output_incomplete: false,
        cleanup_error: Some("cleanup failed".into()),
        sandbox: SandboxSummary {
            backend: "none".into(),
            enforced: false,
            network: "allowed".into(),
            writable: Vec::new(),
            readable_extra: Vec::new(),
            summary: "test".into(),
        },
    };

    assert!(!report.passed());
    assert_eq!(report.to_json()["passed"], false);
    assert_eq!(report.to_json()["cleanup_error"], "cleanup failed");
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
