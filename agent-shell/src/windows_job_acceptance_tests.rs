use crate::{win, PendingTree, ProcessTree};
use std::fs;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    GetHandleInformation, ERROR_INVALID_HANDLE, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::System::JobObjects::{
    IsProcessInJob, JobObjectBasicAccountingInformation, QueryInformationJobObject,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE,
};

const ROLE_ENV: &str = "CITRATE_S10_WINDOWS_ROLE";
const MARKER_ENV: &str = "CITRATE_S10_WINDOWS_MARKER";
const JOB_HANDLE_ENV: &str = "CITRATE_S10_WINDOWS_JOB_HANDLE";
const DESCENDANT_ID_ENV: &str = "CITRATE_S10_WINDOWS_DESCENDANT_ID";
const OWNER_ID_ENV: &str = "CITRATE_S10_WINDOWS_OWNER_ID";

const MARKER_HELPER: &str = "windows_job_acceptance_tests::windows_s10_marker_helper";
const QUERY_HELPER: &str = "windows_job_acceptance_tests::windows_s10_job_handle_query_helper";
const OWNER_HELPER: &str = "windows_job_acceptance_tests::windows_s10_job_owner_helper";
const LEADER_HELPER: &str = "windows_job_acceptance_tests::windows_s10_job_leader_helper";
const DESCENDANT_HELPER: &str = "windows_job_acceptance_tests::windows_s10_job_descendant_helper";

const PHASE_TIMEOUT: Duration = Duration::from_secs(10);
const PRE_ADOPTION_OBSERVATION: Duration = Duration::from_millis(200);
const WATCHDOG_TIMEOUT: Duration = Duration::from_secs(5);

static NONCE_SEQ: AtomicU64 = AtomicU64::new(0);

struct ChildWatchdog {
    child: Child,
}

impl ChildWatchdog {
    fn spawn(command: &mut Command) -> io::Result<Self> {
        command.spawn().map(|child| Self { child })
    }

    fn child(&self) -> &Child {
        &self.child
    }

    fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    fn wait_until(&mut self, deadline: Instant) -> io::Result<ExitStatus> {
        wait_for_signal(child_handle(&self.child), deadline, "helper process")?;
        self.child.wait()
    }

    fn terminate_and_reap_until(&mut self, deadline: Instant) -> io::Result<ExitStatus> {
        match wait_state(child_handle(&self.child), Duration::ZERO)? {
            WAIT_OBJECT_0 => return self.child.wait(),
            WAIT_TIMEOUT => {}
            other => return Err(unexpected_wait_result("helper process", other)),
        }

        let kill_error = self.child.kill().err();
        match wait_for_signal(child_handle(&self.child), deadline, "terminated helper process") {
            Ok(()) => self.child.wait(),
            Err(wait_error) => Err(match kill_error {
                Some(kill_error) => io::Error::other(format!(
                    "could not terminate helper process: {kill_error}; could not reap it: {wait_error}"
                )),
                None => wait_error,
            }),
        }
    }
}

impl Drop for ChildWatchdog {
    fn drop(&mut self) {
        let _ = self.terminate_and_reap_until(Instant::now() + WATCHDOG_TIMEOUT);
    }
}

fn nonce(label: &str) -> String {
    format!(
        "{label}-{}-{}",
        std::process::id(),
        NONCE_SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

fn helper_nonce(role: &str) -> Option<String> {
    let value = std::env::var(ROLE_ENV).ok()?;
    value
        .strip_prefix(role)
        .and_then(|rest| rest.strip_prefix(':'))
        .filter(|nonce| !nonce.is_empty())
        .map(str::to_owned)
}

fn required_path_env(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("missing {name}")))
}

fn required_string_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing {name}"))
}

fn helper_command(test_name: &str, role: &str, nonce: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("current test executable"));
    command
        .args([
            "--ignored",
            "--exact",
            test_name,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ROLE_ENV, format!("{role}:{nonce}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn suspended_marker_helper(marker: &Path, nonce: &str) -> ChildWatchdog {
    let mut command = helper_command(MARKER_HELPER, "marker", nonce);
    command
        .env(MARKER_ENV, marker)
        .creation_flags(win::CREATION_FLAGS);
    ChildWatchdog::spawn(&mut command).expect("spawn suspended marker helper")
}

fn child_handle(child: &Child) -> HANDLE {
    child.as_raw_handle() as HANDLE
}

fn duration_millis(duration: Duration) -> u32 {
    if duration.is_zero() {
        return 0;
    }
    u32::try_from(duration.as_millis().max(1)).unwrap_or(u32::MAX)
}

fn wait_state(handle: HANDLE, timeout: Duration) -> io::Result<u32> {
    // SAFETY: the caller keeps `handle` alive for the duration of this bounded wait.
    let result = unsafe { WaitForSingleObject(handle, duration_millis(timeout)) };
    if result == u32::MAX {
        return Err(io::Error::last_os_error());
    }
    Ok(result)
}

fn unexpected_wait_result(context: &str, result: u32) -> io::Error {
    io::Error::other(format!(
        "WaitForSingleObject returned unexpected value {result:#x} for {context}"
    ))
}

fn wait_for_signal(handle: HANDLE, deadline: Instant, context: &str) -> io::Result<()> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    match wait_state(handle, timeout)? {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("timed out waiting for {context}"),
        )),
        other => Err(unexpected_wait_result(context, other)),
    }
}

fn assert_process_running(child: &Child, observation: Duration) {
    assert_eq!(
        wait_state(child_handle(child), observation).expect("query helper liveness"),
        WAIT_TIMEOUT,
        "helper exited during the pre-adoption observation window"
    );
}

fn read_file_while_process_runs(
    path: &Path,
    process: HANDLE,
    deadline: Instant,
) -> io::Result<String> {
    loop {
        match fs::read_to_string(path) {
            Ok(value) => return Ok(value),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("timed out waiting for {}", path.display()),
            ));
        }
        let slice = (deadline - now).min(Duration::from_millis(20));
        match wait_state(process, slice)? {
            WAIT_TIMEOUT => {}
            WAIT_OBJECT_0 => {
                return fs::read_to_string(path).map_err(|error| {
                    io::Error::other(format!(
                        "helper exited before writing {}: {error}",
                        path.display()
                    ))
                });
            }
            other => return Err(unexpected_wait_result("marker-producing helper", other)),
        }
    }
}

fn create_event() -> io::Result<OwnedHandle> {
    // SAFETY: null security attributes and name request an anonymous, non-inheritable event.
    let raw = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh handle uniquely owned by the caller.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) })
}

fn open_process(pid: u32) -> io::Result<OwnedHandle> {
    // SAFETY: OpenProcess accepts any process id; the result is checked and is non-inheritable.
    let raw = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        )
    };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh handle uniquely owned by the caller.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) })
}

fn assert_process_in_job(job: HANDLE, process: HANDLE, label: &str) {
    let mut in_job = 0;
    // SAFETY: both handles remain valid for the call and `in_job` is a valid output pointer.
    let ok = unsafe { IsProcessInJob(process, job, &mut in_job) };
    if ok == 0 {
        let error = io::Error::last_os_error();
        panic!("could not query {label} Job membership: {error}");
    }
    assert_ne!(in_job, 0, "{label} was not captured by the Job Object");
}

fn write_atomic(path: &Path, nonce: &str, contents: &str) -> io::Result<()> {
    let temporary = path.with_extension(format!("{nonce}.tmp"));
    fs::write(&temporary, contents)?;
    fs::rename(temporary, path)
}

fn hold_for_owner_cleanup() {
    let event = create_event().expect("create helper hold event");
    assert_eq!(
        wait_state(event.as_raw_handle() as HANDLE, PHASE_TIMEOUT).expect("wait on hold event"),
        WAIT_TIMEOUT,
        "anonymous hold event unexpectedly became signalled"
    );
}

#[test]
#[ignore = "spawned as a suspended S10.0 subprocess"]
fn windows_s10_marker_helper() {
    let Some(nonce) = helper_nonce("marker") else {
        return;
    };
    fs::write(required_path_env(MARKER_ENV), nonce).expect("write marker nonce");
}

#[test]
#[ignore = "spawned to probe the parent's numeric Job handle"]
fn windows_s10_job_handle_query_helper() {
    let Some(nonce) = helper_nonce("query") else {
        return;
    };
    let marker = required_path_env(MARKER_ENV);
    let numeric = required_string_env(JOB_HANDLE_ENV)
        .parse::<usize>()
        .expect("numeric parent Job handle");
    let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    // SAFETY: the numeric value is deliberately probed in this process. `info` is a valid
    // output buffer, and a failed call is the expected proof that the handle was not inherited.
    let ok = unsafe {
        QueryInformationJobObject(
            numeric as HANDLE,
            JobObjectBasicAccountingInformation,
            (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        let error = io::Error::last_os_error();
        fs::write(marker, format!("{nonce}:query-failed:{error}"))
            .expect("write failed-query marker");
        return;
    }

    fs::write(
        marker,
        format!("{nonce}:query-succeeded:{}", info.ActiveProcesses),
    )
    .expect("write unexpected-query marker");
    panic!("the adopted child queried the parent's numeric Job handle");
}

#[test]
#[ignore = "spawned as the descendant captured by the owner helper's Job"]
fn windows_s10_job_descendant_helper() {
    if helper_nonce("descendant").is_none() {
        return;
    }
    hold_for_owner_cleanup();
}

#[test]
#[ignore = "spawned as the leader captured by the owner helper's Job"]
fn windows_s10_job_leader_helper() {
    let Some(nonce) = helper_nonce("leader") else {
        return;
    };
    let descendant_id = required_path_env(DESCENDANT_ID_ENV);
    let mut command = helper_command(DESCENDANT_HELPER, "descendant", &nonce);
    let descendant = ChildWatchdog::spawn(&mut command).expect("spawn descendant helper");
    assert_process_running(descendant.child(), PRE_ADOPTION_OBSERVATION);
    write_atomic(&descendant_id, &nonce, &descendant.child().id().to_string())
        .expect("publish descendant identity");
    hold_for_owner_cleanup();
}

#[test]
#[ignore = "spawned as the sole owner of the S10.0 Job handle"]
fn windows_s10_job_owner_helper() {
    let Some(nonce) = helper_nonce("owner") else {
        return;
    };
    let owner_id = required_path_env(OWNER_ID_ENV);
    let descendant_id = required_path_env(DESCENDANT_ID_ENV);
    let job = win::Job::new().expect("create owner Job");
    let mut command = helper_command(LEADER_HELPER, "leader", &nonce);
    command
        .env(DESCENDANT_ID_ENV, &descendant_id)
        .creation_flags(win::CREATION_FLAGS);
    let mut leader = ChildWatchdog::spawn(&mut command).expect("spawn suspended leader helper");
    job.adopt(leader.child()).expect("adopt and resume leader");

    let descendant_pid = read_file_while_process_runs(
        &descendant_id,
        child_handle(leader.child()),
        Instant::now() + PHASE_TIMEOUT,
    )
    .expect("read descendant identity")
    .trim()
    .parse::<u32>()
    .expect("descendant process id");
    let descendant = open_process(descendant_pid).expect("open descendant process");

    assert_process_running(leader.child(), Duration::ZERO);
    assert_eq!(
        wait_state(descendant.as_raw_handle() as HANDLE, Duration::ZERO)
            .expect("query descendant liveness"),
        WAIT_TIMEOUT,
        "descendant exited before owner published identities"
    );
    assert_process_in_job(job.raw_for_test(), child_handle(leader.child()), "leader");
    assert_process_in_job(
        job.raw_for_test(),
        descendant.as_raw_handle() as HANDLE,
        "descendant",
    );
    assert!(
        job.active_processes().expect("query owner Job") >= 2,
        "owner Job did not account for both captured processes"
    );

    write_atomic(
        &owner_id,
        &nonce,
        &format!("{nonce}\n{}\n{descendant_pid}\n", leader.child().id()),
    )
    .expect("publish captured process identities");
    hold_for_owner_cleanup();

    leader
        .terminate_and_reap_until(Instant::now() + WATCHDOG_TIMEOUT)
        .expect("clean up leader if owner was not terminated");
}

#[test]
fn windows_s10_acceptance_suspended_helper_runs_only_after_adoption() {
    let directory = tempfile::tempdir().expect("tempdir");
    let marker = directory.path().join("adopted-marker");
    let nonce = nonce("adopt");
    let pending = ProcessTree::prepare().expect("prepare production Job");
    let mut helper = suspended_marker_helper(&marker, &nonce);

    assert_process_running(helper.child(), PRE_ADOPTION_OBSERVATION);
    assert!(
        !marker.exists(),
        "suspended helper wrote its marker before Job assignment and resume"
    );

    let tree = pending
        .adopt(helper.child_mut())
        .expect("adopt and resume suspended helper");
    let status = helper
        .wait_until(Instant::now() + PHASE_TIMEOUT)
        .expect("wait for adopted helper");
    assert!(status.success(), "adopted helper failed: {status}");
    assert_eq!(fs::read_to_string(marker).expect("read marker"), nonce);
    drop(tree);
}

#[test]
fn windows_s10_acceptance_assignment_failure_reaps_suspended_helper() {
    let directory = tempfile::tempdir().expect("tempdir");
    let marker = directory.path().join("failed-adoption-marker");
    let nonce = nonce("assignment-failure");
    let wrong_object = create_event().expect("create wrong-object Event handle");
    let pending = PendingTree {
        job: win::Job::from_handle_for_test(wrong_object),
    };
    let mut helper = suspended_marker_helper(&marker, &nonce);

    assert_process_running(helper.child(), PRE_ADOPTION_OBSERVATION);
    let error = match pending.adopt(helper.child_mut()) {
        Ok(tree) => {
            drop(tree);
            panic!("Event handle unexpectedly succeeded in AssignProcessToJobObject");
        }
        Err(error) => error,
    };

    let error_text = error.to_string();
    let assignment_error = error_text
        .strip_prefix("cannot adopt the suspended process: ")
        .and_then(|rest| rest.split_once("; cleanup failed").map(|(first, _)| first))
        .unwrap_or_else(|| panic!("original assignment failure was not preserved: {error}"));
    assert_eq!(
        assignment_error,
        io::Error::from_raw_os_error(ERROR_INVALID_HANDLE as i32).to_string(),
        "wrong-object assignment did not preserve its Win32 error"
    );
    assert_eq!(
        wait_state(child_handle(helper.child()), Duration::ZERO)
            .expect("query failed-adoption helper"),
        WAIT_OBJECT_0,
        "production PendingTree cleanup left the suspended helper alive"
    );
    assert!(
        helper
            .child_mut()
            .try_wait()
            .expect("query reaped helper")
            .is_some(),
        "production PendingTree cleanup did not reap the helper"
    );
    assert!(
        !marker.exists(),
        "assignment-failure cleanup resumed the suspended helper"
    );
}

#[test]
fn windows_s10_acceptance_job_handle_is_not_inherited_or_usable() {
    let directory = tempfile::tempdir().expect("tempdir");
    let marker = directory.path().join("job-query-marker");
    let nonce = nonce("handle");
    let pending = ProcessTree::prepare().expect("prepare production Job");
    let raw_job = pending.job.raw_for_test();
    let mut flags = 0;
    // SAFETY: `raw_job` remains owned by `pending` and `flags` is a valid output pointer.
    let ok = unsafe { GetHandleInformation(raw_job, &mut flags) };
    if ok == 0 {
        let error = io::Error::last_os_error();
        panic!("GetHandleInformation failed for production Job: {error}");
    }
    assert_eq!(
        flags & HANDLE_FLAG_INHERIT,
        0,
        "production Job handle was inheritable"
    );

    let mut command = helper_command(QUERY_HELPER, "query", &nonce);
    command
        .env(MARKER_ENV, &marker)
        .env(JOB_HANDLE_ENV, (raw_job as usize).to_string())
        .creation_flags(win::CREATION_FLAGS);
    let mut helper = ChildWatchdog::spawn(&mut command).expect("spawn suspended query helper");
    let tree = pending
        .adopt(helper.child_mut())
        .expect("adopt and resume query helper");
    let status = helper
        .wait_until(Instant::now() + PHASE_TIMEOUT)
        .expect("wait for query helper");
    let result = fs::read_to_string(marker).expect("read query result");

    assert!(status.success(), "query helper failed: {status}; {result}");
    assert!(
        result.starts_with(&format!("{nonce}:query-failed:")),
        "adopted child could query the parent's numeric Job handle: {result}"
    );
    drop(tree);
}

#[test]
fn windows_s10_acceptance_owner_death_closes_job_and_terminates_tree() {
    let directory = tempfile::tempdir().expect("tempdir");
    let owner_id = directory.path().join("captured-processes");
    let descendant_id = directory.path().join("descendant-process");
    let nonce = nonce("owner");
    let mut command = helper_command(OWNER_HELPER, "owner", &nonce);
    command
        .env(OWNER_ID_ENV, &owner_id)
        .env(DESCENDANT_ID_ENV, &descendant_id);
    let mut owner = ChildWatchdog::spawn(&mut command).expect("spawn Job owner helper");

    let identities = read_file_while_process_runs(
        &owner_id,
        child_handle(owner.child()),
        Instant::now() + PHASE_TIMEOUT,
    )
    .expect("read captured process identities");
    let mut lines = identities.lines();
    assert_eq!(lines.next(), Some(nonce.as_str()), "owner nonce mismatch");
    let leader_pid = lines
        .next()
        .expect("leader process id")
        .parse::<u32>()
        .expect("numeric leader process id");
    let descendant_pid = lines
        .next()
        .expect("descendant process id")
        .parse::<u32>()
        .expect("numeric descendant process id");
    assert_ne!(leader_pid, descendant_pid);

    let leader = open_process(leader_pid).expect("open captured leader");
    let descendant = open_process(descendant_pid).expect("open captured descendant");
    for (label, process) in [("leader", &leader), ("descendant", &descendant)] {
        assert_eq!(
            wait_state(process.as_raw_handle() as HANDLE, Duration::ZERO)
                .unwrap_or_else(|error| panic!("query {label} liveness: {error}")),
            WAIT_TIMEOUT,
            "captured {label} was not alive before owner termination"
        );
    }

    owner
        .terminate_and_reap_until(Instant::now() + PHASE_TIMEOUT)
        .expect("terminate and reap Job owner");
    let tree_deadline = Instant::now() + PHASE_TIMEOUT;
    wait_for_signal(
        leader.as_raw_handle() as HANDLE,
        tree_deadline,
        "captured leader after owner death",
    )
    .expect("owner death did not terminate leader");
    wait_for_signal(
        descendant.as_raw_handle() as HANDLE,
        tree_deadline,
        "captured descendant after owner death",
    )
    .expect("owner death did not terminate descendant");
}
