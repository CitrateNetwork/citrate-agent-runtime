//! Windows implementations of the runner's process-tree and scratch-directory guarantees.
//!
//! - **Process tree.** Unix makes the child the leader of a new process group and kills the
//!   group with `SIGKILL`. Windows has no process groups that can be signalled, so every run
//!   gets its own Job Object instead: the child is created suspended, assigned to the job, and
//!   only then resumed, so nothing it starts can escape the job (children inherit job
//!   membership, and breakaway is not permitted). [`Job::kill`] is `TerminateJobObject`, which
//!   ends every process in the tree; the job also carries `KILL_ON_JOB_CLOSE`, so if the
//!   runner (or the whole sidecar) goes away, closing the last handle reaps the tree too.
//! - **Process creation flags.** `CREATE_NEW_PROCESS_GROUP` keeps a console Ctrl+C/Ctrl+Break
//!   aimed at the host from reaching the child (and vice versa), the same isolation a new
//!   Unix process group gives; `CREATE_NO_WINDOW` stops a console program spawned from the
//!   GUI-hosted sidecar from opening a console window; `CREATE_SUSPENDED` closes the race
//!   between process creation and job assignment.
//! - **Scratch HOME.** Unix creates it with mode `0700`. Windows has no mode bits; the
//!   directory is created with an explicit *protected* DACL (`D:P`, no inheritance from the
//!   parent) that grants full control to the owner (`OW`) and to `SYSTEM` (`SY`) only, inherited
//!   by everything created inside it. That is the ACL equivalent of `0700`: other users get
//!   nothing, regardless of what `%TEMP%`'s own ACL allows.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::process::Child;

use windows_sys::Win32::Foundation::{LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    OpenThread, ResumeThread, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    THREAD_SUSPEND_RESUME,
};

/// Creation flags for every child the runner starts. The child must then be handed to
/// [`Job::adopt`], which assigns it to the job and resumes it.
pub(crate) const CREATION_FLAGS: u32 =
    CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW | CREATE_SUSPENDED;

/// Exit code given to processes ended by [`Job::kill`] (a timeout or leftover reaping).
const KILLED_EXIT_CODE: u32 = 1;

/// The protected DACL for a scratch directory: owner and SYSTEM, full control, inherited by
/// files and subdirectories; nothing inherited from the parent.
const SCRATCH_SDDL: &str = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)";

/// A Job Object that holds one run's whole process tree.
pub(crate) struct Job {
    handle: OwnedHandle,
}

impl Job {
    /// A new anonymous job with `KILL_ON_JOB_CLOSE`.
    pub(crate) fn new() -> io::Result<Self> {
        // SAFETY: both pointer arguments may be null (default security, unnamed job).
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a freshly created, valid handle that nothing else owns.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `info` is a correctly sized, initialised JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        // that outlives the call; the handle is valid.
        let ok = unsafe {
            SetInformationJobObject(
                handle.as_raw_handle() as HANDLE,
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle })
    }

    fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle() as HANDLE
    }

    /// Put a child spawned with [`CREATION_FLAGS`] (so still suspended) into the job, then
    /// resume it. On error the caller must kill and reap the child: it never ran.
    pub(crate) fn adopt(&self, child: &Child) -> io::Result<()> {
        // SAFETY: both handles are valid for the duration of the call.
        let ok = unsafe { AssignProcessToJobObject(self.raw(), child.as_raw_handle() as HANDLE) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        resume_threads(child.id())
    }

    /// End every process in the job. Ending an empty job is a successful no-op; an error
    /// (which would mean the handle is unusable) is ignored, as on Unix, because closing the
    /// handle on drop still kills the tree via `KILL_ON_JOB_CLOSE`.
    pub(crate) fn kill(&self) {
        // SAFETY: the job handle is valid.
        unsafe {
            TerminateJobObject(self.raw(), KILLED_EXIT_CODE);
        }
    }

    /// Processes currently alive in the job.
    #[cfg(test)]
    pub(crate) fn active_processes(&self) -> io::Result<u32> {
        use windows_sys::Win32::System::JobObjects::{
            JobObjectBasicAccountingInformation, QueryInformationJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        };
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: `info` is a correctly sized output buffer that outlives the call.
        let ok = unsafe {
            QueryInformationJobObject(
                self.raw(),
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info.ActiveProcesses)
    }
}

/// Resume every thread of process `pid` (a process created suspended has exactly one).
fn resume_threads(pid: u32) -> io::Result<()> {
    // SAFETY: TH32CS_SNAPTHREAD ignores the process id argument; the result is checked.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snap == INVALID_HANDLE_VALUE || snap.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `snap` is a valid handle that nothing else owns; dropping it closes it.
    let snap = unsafe { OwnedHandle::from_raw_handle(snap as RawHandle) };
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut resumed = 0usize;
    // SAFETY: `entry.dwSize` is set as the API requires; the snapshot handle is valid.
    let mut more = unsafe { Thread32First(snap.as_raw_handle() as HANDLE, &mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == pid {
            // SAFETY: OpenThread with a thread id from the snapshot; the result is checked.
            let t = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if t.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `t` is a valid thread handle that nothing else owns.
            let t = unsafe { OwnedHandle::from_raw_handle(t as RawHandle) };
            // SAFETY: the thread handle is valid and has THREAD_SUSPEND_RESUME.
            if unsafe { ResumeThread(t.as_raw_handle() as HANDLE) } == u32::MAX {
                return Err(io::Error::last_os_error());
            }
            resumed += 1;
        }
        // SAFETY: as for Thread32First.
        more = unsafe { Thread32Next(snap.as_raw_handle() as HANDLE, &mut entry) } != 0;
    }
    if resumed == 0 {
        return Err(io::Error::other(format!(
            "no thread of process {pid} found to resume"
        )));
    }
    Ok(())
}

/// Create `path` as a new directory (failing if it exists) with the owner-and-SYSTEM-only
/// protected DACL described in the module docs.
pub(crate) fn create_private_dir(path: &Path) -> io::Result<()> {
    let sddl = wide(OsStr::new(SCRATCH_SDDL));
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated and outlives the call; `sd` receives a LocalAlloc'd
    // descriptor that is freed below; the size out-pointer may be null.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let attrs = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let p = wide(path.as_os_str());
    // SAFETY: `p` is NUL-terminated; `attrs` and the descriptor it points at are valid.
    let created = unsafe { CreateDirectoryW(p.as_ptr(), &attrs) };
    let err = io::Error::last_os_error();
    // SAFETY: `sd` was allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
    unsafe {
        LocalFree(sd);
    }
    if created == 0 {
        return Err(err);
    }
    Ok(())
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn system32(program: &str) -> std::path::PathBuf {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        Path::new(&root).join("System32").join(program)
    }

    #[test]
    fn job_kill_ends_the_child_and_its_descendants() {
        let job = Job::new().expect("job");
        // cmd starts a grandchild ping and then waits on its own ping; both live ~30s.
        let mut child = Command::new(system32("cmd.exe"))
            .args([
                "/d",
                "/c",
                "start",
                "/b",
                "ping",
                "-n",
                "30",
                "127.0.0.1",
                "&",
                "ping",
                "-n",
                "30",
                "127.0.0.1",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags_for_test()
            .spawn()
            .expect("spawn");
        job.adopt(&child).expect("adopt");
        let t = Instant::now();
        while job.active_processes().expect("query") < 3 && t.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            job.active_processes().expect("query") >= 3,
            "tree did not start"
        );
        job.kill();
        let status = child.wait().expect("wait");
        assert_eq!(status.code(), Some(KILLED_EXIT_CODE as i32));
        let t = Instant::now();
        while job.active_processes().expect("query") > 0 && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(job.active_processes().expect("query"), 0);
    }

    #[test]
    fn closing_the_job_kills_the_tree() {
        let job = Job::new().expect("job");
        let mut child = Command::new(system32("PING.EXE"))
            .args(["-n", "30", "127.0.0.1"])
            .stdout(Stdio::null())
            .creation_flags_for_test()
            .spawn()
            .expect("spawn");
        job.adopt(&child).expect("adopt");
        drop(job);
        // ping -n 30 runs ~29s; returning at once means closing the job ended it. (The exit
        // code of a process ended by job close is not specified, so it is not asserted.)
        let t = Instant::now();
        child.wait().expect("wait");
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    }

    #[test]
    fn private_dir_is_created_once_and_is_usable() {
        let base = tempfile::tempdir().expect("tempdir");
        let p = base.path().join("scratch");
        create_private_dir(&p).expect("create");
        assert!(p.is_dir());
        std::fs::write(p.join("f"), b"x").expect("write inside");
        assert_eq!(
            create_private_dir(&p).expect_err("exists").kind(),
            io::ErrorKind::AlreadyExists
        );
        std::fs::remove_dir_all(&p).expect("remove");
    }

    trait ForTest {
        fn creation_flags_for_test(&mut self) -> &mut Self;
    }
    impl ForTest for Command {
        fn creation_flags_for_test(&mut self) -> &mut Self {
            use std::os::windows::process::CommandExt;
            self.creation_flags(CREATION_FLAGS)
        }
    }
}
