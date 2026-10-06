//! HUP-S1.9 — the worker supervisor: Hermes's browser and toolchain workers run as separate
//! child processes of the sidecar, so a crash, a hang or a runaway allocation in one of them
//! never takes down the agent loop or the other worker.
//!
//! Process layout (citrate-core ADR-2026-09-30-hermes-loop-in-sidecar):
//!
//! ```text
//! citrate-core ── supervises ──> sidecar (the agent loop; restarted by core's supervisor)
//!                                  ├── supervises ──> toolchain worker (forge, slither, aderyn, medusa)
//!                                  └── supervises ──> browser worker   (HUP-S5.1, not built yet)
//! ```
//!
//! A [`Worker`] owns one child. A monitor thread spawns it, waits for it to answer a startup
//! `ping`, pings it every [`RestartPolicy::health_interval`], and when the child exits (or is
//! killed for failing [`RestartPolicy::health_failures_to_kill`] health checks in a row) it fails
//! every call in flight with [`WorkerError::Crashed`], backs off, and starts a new one. More than
//! [`RestartPolicy::max_restarts`] restarts inside [`RestartPolicy::window`] and the worker is given
//! up on: its state is [`WorkerState::Failed`] and calls are refused until the sidecar restarts.
//! [`Worker::shutdown`] (also run on drop) asks the child to stop, closes its stdin, waits
//! [`RestartPolicy::shutdown_grace`], and kills it if it is still there.
//!
//! The wire is line-delimited JSON over stdio ([`protocol`]); the child's stderr is inherited as
//! the operator log. A worker exits when its stdin closes, so it does not outlive a sidecar that
//! died without a clean shutdown.
//!
//! Honest scope: this supervises processes; it is not a sandbox. A worker runs with the sidecar's
//! user, and with the sidecar's environment unless its spec names an inherit list. On Unix each
//! worker starts a session of its own, and when it ends (crash, kill or shutdown) every process
//! left in that session is killed, so programs it started in their own process groups (a forge
//! run, say) do not outlive it. The worker is reaped only after that, so the session id it led
//! cannot have been given to another process while the session is being signalled (SCL-S0.4).
//! On Windows they may still outlive it until their own timeout.
//! Nothing here holds a key or signs (Rule 3).

pub mod protocol;

use std::collections::{HashMap, VecDeque};
use std::io::{BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;

use protocol::{Request, Response, METHOD_CALL, METHOD_PING, METHOD_SHUTDOWN};

/// Which worker this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkerKind {
    Toolchain,
    Browser,
}

impl WorkerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            WorkerKind::Toolchain => "toolchain",
            WorkerKind::Browser => "browser",
        }
    }
}

/// How to start a worker.
#[derive(Debug, Clone)]
pub struct WorkerSpec {
    pub kind: WorkerKind,
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Added to the inherited environment.
    pub env: Vec<(String, String)>,
    /// Removed from the inherited environment (least privilege: e.g. the control-plane bearer
    /// file path, which no worker needs).
    pub env_remove: Vec<String>,
    /// When set, the worker inherits only these variables (exact names, or a prefix ending in
    /// `*`), then `env` is added and `env_remove` applied. `None` = the whole environment.
    pub env_inherit: Option<Vec<String>>,
}

impl WorkerSpec {
    /// Whether `name` is on the inherit list (`true` for every name without a list).
    pub fn inherits(&self, name: &str) -> bool {
        match &self.env_inherit {
            None => true,
            Some(list) => list.iter().any(|a| match a.strip_suffix('*') {
                Some(prefix) => name.starts_with(prefix),
                None => a == name,
            }),
        }
    }
}

/// Restart, health and shutdown bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartPolicy {
    /// Restarts allowed inside `window` before the worker is given up on.
    pub max_restarts: u32,
    pub window: Duration,
    /// First backoff; doubles per restart inside the window up to `backoff_max`.
    pub backoff_base: Duration,
    pub backoff_max: Duration,
    /// How long a new child has to answer its first ping.
    pub startup_timeout: Duration,
    pub health_interval: Duration,
    pub health_timeout: Duration,
    /// Consecutive missed health checks before the child is killed and replaced.
    pub health_failures_to_kill: u32,
    /// How long a child has to exit after `shutdown` before it is killed.
    pub shutdown_grace: Duration,
}

// The default values below are conservative placeholders, pending owner sign-off (HUP-S1.9):
// 5 restarts per 60 s, 250 ms to 10 s backoff, ping every 5 s with a 2 s timeout, kill after 2
// misses, 10 s for the first ping, 3 s shutdown grace.
impl Default for RestartPolicy {
    fn default() -> Self {
        RestartPolicy {
            max_restarts: 5,
            window: Duration::from_secs(60),
            backoff_base: Duration::from_millis(250),
            backoff_max: Duration::from_secs(10),
            startup_timeout: Duration::from_secs(10),
            health_interval: Duration::from_secs(5),
            health_timeout: Duration::from_secs(2),
            health_failures_to_kill: 2,
            shutdown_grace: Duration::from_secs(3),
        }
    }
}

/// Where a worker is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkerState {
    /// A child was spawned and has not answered its first ping yet.
    Starting,
    /// Answering pings; calls are accepted.
    Running,
    /// The last child exited; a new one starts after the backoff.
    Restarting,
    /// Too many restarts inside the window (or the program cannot be started); given up.
    Failed,
    /// Shut down on request.
    Stopped,
}

/// A point-in-time report, serialized as-is on the sidecar's `/workers` route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkerStatus {
    pub kind: WorkerKind,
    pub state: WorkerState,
    /// True while the current child answers its health checks.
    pub healthy: bool,
    pub pid: Option<u32>,
    /// Restarts since this worker was created (a requested stop is not counted).
    pub restarts: u32,
    /// How the most recent child ended, e.g. `exited with code 0` or `killed by signal 9`.
    pub last_exit: Option<String>,
    /// The most recent supervisor-side problem (spawn failure, missed health checks, give-up).
    pub last_error: Option<String>,
    /// When the current child became healthy (ms since the Unix epoch).
    pub running_since_ms: Option<u64>,
}

/// Why a call did not produce a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerError {
    /// The worker is not accepting calls (failed, stopped, or still restarting at the deadline).
    NotRunning(String),
    /// The worker process ended while this call was in flight; its outcome is unknown.
    Crashed(String),
    /// No answer before the caller's deadline. The call may still be running in the worker.
    Timeout,
    /// The worker answered with an error.
    Remote(String),
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerError::NotRunning(s) => write!(f, "the worker is not running ({s})"),
            WorkerError::Crashed(s) => write!(f, "the worker process ended during the call ({s})"),
            WorkerError::Timeout => write!(f, "the worker did not answer in time"),
            WorkerError::Remote(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for WorkerError {}

type Reply = Result<Value, WorkerError>;

struct Shared {
    state: WorkerState,
    healthy: bool,
    pid: Option<u32>,
    restarts: u32,
    last_exit: Option<String>,
    last_error: Option<String>,
    running_since_ms: Option<u64>,
    shutting_down: bool,
    pending: HashMap<u64, mpsc::Sender<Reply>>,
}

struct Inner {
    spec: WorkerSpec,
    policy: RestartPolicy,
    shared: Mutex<Shared>,
    cv: Condvar,
    stdin: Mutex<Option<ChildStdin>>,
    ids: AtomicU64,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, Shared> {
        // A poisoned lock only means another thread panicked mid-update; the fields are plain
        // values, so keep going rather than wedge the supervisor.
        self.shared.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn set_state(&self, state: WorkerState) {
        let mut s = self.lock();
        s.state = state;
        drop(s);
        self.cv.notify_all();
    }

    fn fail_pending(&self, why: &str) {
        let pending: Vec<_> = self.lock().pending.drain().collect();
        for (_, tx) in pending {
            let _ = tx.send(Err(WorkerError::Crashed(why.to_string())));
        }
    }

    /// Write one request; the receiver gets its response (or the crash that ended the child).
    fn send(
        &self,
        method: &str,
        params: Value,
    ) -> Result<(u64, mpsc::Receiver<Reply>), WorkerError> {
        let id = self.ids.fetch_add(1, Ordering::SeqCst) + 1;
        let mut line = serde_json::to_string(&Request {
            id,
            method: method.to_string(),
            params,
        })
        .map_err(|e| WorkerError::Remote(format!("could not encode the request: {e}")))?;
        if line.len() > protocol::MAX_LINE_BYTES {
            // The worker would skip it and the caller would wait out its whole timeout.
            return Err(WorkerError::Remote(format!(
                "the request is too large for the worker wire ({} bytes, limit {})",
                line.len(),
                protocol::MAX_LINE_BYTES
            )));
        }
        line.push('\n');
        let (tx, rx) = mpsc::channel();
        self.lock().pending.insert(id, tx);
        let written = {
            let mut stdin = self.stdin.lock().unwrap_or_else(|p| p.into_inner());
            match stdin.as_mut() {
                Some(w) => w.write_all(line.as_bytes()).and_then(|_| w.flush()).is_ok(),
                None => false,
            }
        };
        if !written {
            self.lock().pending.remove(&id);
            return Err(WorkerError::Crashed("the worker's input is closed".into()));
        }
        Ok((id, rx))
    }

    /// Send one request and wait up to `timeout` for its response. Used by callers; a crash of
    /// the child is delivered by the monitor as [`WorkerError::Crashed`].
    fn request(&self, method: &str, params: Value, timeout: Duration) -> Reply {
        let (id, rx) = self.send(method, params)?;
        match rx.recv_timeout(timeout) {
            Ok(r) => r,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.lock().pending.remove(&id);
                Err(WorkerError::Timeout)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(WorkerError::Crashed("the worker went away".into()))
            }
        }
    }

    /// The monitor's ping: waits for the answer while watching the child, so a child that dies
    /// is noticed at once instead of at the ping's deadline.
    fn ping_watching(&self, child: &mut Child, timeout: Duration) -> Ping {
        let deadline = Instant::now() + timeout;
        let (id, rx) = match self.send(METHOD_PING, Value::Null) {
            Ok(x) => x,
            Err(_) => return Ping::Missed,
        };
        loop {
            match rx.recv_timeout(POLL) {
                Ok(Ok(_)) => return Ping::Answered,
                Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => return Ping::Missed,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            if matches!(has_exited(child), Ok(true)) {
                self.lock().pending.remove(&id);
                return Ping::Exited;
            }
            if self.lock().shutting_down || Instant::now() >= deadline {
                self.lock().pending.remove(&id);
                return Ping::Missed;
            }
        }
    }

    /// Wait (on the condvar) until shutdown is requested or `d` passes. True on shutdown.
    fn sleep_unless_shutdown(&self, d: Duration) -> bool {
        let deadline = Instant::now() + d;
        let mut s = self.lock();
        loop {
            if s.shutting_down {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            s = match self.cv.wait_timeout(s, deadline - now) {
                Ok((g, _)) => g,
                Err(p) => p.into_inner().0,
            };
        }
    }
}

/// Describe how a child ended.
pub fn describe_exit(status: &ExitStatus) -> String {
    if let Some(code) = status.code() {
        return format!("exited with code {code}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return format!("killed by signal {sig}");
        }
    }
    "exited".to_string()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// How often the monitor checks whether the child has exited.
const POLL: Duration = Duration::from_millis(25);

/// One supervised worker process.
pub struct Worker {
    inner: Arc<Inner>,
    monitor: Mutex<Option<JoinHandle<()>>>,
}

impl Worker {
    /// Start supervising. Returns at once; the first child starts in the background (see
    /// [`Worker::status`]). A program that cannot be spawned ends up [`WorkerState::Failed`].
    pub fn start(spec: WorkerSpec, policy: RestartPolicy) -> Worker {
        let inner = Arc::new(Inner {
            spec,
            policy,
            shared: Mutex::new(Shared {
                state: WorkerState::Starting,
                healthy: false,
                pid: None,
                restarts: 0,
                last_exit: None,
                last_error: None,
                running_since_ms: None,
                shutting_down: false,
                pending: HashMap::new(),
            }),
            cv: Condvar::new(),
            stdin: Mutex::new(None),
            ids: AtomicU64::new(0),
        });
        let m = inner.clone();
        let monitor = std::thread::Builder::new()
            .name(format!("citrate-worker-{}", inner.spec.kind.as_str()))
            .spawn(move || monitor(m))
            .ok();
        if monitor.is_none() {
            let mut s = inner.lock();
            s.state = WorkerState::Failed;
            s.last_error = Some("could not start the supervisor thread".into());
        }
        Worker {
            inner,
            monitor: Mutex::new(monitor),
        }
    }

    pub fn kind(&self) -> WorkerKind {
        self.inner.spec.kind
    }

    pub fn status(&self) -> WorkerStatus {
        let s = self.inner.lock();
        WorkerStatus {
            kind: self.inner.spec.kind,
            state: s.state,
            healthy: s.healthy,
            pid: s.pid,
            restarts: s.restarts,
            last_exit: s.last_exit.clone(),
            last_error: s.last_error.clone(),
            running_since_ms: s.running_since_ms,
        }
    }

    /// Run one call in the worker. While the worker is starting or restarting, waits for it (up
    /// to `timeout`); a failed or stopped worker refuses at once.
    pub fn call(&self, params: Value, timeout: Duration) -> Result<Value, WorkerError> {
        let deadline = Instant::now() + timeout;
        {
            let mut s = self.inner.lock();
            loop {
                match s.state {
                    WorkerState::Running => break,
                    WorkerState::Failed | WorkerState::Stopped => {
                        let why = match s.state {
                            WorkerState::Failed => match &s.last_error {
                                Some(e) => format!("failed: {e}"),
                                None => "failed".to_string(),
                            },
                            _ => "stopped".to_string(),
                        };
                        return Err(WorkerError::NotRunning(why));
                    }
                    WorkerState::Starting | WorkerState::Restarting => {
                        let now = Instant::now();
                        if now >= deadline {
                            return Err(WorkerError::NotRunning(
                                "still restarting at the call's deadline".into(),
                            ));
                        }
                        s = match self.inner.cv.wait_timeout(s, deadline - now) {
                            Ok((g, _)) => g,
                            Err(p) => p.into_inner().0,
                        };
                    }
                }
            }
        }
        let left = deadline.saturating_duration_since(Instant::now());
        self.inner.request(METHOD_CALL, params, left)
    }

    /// Stop the worker cleanly and wait for the supervisor to finish. Idempotent.
    pub fn shutdown(&self) {
        {
            let mut s = self.inner.lock();
            s.shutting_down = true;
        }
        self.inner.cv.notify_all();
        let handle = self
            .monitor
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(h) = handle {
            let _ = h.join();
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn spawn_child(spec: &WorkerSpec) -> std::io::Result<Child> {
    let mut cmd = Command::new(&spec.program);
    cmd.args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if spec.env_inherit.is_some() {
        cmd.env_clear();
        for (k, v) in std::env::vars_os() {
            if k.to_str().is_some_and(|name| spec.inherits(name)) {
                cmd.env(k, v);
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid(2) is async-signal-safe and touches no memory of the parent; it runs in
        // the forked child before exec. The worker leads a new session, so everything it starts
        // (even in process groups of its own) can be found and stopped by session id.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    for k in &spec.env_remove {
        cmd.env_remove(k);
    }
    for (k, v) in &spec.env {
        cmd.env(k, v);
    }
    cmd.spawn()
}

/// Read responses from the child's stdout and hand each to its waiting caller. Lines that are not
/// protocol responses are ignored.
fn reader(inner: Arc<Inner>, stdout: std::process::ChildStdout) {
    let mut input = BufReader::new(stdout);
    while let Ok(Some(line)) = protocol::read_line_capped(&mut input) {
        let Ok(resp) = serde_json::from_str::<Response>(line.trim()) else {
            continue;
        };
        let tx = inner.lock().pending.remove(&resp.id);
        if let Some(tx) = tx {
            let reply = match (resp.result, resp.error) {
                (_, Some(e)) => Err(WorkerError::Remote(e)),
                (Some(v), None) => Ok(v),
                (None, None) => Ok(Value::Null),
            };
            let _ = tx.send(reply);
        }
    }
}

/// Every process id on the system (best effort; empty when they cannot be listed).
#[cfg(target_os = "macos")]
fn all_pids() -> Vec<libc::pid_t> {
    // SAFETY: proc_listallpids with a null buffer returns the count; with a buffer of `cap`
    // pid_t it fills at most `cap` entries and returns how many it wrote.
    unsafe {
        let n = libc::proc_listallpids(std::ptr::null_mut(), 0);
        if n <= 0 {
            return Vec::new();
        }
        let cap = n as usize + 64;
        let mut buf: Vec<libc::pid_t> = vec![0; cap];
        let bytes = (cap * std::mem::size_of::<libc::pid_t>()) as libc::c_int;
        let got = libc::proc_listallpids(buf.as_mut_ptr().cast(), bytes);
        if got <= 0 {
            return Vec::new();
        }
        buf.truncate((got as usize).min(cap));
        buf
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn all_pids() -> Vec<libc::pid_t> {
    std::fs::read_dir("/proc")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok()))
                .collect()
        })
        .unwrap_or_default()
}

/// Kill every process left in the session the worker `sid` led (see [`spawn_child`]): the
/// programs it started, whatever process group they are in. Run after the worker has exited and
/// BEFORE it is reaped: while the exited worker is unreaped its id stays taken, so `sid` still
/// names that session and no other process can hold it. Best effort, a few passes in case one of
/// them was forking.
#[cfg(unix)]
fn stop_session(sid: u32) {
    let Ok(sid) = libc::pid_t::try_from(sid) else {
        return;
    };
    #[cfg(test)]
    tests::note_session_stop(sid);
    // SAFETY: getpid/getsid/kill are plain syscalls on integer ids; no memory is shared.
    let me = unsafe { libc::getpid() };
    for _ in 0..3 {
        let mut found = false;
        for pid in all_pids() {
            // The exited (unreaped) worker itself is skipped: it holds the id and is reaped next.
            if pid <= 1 || pid == me || pid == sid {
                continue;
            }
            // SAFETY: see above.
            if unsafe { libc::getsid(pid) } == sid {
                found = true;
                // SAFETY: see above.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
        if !found {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(not(unix))]
fn stop_session(_sid: u32) {}

/// `waitid` on the child with `WNOWAIT`: reports whether it has exited without reaping it.
/// `block` waits for the exit. Retries on `EINTR`.
#[cfg(unix)]
fn wait_exit(child: &Child, block: bool) -> std::io::Result<bool> {
    let pid = child.id() as libc::id_t;
    let mut options = libc::WEXITED | libc::WNOWAIT;
    if !block {
        options |= libc::WNOHANG;
    }
    loop {
        // SAFETY: zeroed is a valid siginfo_t; waitid writes into it. With WNOWAIT nothing is
        // reaped, so the child stays ours until `Child::wait`.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::waitid(libc::P_PID, pid, &mut info, options) };
        if rc == 0 {
            // With WNOHANG and no exit yet, si_pid stays 0.
            // SAFETY: waitid filled the SIGCHLD fields of `info`.
            return Ok(unsafe { info.si_pid() } != 0);
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// Whether the child has exited, WITHOUT reaping it (Unix). The caller reaps it with
/// `Child::wait` once its session has been stopped.
#[cfg(unix)]
fn has_exited(child: &mut Child) -> std::io::Result<bool> {
    wait_exit(child, false)
}

#[cfg(not(unix))]
fn has_exited(child: &mut Child) -> std::io::Result<bool> {
    child.try_wait().map(|s| s.is_some())
}

/// Kill the child (best effort) and wait until it has exited, without reaping it on Unix.
fn kill_and_wait(child: &mut Child) {
    // The child is not reaped yet, so this signals the worker and nothing else.
    let _ = child.kill();
    #[cfg(unix)]
    {
        let _ = wait_exit(child, true);
    }
    #[cfg(not(unix))]
    {
        let _ = child.wait();
    }
}

/// The result of a monitor ping.
enum Ping {
    Answered,
    Missed,
    Exited,
}

/// What ended one child's life. Either way the child has exited and is not reaped yet.
enum End {
    Exited,
    Shutdown,
}

/// Watch one running child until it exits, is killed for missing health checks, or shutdown is
/// requested. Returns once the child has exited; it is left unreaped for the caller.
fn watch(inner: &Inner, child: &mut Child) -> End {
    let p = &inner.policy;
    // Startup: the first ping must be answered.
    let ready = inner.ping_watching(child, p.startup_timeout);
    if let Ping::Exited = ready {
        return End::Exited;
    }
    if matches!(ready, Ping::Answered) {
        let mut s = inner.lock();
        s.state = WorkerState::Running;
        s.healthy = true;
        s.running_since_ms = Some(now_ms());
        drop(s);
        inner.cv.notify_all();
    } else if inner.lock().shutting_down {
        graceful_stop(inner, child);
        return End::Shutdown;
    } else if matches!(has_exited(child), Ok(true)) {
        return End::Exited;
    } else {
        inner.lock().last_error = Some("did not answer its startup health check".into());
        kill_and_wait(child);
        return End::Exited;
    }
    let mut next_health = Instant::now() + p.health_interval;
    let mut misses = 0u32;
    loop {
        match has_exited(child) {
            Ok(true) => return End::Exited,
            Ok(false) => {}
            Err(_) => {
                kill_and_wait(child);
                return End::Exited;
            }
        }
        if inner.sleep_unless_shutdown(POLL) {
            graceful_stop(inner, child);
            return End::Shutdown;
        }
        if Instant::now() >= next_health {
            match inner.ping_watching(child, p.health_timeout) {
                Ping::Exited => return End::Exited,
                Ping::Answered => {
                    misses = 0;
                    inner.lock().healthy = true;
                }
                Ping::Missed => {
                    misses += 1;
                    inner.lock().healthy = false;
                    if misses >= p.health_failures_to_kill {
                        if matches!(has_exited(child), Ok(true)) {
                            return End::Exited;
                        }
                        inner.lock().last_error = Some(format!(
                            "stopped answering health checks ({misses} missed in a row)"
                        ));
                        kill_and_wait(child);
                        return End::Exited;
                    }
                }
            }
            next_health = Instant::now() + p.health_interval;
        }
    }
}

/// Ask the child to stop, close its input, wait out the grace period, then kill it. Returns once
/// it has exited (not reaped).
fn graceful_stop(inner: &Inner, child: &mut Child) {
    let grace = inner.policy.shutdown_grace;
    let _ = inner.request(
        METHOD_SHUTDOWN,
        Value::Null,
        grace.min(Duration::from_secs(1)),
    );
    inner.stdin.lock().unwrap_or_else(|p| p.into_inner()).take();
    let deadline = Instant::now() + grace;
    loop {
        match has_exited(child) {
            Ok(true) => return,
            Ok(false) if Instant::now() < deadline => std::thread::sleep(POLL),
            _ => return kill_and_wait(child),
        }
    }
}

fn monitor(inner: Arc<Inner>) {
    let p = inner.policy.clone();
    let mut recent: VecDeque<Instant> = VecDeque::new();
    loop {
        if inner.lock().shutting_down {
            inner.set_state(WorkerState::Stopped);
            return;
        }
        {
            let mut s = inner.lock();
            s.state = WorkerState::Starting;
            s.healthy = false;
        }
        inner.cv.notify_all();
        let end = match spawn_child(&inner.spec) {
            Err(e) => {
                inner.lock().last_error = Some(format!(
                    "could not start {}: {e}",
                    inner.spec.program.display()
                ));
                (End::Exited, None)
            }
            Ok(mut child) => {
                *inner.stdin.lock().unwrap_or_else(|p| p.into_inner()) = child.stdin.take();
                // The reader ends on its own at end of output. It is not joined: a stray holder of
                // the pipe must not wedge the supervisor, and request ids never repeat, so a late
                // line from an old child cannot answer a new call.
                if let Some(out) = child.stdout.take() {
                    let r = inner.clone();
                    let _ = std::thread::Builder::new()
                        .name(format!("citrate-worker-{}-io", inner.spec.kind.as_str()))
                        .spawn(move || reader(r, out));
                }
                let pid = child.id();
                inner.lock().pid = Some(pid);
                let end = watch(&inner, &mut child);
                inner.stdin.lock().unwrap_or_else(|p| p.into_inner()).take();
                // The worker has exited but is not reaped yet, so its id still names its session:
                // stop anything it left running there, and only then reap it.
                stop_session(pid);
                let status = child.wait().ok();
                (end, status)
            }
        };
        let (end, status) = end;
        let requested = matches!(end, End::Shutdown);
        let desc = status.as_ref().map(describe_exit);
        {
            let mut s = inner.lock();
            s.pid = None;
            s.healthy = false;
            s.running_since_ms = None;
            if desc.is_some() {
                s.last_exit = desc.clone();
            }
        }
        inner.fail_pending(desc.as_deref().unwrap_or("the worker could not be started"));
        if requested || inner.lock().shutting_down {
            inner.set_state(WorkerState::Stopped);
            return;
        }
        // An unplanned end: restart within the policy, or give up.
        let now = Instant::now();
        while recent
            .front()
            .is_some_and(|t| now.duration_since(*t) > p.window)
        {
            recent.pop_front();
        }
        if recent.len() as u32 >= p.max_restarts {
            let mut s = inner.lock();
            s.state = WorkerState::Failed;
            let tail = s.last_error.clone().unwrap_or_else(|| {
                desc.clone()
                    .unwrap_or_else(|| "the worker could not be started".into())
            });
            s.last_error = Some(format!(
                "gave up after {} restarts in {}s; last problem: {tail}",
                p.max_restarts,
                p.window.as_secs()
            ));
            drop(s);
            inner.cv.notify_all();
            return;
        }
        recent.push_back(now);
        let backoff = p
            .backoff_base
            .saturating_mul(1u32 << (recent.len().saturating_sub(1)).min(16))
            .min(p.backoff_max);
        {
            let mut s = inner.lock();
            s.restarts += 1;
            s.state = WorkerState::Restarting;
        }
        inner.cv.notify_all();
        if inner.sleep_unless_shutdown(backoff) {
            inner.set_state(WorkerState::Stopped);
            return;
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Every session stop: the session id and whether its leader was still this process's
    /// unreaped child at that moment (so the id could not have been handed to another process).
    static STOPS: Mutex<Vec<(libc::pid_t, bool)>> = Mutex::new(Vec::new());

    /// Whether `pid` is still an unreaped child of this process (running or exited). `waitid`
    /// with `WNOWAIT` looks without reaping; it fails with `ECHILD` once the child was reaped.
    fn held(pid: libc::pid_t) -> bool {
        // SAFETY: zeroed is a valid siginfo_t; waitid writes into it and reaps nothing (WNOWAIT).
        unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            ) == 0
        }
    }

    pub(super) fn note_session_stop(sid: libc::pid_t) {
        let h = held(sid);
        STOPS
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((sid, h));
    }

    fn sh() -> PathBuf {
        ["/bin/sh", "/usr/bin/sh"]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.exists())
            .expect("a shell")
    }

    fn alive(pid: libc::pid_t) -> bool {
        // SAFETY: signal 0 only checks that the process exists.
        if unsafe { libc::kill(pid, 0) } != 0 {
            return false;
        }
        #[cfg(target_os = "linux")]
        if let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            if let Some(i) = s.rfind(')') {
                if s[i + 1..].trim_start().starts_with('Z') {
                    return false;
                }
            }
        }
        true
    }

    /// SCL-S0.4: when a worker ends, the processes left in its session are signalled while the
    /// worker itself is still unreaped, so its id (the session id) still names that session and
    /// cannot belong to an unrelated process. Only then is the worker reaped.
    #[test]
    fn a_worker_session_is_stopped_before_the_worker_is_reaped() {
        let dir = std::env::temp_dir().join(format!("citrate-worker-sid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        let pidfile = dir.join("left.pid");
        // The worker starts a long-lived program in its session, then exits at once.
        let spec = WorkerSpec {
            kind: WorkerKind::Toolchain,
            program: sh(),
            args: vec![
                "-c".into(),
                format!(
                    "sleep 600 & echo $! > '{p}.tmp' && mv '{p}.tmp' '{p}'; exit 3",
                    p = pidfile.display()
                ),
            ],
            env: Vec::new(),
            env_remove: Vec::new(),
            env_inherit: None,
        };
        let policy = RestartPolicy {
            max_restarts: 0,
            startup_timeout: Duration::from_secs(5),
            ..RestartPolicy::default()
        };
        let worker = Worker::start(spec, policy);
        let deadline = Instant::now() + Duration::from_secs(10);
        while worker.status().state != WorkerState::Failed && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let left: Option<libc::pid_t> = std::fs::read_to_string(&pidfile)
            .ok()
            .and_then(|s| s.trim().parse().ok());
        let state = worker.status().state;
        drop(worker);
        let stops: Vec<_> = STOPS.lock().unwrap_or_else(|p| p.into_inner()).clone();
        // Clean up whatever the worker left, pass or fail.
        let left_alive = left.is_some_and(alive);
        if let Some(pid) = left.filter(|p| alive(*p)) {
            // SAFETY: kill(2) on the program this test's worker started.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            state,
            WorkerState::Failed,
            "the worker ran once and was given up on"
        );
        assert!(left.is_some(), "the worker started its program");
        assert!(
            !left_alive,
            "the program left in the worker's session was stopped"
        );
        assert!(!stops.is_empty(), "the worker's session was stopped");
        for (sid, held) in stops {
            assert!(
                held,
                "session {sid} was signalled after its leader was reaped (its id may be reused)"
            );
        }
    }
}
