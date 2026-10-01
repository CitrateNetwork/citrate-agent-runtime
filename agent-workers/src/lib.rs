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
//! user and environment. Programs a worker itself started (a forge run, say) are that worker's
//! responsibility; if the worker is killed mid-run they may outlive it until their own timeout.
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
            if let Ok(Some(st)) = child.try_wait() {
                self.lock().pending.remove(&id);
                return Ping::Exited(st);
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

/// Kill the child (best effort) and reap it.
fn kill_and_reap(child: &mut Child) -> Option<ExitStatus> {
    let _ = child.kill();
    child.wait().ok()
}

/// The result of a monitor ping.
enum Ping {
    Answered,
    Missed,
    Exited(ExitStatus),
}

/// What ended one child's life.
enum End {
    Exited(Option<ExitStatus>),
    Shutdown(Option<ExitStatus>),
}

/// Watch one running child until it exits, is killed for missing health checks, or shutdown is
/// requested.
fn watch(inner: &Inner, child: &mut Child) -> End {
    let p = &inner.policy;
    // Startup: the first ping must be answered.
    let ready = inner.ping_watching(child, p.startup_timeout);
    if let Ping::Exited(st) = ready {
        return End::Exited(Some(st));
    }
    if matches!(ready, Ping::Answered) {
        let mut s = inner.lock();
        s.state = WorkerState::Running;
        s.healthy = true;
        s.running_since_ms = Some(now_ms());
        drop(s);
        inner.cv.notify_all();
    } else if inner.lock().shutting_down {
        return End::Shutdown(graceful_stop(inner, child));
    } else if let Ok(Some(st)) = child.try_wait() {
        return End::Exited(Some(st));
    } else {
        inner.lock().last_error = Some("did not answer its startup health check".into());
        return End::Exited(kill_and_reap(child));
    }
    let mut next_health = Instant::now() + p.health_interval;
    let mut misses = 0u32;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return End::Exited(Some(st)),
            Ok(None) => {}
            Err(_) => return End::Exited(kill_and_reap(child)),
        }
        if inner.sleep_unless_shutdown(POLL) {
            return End::Shutdown(graceful_stop(inner, child));
        }
        if Instant::now() >= next_health {
            match inner.ping_watching(child, p.health_timeout) {
                Ping::Exited(st) => return End::Exited(Some(st)),
                Ping::Answered => {
                    misses = 0;
                    inner.lock().healthy = true;
                }
                Ping::Missed => {
                    misses += 1;
                    inner.lock().healthy = false;
                    if misses >= p.health_failures_to_kill {
                        if let Ok(Some(st)) = child.try_wait() {
                            return End::Exited(Some(st));
                        }
                        inner.lock().last_error = Some(format!(
                            "stopped answering health checks ({misses} missed in a row)"
                        ));
                        return End::Exited(kill_and_reap(child));
                    }
                }
            }
            next_health = Instant::now() + p.health_interval;
        }
    }
}

/// Ask the child to stop, close its input, wait out the grace period, then kill it.
fn graceful_stop(inner: &Inner, child: &mut Child) -> Option<ExitStatus> {
    let grace = inner.policy.shutdown_grace;
    let _ = inner.request(
        METHOD_SHUTDOWN,
        Value::Null,
        grace.min(Duration::from_secs(1)),
    );
    inner.stdin.lock().unwrap_or_else(|p| p.into_inner()).take();
    let deadline = Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Some(st),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
            _ => return kill_and_reap(child),
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
                End::Exited(None)
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
                inner.lock().pid = Some(child.id());
                let end = watch(&inner, &mut child);
                inner.stdin.lock().unwrap_or_else(|p| p.into_inner()).take();
                end
            }
        };
        let (status, requested) = match end {
            End::Exited(st) => (st, false),
            End::Shutdown(st) => (st, true),
        };
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
