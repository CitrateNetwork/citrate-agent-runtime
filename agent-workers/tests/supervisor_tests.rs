//! HUP-S1.9 — the worker supervisor against real child processes.
//!
//! The child is this test binary re-executed with `CITRATE_WORKERS_TEST_MODE` set: libtest runs
//! only [`worker_child_entry`], which serves the line protocol on stdin/stdout with the behavior
//! the mode names, then exits. libtest's own banner lines on stdout are not protocol responses,
//! and the supervisor ignores them, which is also what these tests prove about stray output.
//!
//! Every test that kills a worker does so from outside (`kill -9` on its pid), the way a real
//! crash or an OOM kill arrives.

use citrate_agent_workers::protocol::{serve, Handler, ServeEnd};
use citrate_agent_workers::{
    RestartPolicy, Worker, WorkerError, WorkerKind, WorkerSpec, WorkerState,
};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MODE_ENV: &str = "CITRATE_WORKERS_TEST_MODE";

/// The child side. Without the mode variable it is a no-op (the normal test run).
#[test]
fn worker_child_entry() {
    let Ok(mode) = std::env::var(MODE_ENV) else {
        return;
    };
    struct Echo {
        mode: String,
    }
    impl Handler for Echo {
        fn call(&self, params: Value) -> Result<Value, String> {
            if let Some(ms) = params.get("sleep_ms").and_then(Value::as_u64) {
                std::thread::sleep(Duration::from_millis(ms));
            }
            if params.get("fail").and_then(Value::as_bool) == Some(true) {
                return Err("the handler refused".into());
            }
            let env = params
                .get("env_var")
                .and_then(Value::as_str)
                .and_then(|k| std::env::var(k).ok());
            Ok(json!({"echo": params, "pid": std::process::id(), "mode": self.mode, "env": env}))
        }
    }
    // libtest has printed `test worker_child_entry ... ` with no newline; end that line so the
    // first protocol response starts a line of its own.
    println!();
    match mode.as_str() {
        "crash_on_start" => std::process::exit(3),
        "hang" => {
            // Reads requests but never answers: the health check must catch it.
            let stdin = std::io::stdin();
            let mut line = String::new();
            while std::io::BufRead::read_line(&mut stdin.lock(), &mut line).unwrap_or(0) > 0 {
                line.clear();
            }
            std::process::exit(0);
        }
        "stall" => {
            // Answers the startup ping, then stops answering anything.
            let stdin = std::io::stdin();
            let mut lock = stdin.lock();
            let mut line = String::new();
            let mut answered = false;
            while std::io::BufRead::read_line(&mut lock, &mut line).unwrap_or(0) > 0 {
                if !answered {
                    let v: Value = serde_json::from_str(line.trim()).unwrap_or(Value::Null);
                    println!("{}", json!({"id": v["id"], "result": {"pong": true}}));
                    answered = true;
                }
                line.clear();
            }
            std::process::exit(0);
        }
        _ => {
            let stdin = std::io::stdin();
            let end = serve(
                stdin.lock(),
                std::io::stdout(),
                Arc::new(Echo { mode: mode.clone() }),
            );
            std::process::exit(match end {
                ServeEnd::Shutdown => 0,
                ServeEnd::Eof => 7,
            });
        }
    }
}

fn spec(mode: &str) -> WorkerSpec {
    let exe: PathBuf = std::env::current_exe().unwrap();
    WorkerSpec {
        kind: WorkerKind::Toolchain,
        program: exe,
        args: vec![
            "--exact".into(),
            "worker_child_entry".into(),
            "--nocapture".into(),
            "--test-threads=1".into(),
        ],
        env: vec![(MODE_ENV.into(), mode.into())],
        env_remove: vec![],
    }
}

fn fast_policy() -> RestartPolicy {
    RestartPolicy {
        max_restarts: 3,
        window: Duration::from_secs(30),
        backoff_base: Duration::from_millis(50),
        backoff_max: Duration::from_millis(200),
        startup_timeout: Duration::from_secs(10),
        health_interval: Duration::from_millis(100),
        health_timeout: Duration::from_millis(300),
        health_failures_to_kill: 2,
        shutdown_grace: Duration::from_secs(2),
    }
}

fn wait_for(what: &str, limit: Duration, mut f: impl FnMut() -> bool) {
    let t0 = Instant::now();
    while !f() {
        assert!(t0.elapsed() < limit, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
fn kill9(pid: u32) {
    // SAFETY: kill(2) on a pid we just read from the supervisor's status; no memory involved.
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    assert_eq!(rc, 0, "kill -9 {pid}");
}

fn running(w: &Worker) -> bool {
    w.status().state == WorkerState::Running
}

#[test]
fn a_worker_starts_answers_calls_and_reports_running() {
    let w = Worker::start(spec("echo"), fast_policy());
    wait_for("running", Duration::from_secs(15), || running(&w));
    let st = w.status();
    assert_eq!(st.kind, WorkerKind::Toolchain);
    assert!(st.healthy);
    assert_eq!(st.restarts, 0);
    let pid = st.pid.expect("a running worker has a pid");
    assert_ne!(pid, std::process::id(), "the worker is a separate process");
    let out = w
        .call(json!({"x": 1}), Duration::from_secs(5))
        .expect("call");
    assert_eq!(out["echo"]["x"], 1);
    assert_eq!(out["pid"], pid);
}

#[test]
fn a_handler_error_comes_back_as_a_remote_error_and_the_worker_lives() {
    let w = Worker::start(spec("echo"), fast_policy());
    wait_for("running", Duration::from_secs(15), || running(&w));
    let err = w
        .call(json!({"fail": true}), Duration::from_secs(5))
        .unwrap_err();
    assert_eq!(err, WorkerError::Remote("the handler refused".into()));
    assert!(w.call(json!({}), Duration::from_secs(5)).is_ok());
    assert_eq!(w.status().restarts, 0);
}

#[cfg(unix)]
#[test]
fn a_killed_worker_is_restarted_and_the_status_says_so() {
    let w = Worker::start(spec("echo"), fast_policy());
    wait_for("running", Duration::from_secs(15), || running(&w));
    let first = w.status().pid.unwrap();
    kill9(first);
    wait_for("restart", Duration::from_secs(15), || {
        let s = w.status();
        s.state == WorkerState::Running && s.pid.is_some() && s.pid != Some(first)
    });
    let st = w.status();
    assert_eq!(st.restarts, 1);
    let last = st.last_exit.clone().expect("the crash is recorded");
    assert!(last.contains("signal 9"), "{last}");
    let out = w
        .call(json!({"after": "restart"}), Duration::from_secs(5))
        .unwrap();
    assert_eq!(out["pid"], st.pid.unwrap());
}

#[cfg(unix)]
#[test]
fn a_call_in_flight_when_the_worker_dies_fails_as_crashed_not_as_a_result() {
    let w = Arc::new(Worker::start(spec("echo"), fast_policy()));
    wait_for("running", Duration::from_secs(15), || running(&w));
    let pid = w.status().pid.unwrap();
    let w2 = w.clone();
    let h = std::thread::spawn(move || w2.call(json!({"sleep_ms": 5000}), Duration::from_secs(20)));
    std::thread::sleep(Duration::from_millis(300));
    let t0 = Instant::now();
    kill9(pid);
    let r = h.join().unwrap();
    match r {
        Err(WorkerError::Crashed(why)) => assert!(why.contains("signal 9"), "{why}"),
        other => panic!("expected Crashed, got {other:?}"),
    }
    assert!(
        t0.elapsed() < Duration::from_secs(4),
        "the caller learns of the crash promptly, not at its own timeout"
    );
}

#[cfg(unix)]
#[test]
fn two_workers_are_independent_a_crash_in_one_leaves_the_other_running() {
    let a = Worker::start(spec("echo"), fast_policy());
    let mut b_spec = spec("echo");
    b_spec.kind = WorkerKind::Browser;
    let b = Worker::start(b_spec, fast_policy());
    wait_for("both running", Duration::from_secs(15), || {
        running(&a) && running(&b)
    });
    let b_pid = b.status().pid.unwrap();
    kill9(a.status().pid.unwrap());
    wait_for("a restarted", Duration::from_secs(15), || {
        a.status().restarts == 1 && running(&a)
    });
    let bs = b.status();
    assert_eq!(bs.restarts, 0);
    assert_eq!(bs.pid, Some(b_pid), "the other worker was never touched");
    assert!(b.call(json!({}), Duration::from_secs(5)).is_ok());
}

#[test]
fn a_worker_that_keeps_crashing_is_given_up_on_and_says_failed() {
    let w = Worker::start(spec("crash_on_start"), fast_policy());
    wait_for("failed", Duration::from_secs(20), || {
        w.status().state == WorkerState::Failed
    });
    let st = w.status();
    assert_eq!(st.restarts, 3, "exactly max_restarts restarts were tried");
    assert!(!st.healthy);
    assert!(st.pid.is_none());
    let last = st.last_exit.unwrap();
    assert!(last.contains("code 3"), "{last}");
    let err = w.call(json!({}), Duration::from_millis(200)).unwrap_err();
    assert!(matches!(err, WorkerError::NotRunning(_)), "{err:?}");
}

#[test]
fn a_worker_that_never_answers_its_startup_ping_is_replaced_then_given_up_on() {
    let mut p = fast_policy();
    p.startup_timeout = Duration::from_millis(500);
    let w = Worker::start(spec("hang"), p);
    wait_for("given up", Duration::from_secs(30), || {
        w.status().state == WorkerState::Failed
    });
    let st = w.status();
    assert_eq!(st.restarts, 3);
    let err = st.last_error.unwrap_or_default();
    assert!(err.contains("startup health check"), "{err}");
}

#[test]
fn a_running_worker_that_stops_answering_health_checks_is_killed_and_replaced() {
    let w = Worker::start(spec("stall"), fast_policy());
    wait_for("running once", Duration::from_secs(15), || running(&w));
    let first = w.status().pid.unwrap();
    wait_for("replaced", Duration::from_secs(15), || {
        let s = w.status();
        s.restarts >= 1 && s.pid.is_some() && s.pid != Some(first)
    });
    let st = w.status();
    let err = st.last_error.unwrap_or_default();
    assert!(err.contains("stopped answering health checks"), "{err}");
    let exit = st.last_exit.unwrap_or_default();
    #[cfg(unix)]
    assert!(
        exit.contains("signal 9"),
        "the stalled child was killed: {exit}"
    );
}

#[test]
fn shutdown_is_clean_the_worker_exits_on_request_and_state_is_stopped() {
    let w = Worker::start(spec("echo"), fast_policy());
    wait_for("running", Duration::from_secs(15), || running(&w));
    let t0 = Instant::now();
    w.shutdown();
    assert!(
        t0.elapsed() < Duration::from_secs(3),
        "inside the grace period"
    );
    let st = w.status();
    assert_eq!(st.state, WorkerState::Stopped);
    assert!(st.pid.is_none());
    assert_eq!(st.restarts, 0, "a requested stop is not a crash");
    assert_eq!(st.last_exit.as_deref(), Some("exited with code 0"));
    let err = w.call(json!({}), Duration::from_millis(200)).unwrap_err();
    assert!(matches!(err, WorkerError::NotRunning(_)), "{err:?}");
}

#[test]
fn removed_environment_variables_do_not_reach_the_worker() {
    assert!(std::env::var("HOME").is_ok(), "the test process has a HOME");
    let mut keep = spec("echo");
    keep.kind = WorkerKind::Browser;
    let mut strip = spec("echo");
    strip.env_remove.push("HOME".into());
    let (a, b) = (
        Worker::start(keep, fast_policy()),
        Worker::start(strip, fast_policy()),
    );
    wait_for("running", Duration::from_secs(15), || {
        running(&a) && running(&b)
    });
    let q = json!({"env_var": "HOME"});
    let with = a.call(q.clone(), Duration::from_secs(5)).unwrap();
    let without = b.call(q, Duration::from_secs(5)).unwrap();
    assert!(with["env"].is_string(), "{with}");
    assert!(without["env"].is_null(), "{without}");
}

#[test]
fn a_program_that_cannot_be_spawned_is_reported_failed_honestly() {
    let mut s = spec("echo");
    s.program = PathBuf::from("/nonexistent/citrate-worker");
    let w = Worker::start(s, fast_policy());
    wait_for("failed", Duration::from_secs(10), || {
        w.status().state == WorkerState::Failed
    });
    let e = w.status().last_error.unwrap();
    assert!(e.contains("could not start"), "{e}");
}

#[test]
fn a_call_that_outlives_its_timeout_is_a_timeout_and_the_worker_lives() {
    let w = Worker::start(spec("echo"), fast_policy());
    wait_for("running", Duration::from_secs(15), || running(&w));
    let err = w
        .call(json!({"sleep_ms": 1500}), Duration::from_millis(200))
        .unwrap_err();
    assert_eq!(err, WorkerError::Timeout);
    assert!(w.call(json!({}), Duration::from_secs(5)).is_ok());
    assert_eq!(w.status().restarts, 0);
}

#[test]
fn the_status_serializes_with_stable_lowercase_names() {
    let w = Worker::start(spec("echo"), fast_policy());
    wait_for("running", Duration::from_secs(15), || running(&w));
    let v = serde_json::to_value(w.status()).unwrap();
    assert_eq!(v["kind"], "toolchain");
    assert_eq!(v["state"], "running");
    assert_eq!(v["healthy"], true);
    assert!(v["pid"].is_u64());
    assert_eq!(v["restarts"], 0);
}

#[test]
fn a_request_too_large_for_the_wire_is_refused_at_once_not_left_to_time_out() {
    let w = Worker::start(spec("echo"), fast_policy());
    wait_for("running", Duration::from_secs(15), || running(&w));
    let pad = "x".repeat(citrate_agent_workers::protocol::MAX_LINE_BYTES);
    let t0 = std::time::Instant::now();
    let r = w.call(json!({ "pad": pad }), Duration::from_secs(20));
    assert!(
        matches!(&r, Err(WorkerError::Remote(e)) if e.contains("too large")),
        "{r:?}"
    );
    assert!(t0.elapsed() < Duration::from_secs(5), "refused promptly");
    assert!(w.call(json!({"ok": 1}), Duration::from_secs(5)).is_ok());
}
