//! SCL-S0.3: stopping the managed browser stops all of it. The browser leads a process group of
//! its own, and dropping it kills that whole group (its helper processes too, not only the main
//! process) before the temporary profile is removed, so nothing of it keeps running and nothing
//! keeps serving its debugging endpoint.
//!
//! These tests use a stand-in browser: a shell script that writes the `DevToolsActivePort` file the
//! launcher waits for and starts one long-lived helper, like Chrome's renderer and GPU processes.
//! Every test stops the processes it started, pass or fail.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use citrate_agent_browser::chromium::ManagedChrome;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let p = std::env::temp_dir().join(format!(
            "citrate-chrome-stop-test-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("scratch folder");
        Scratch(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Kills a helper the test learned about, whatever the outcome of the test. (The browser itself
/// is stopped by dropping it, which also runs when an assertion fails.)
struct Reaper(Vec<i32>);

impl Drop for Reaper {
    fn drop(&mut self) {
        for pid in &self.0 {
            if alive(*pid) {
                // SAFETY: plain kill(2) on the helper this test's stand-in browser started.
                unsafe {
                    libc::kill(*pid, libc::SIGKILL);
                }
            }
        }
    }
}

/// A stand-in browser: writes the endpoint file into its `--user-data-dir`, starts a helper that
/// would run for ten minutes, records the helper's pid in `--test-helper-pidfile`, and waits.
fn fake_browser(dir: &Path) -> PathBuf {
    let script = dir.join("fake-chrome.sh");
    std::fs::write(
        &script,
        r#"#!/bin/sh
profile=""
pidfile=""
for a in "$@"; do
  case "$a" in
    --user-data-dir=*) profile="${a#--user-data-dir=}" ;;
    --test-helper-pidfile=*) pidfile="${a#--test-helper-pidfile=}" ;;
  esac
done
sleep 600 &
echo $! > "$pidfile.tmp" && mv "$pidfile.tmp" "$pidfile"
printf '9\n/devtools/browser/stand-in\n' > "$profile/DevToolsActivePort"
wait
"#,
    )
    .expect("write the stand-in browser");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    script
}

fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    if unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    // A killed helper is a zombie until its new parent reaps it; a zombie is not running.
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            if let Some(after) = s.rfind(')').map(|i| &s[i + 1..]) {
                if after.trim_start().starts_with('Z') {
                    return false;
                }
            }
        }
    }
    true
}

fn gone_within(pid: i32, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if !alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    !alive(pid)
}

fn read_pid(file: &Path) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(s) = std::fs::read_to_string(file) {
            if let Ok(p) = s.trim().parse::<i32>() {
                return p;
            }
        }
        assert!(
            Instant::now() < deadline,
            "the stand-in browser never started its helper"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn launch(dir: &Path, pidfile: &Path) -> ManagedChrome {
    ManagedChrome::launch(
        &fake_browser(dir),
        (800, 600),
        &[format!("--test-helper-pidfile={}", pidfile.display())],
        Duration::from_secs(10),
    )
    .expect("the stand-in browser starts")
}

#[test]
fn dropping_the_browser_stops_its_helpers_and_removes_the_profile() {
    let dir = Scratch::new("drop");
    let pidfile = dir.0.join("helper.pid");
    let chrome = launch(&dir.0, &pidfile);
    let helper = read_pid(&pidfile);
    let _reap = Reaper(vec![helper]);
    let profile = chrome.profile_dir().to_path_buf();
    assert!(
        profile.is_dir(),
        "the profile exists while the browser runs"
    );
    assert!(alive(helper), "the helper runs while the browser runs");

    drop(chrome);

    assert!(
        gone_within(helper, Duration::from_secs(3)),
        "a helper of the managed browser outlived it"
    );
    assert!(!profile.exists(), "the profile folder was left behind");
}

#[test]
fn the_managed_browser_leads_a_process_group_of_its_own() {
    let dir = Scratch::new("group");
    let pidfile = dir.0.join("helper.pid");
    let chrome = launch(&dir.0, &pidfile);
    let helper = read_pid(&pidfile);
    let pid = chrome.pid() as i32;
    let _reap = Reaper(vec![helper]);
    // SAFETY: getpgid/getpgrp are plain syscalls on integer ids.
    let (group, helper_group, ours) =
        unsafe { (libc::getpgid(pid), libc::getpgid(helper), libc::getpgrp()) };
    assert_eq!(group, pid, "the browser leads its own process group");
    assert_eq!(helper_group, pid, "its helpers are in that group");
    assert_ne!(group, ours, "the browser is not in the sidecar's group");
    drop(chrome);
    assert!(gone_within(helper, Duration::from_secs(3)));
}
