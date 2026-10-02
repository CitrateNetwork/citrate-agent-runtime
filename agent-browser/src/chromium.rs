//! HUP-S5.1: finding and launching a Chromium.
//!
//! Two sources, in order:
//! 1. **Managed**: the Chromium at a configured path (`CITRATE_BROWSER_CHROMIUM`). Installing and
//!    updating it is the signed component updater's job (HUP-S5.5); this crate only uses it when
//!    it is there.
//! 2. **System**: a Chromium-family browser already installed (Chrome, Chrome for Testing,
//!    Chromium, Edge, Brave) at its usual place.
//!
//! When neither exists the status says "not installed", with the places that were checked. The
//! launched browser is headless, uses a fresh private profile in a temporary folder (never the
//! member's own profile), exposes DevTools on loopback only, and is killed (profile removed) when
//! dropped.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;

/// The env var naming the managed Chromium executable.
pub const MANAGED_CHROMIUM_ENV: &str = "CITRATE_BROWSER_CHROMIUM";

/// Where the browser comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ChromiumStatus {
    Managed { path: String },
    System { path: String },
    NotInstalled { searched: Vec<String> },
}

impl ChromiumStatus {
    pub fn path(&self) -> Option<PathBuf> {
        match self {
            ChromiumStatus::Managed { path } | ChromiumStatus::System { path } => {
                Some(PathBuf::from(path))
            }
            ChromiumStatus::NotInstalled { .. } => None,
        }
    }
}

/// The usual install locations of Chromium-family browsers on this OS.
pub fn system_candidates() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if cfg!(target_os = "macos") {
        let apps = [
            ("Google Chrome.app", "Google Chrome"),
            ("Google Chrome for Testing.app", "Google Chrome for Testing"),
            ("Chromium.app", "Chromium"),
            ("Microsoft Edge.app", "Microsoft Edge"),
            ("Brave Browser.app", "Brave Browser"),
        ];
        let mut roots = vec![PathBuf::from("/Applications")];
        if let Some(home) = std::env::var_os("HOME") {
            roots.push(PathBuf::from(home).join("Applications"));
        }
        for root in &roots {
            for (app, exe) in apps {
                v.push(root.join(app).join("Contents/MacOS").join(exe));
            }
        }
    } else if cfg!(windows) {
        let rels = [
            r"Google\Chrome\Application\chrome.exe",
            r"Chromium\Application\chrome.exe",
            r"Microsoft\Edge\Application\msedge.exe",
            r"BraveSoftware\Brave-Browser\Application\brave.exe",
        ];
        for var in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
            if let Some(base) = std::env::var_os(var) {
                for rel in rels {
                    v.push(PathBuf::from(&base).join(rel));
                }
            }
        }
    } else {
        let names = [
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "microsoft-edge",
            "brave-browser",
        ];
        let path = std::env::var_os("PATH").unwrap_or_default();
        for dir in std::env::split_paths(&path) {
            for n in names {
                v.push(dir.join(n));
            }
        }
        for n in names {
            v.push(PathBuf::from("/usr/bin").join(n));
            v.push(PathBuf::from("/snap/bin").join(n));
        }
    }
    v
}

fn is_executable_file(p: &Path) -> bool {
    match std::fs::metadata(p) {
        Ok(m) if m.is_file() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        _ => false,
    }
}

/// Find a browser: the managed one when it exists, else the first system one, else "not
/// installed" with every place that was checked.
pub fn discover(managed: Option<&Path>, candidates: &[PathBuf]) -> ChromiumStatus {
    let mut searched = Vec::new();
    if let Some(m) = managed {
        if is_executable_file(m) {
            return ChromiumStatus::Managed {
                path: m.display().to_string(),
            };
        }
        searched.push(m.display().to_string());
    }
    for c in candidates {
        if is_executable_file(c) {
            return ChromiumStatus::System {
                path: c.display().to_string(),
            };
        }
        let shown = c.display().to_string();
        if !searched.contains(&shown) {
            searched.push(shown);
        }
    }
    ChromiumStatus::NotInstalled { searched }
}

/// A headless Chromium this process launched. Dropping it kills the browser and removes its
/// temporary profile.
pub struct ManagedChrome {
    child: Child,
    profile: PathBuf,
    ws_url: String,
}

impl ManagedChrome {
    /// Launch `exe` headless with a fresh profile and wait for its DevTools endpoint.
    /// `extra_args` are appended (tests use them; production passes none).
    pub fn launch(
        exe: &Path,
        viewport: (u32, u32),
        extra_args: &[String],
        timeout: Duration,
    ) -> Result<ManagedChrome, String> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let profile =
            std::env::temp_dir().join(format!("citrate-browser-{}-{nanos:x}", std::process::id()));
        std::fs::create_dir_all(&profile)
            .map_err(|e| format!("could not create the browser profile folder: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o700));
        }
        let mut args = vec![
            "--headless=new".to_string(),
            "--remote-debugging-address=127.0.0.1".to_string(),
            "--remote-debugging-port=0".to_string(),
            format!("--user-data-dir={}", profile.display()),
            "--no-first-run".to_string(),
            "--no-default-browser-check".to_string(),
            "--disable-extensions".to_string(),
            "--disable-sync".to_string(),
            "--disable-background-networking".to_string(),
            "--disable-component-update".to_string(),
            "--disable-default-apps".to_string(),
            "--mute-audio".to_string(),
            "--password-store=basic".to_string(),
            "--use-mock-keychain".to_string(),
            format!("--window-size={},{}", viewport.0, viewport.1),
        ];
        args.extend(extra_args.iter().cloned());
        args.push("about:blank".to_string());
        let child = Command::new(exe)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                let _ = std::fs::remove_dir_all(&profile);
                format!("could not start the browser at {}: {e}", exe.display())
            })?;
        let mut me = ManagedChrome {
            child,
            profile,
            ws_url: String::new(),
        };
        let port_file = me.profile.join("DevToolsActivePort");
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(text) = std::fs::read_to_string(&port_file) {
                let mut lines = text.lines();
                if let (Some(port), Some(path)) = (lines.next(), lines.next()) {
                    if let Ok(port) = port.trim().parse::<u16>() {
                        if path.starts_with("/devtools/browser/") {
                            me.ws_url = format!("ws://127.0.0.1:{port}{}", path.trim());
                            return Ok(me);
                        }
                    }
                }
            }
            if let Ok(Some(status)) = me.child.try_wait() {
                return Err(format!("the browser exited while starting ({status})"));
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "the browser did not open its DevTools endpoint within {}s",
                    timeout.as_secs()
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn ws_url(&self) -> &str {
        &self.ws_url
    }

    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for ManagedChrome {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Helper processes may hold the profile for a moment after the browser exits.
        for _ in 0..20 {
            if std::fs::remove_dir_all(&self.profile).is_ok() || !self.profile.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// The DevTools browser WebSocket URL of a Chrome the member started with remote debugging on,
/// read from its loopback `/json/version`. Only loopback ports are ever contacted.
pub fn attach_ws_url(port: u16, timeout: Duration) -> Result<String, String> {
    if port < 1024 {
        return Err("the remote debugging port must be 1024 or higher".to_string());
    }
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .get(format!("http://127.0.0.1:{port}/json/version"))
        .send()
        .map_err(|_| {
            format!(
                "no Chrome is listening for remote debugging on 127.0.0.1:{port}; start Chrome with remote debugging on that port first"
            )
        })?;
    if !resp.status().is_success() {
        return Err(format!(
            "127.0.0.1:{port} answered {} instead of Chrome's DevTools version",
            resp.status()
        ));
    }
    let body = resp
        .text()
        .map_err(|_| format!("127.0.0.1:{port} did not answer with DevTools data"))?;
    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|_| format!("127.0.0.1:{port} is not a Chrome DevTools endpoint"))?;
    let ws = v["webSocketDebuggerUrl"]
        .as_str()
        .ok_or_else(|| format!("127.0.0.1:{port} is not a Chrome DevTools endpoint"))?
        .to_string();
    let addr = crate::cdp::loopback_ws_addr(&ws)?;
    if addr.port() != port {
        return Err("the DevTools endpoint pointed at a different port; refusing it".to_string());
    }
    Ok(ws)
}
