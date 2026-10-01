//! Shared test helpers: a tiny local web server with fixed pages, and Chromium discovery for the
//! live tests (which skip, saying so, when no Chromium is installed).
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;

use citrate_agent_browser::chromium::{discover, system_candidates, ChromiumStatus};
use citrate_agent_browser::BrowserConfig;

pub const LOGIN: &str = r#"<!doctype html><html><head><title>Example login</title></head>
<body><h1>Sign in</h1><p>Use your account.</p>
<form action="/next" method="get">
<label for="email">Email</label><input id="email" name="email" type="text">
<button type="submit">Continue</button>
</form>
<a href="/forgot">Forgot password?</a>
<button disabled>Later</button>
</body></html>"#;

pub const NEXT: &str = r#"<!doctype html><html><head><title>Welcome page</title></head>
<body><h1>Welcome</h1><p id="who"></p>
<script>document.getElementById('who').textContent = 'Signed in as ' + new URLSearchParams(location.search).get('email');</script>
</body></html>"#;

/// Serve LOGIN at /login and NEXT at /next on 127.0.0.1; returns the base URL.
pub fn serve() -> String {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => panic!("bind: {e}"),
    };
    let addr = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut reader = BufReader::new(&stream);
                let mut first = String::new();
                if reader.read_line(&mut first).is_err() {
                    return;
                }
                loop {
                    let mut l = String::new();
                    match reader.read_line(&mut l) {
                        Ok(0) | Err(_) => break,
                        Ok(_) if l == "\r\n" || l == "\n" => break,
                        Ok(_) => {}
                    }
                }
                let path = first.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, body) = if path.starts_with("/login") {
                    ("200 OK", LOGIN)
                } else if path.starts_with("/next") {
                    ("200 OK", NEXT)
                } else {
                    ("404 Not Found", "<html><title>Not found</title>nope</html>")
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let mut s = &stream;
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    format!("http://{addr}")
}

/// The Chromium the live tests use, or None (the test prints that it skipped).
pub fn chromium() -> Option<PathBuf> {
    match discover(None, &system_candidates()) {
        ChromiumStatus::NotInstalled { .. } => {
            eprintln!("SKIPPED: no Chromium-family browser is installed on this machine");
            None
        }
        s => s.path(),
    }
}

/// Test-only launch flags: Linux CI runners may not allow Chrome's sandbox.
pub fn test_args() -> Vec<String> {
    if cfg!(target_os = "linux") {
        vec!["--no-sandbox".to_string()]
    } else {
        Vec::new()
    }
}

pub fn config(exe: PathBuf) -> BrowserConfig {
    BrowserConfig {
        managed_path: Some(exe),
        candidates: Vec::new(),
        extra_args: test_args(),
        approval_timeout: std::time::Duration::from_secs(5),
        ..BrowserConfig::default()
    }
}

/// A free loopback port (bound then released).
pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(0)
}
