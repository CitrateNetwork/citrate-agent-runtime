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

/// A page that changes its own address (same document, `history.pushState`) once the test sets
/// [`SPA_MOVE`]; it asks the server every 100 ms.
pub const SPA: &str = r#"<!doctype html><html><head><title>Single page</title></head>
<body><h1>Cart</h1><button onclick="document.title='clicked'">Continue</button>
<script>var t = setInterval(function(){ fetch('/should-move').then(function(r){ return r.text(); }).then(function(x){ if (x === 'yes') { clearInterval(t); history.pushState({}, '', '/spa?moved=1'); } }).catch(function(){}); }, 100);</script>
</body></html>"#;

/// Set by a test to make the [`SPA`] page move.
pub static SPA_MOVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub const NEXT: &str = r#"<!doctype html><html><head><title>Welcome page</title></head>
<body><h1>Welcome</h1><p id="who"></p>
<script>document.getElementById('who').textContent = 'Signed in as ' + new URLSearchParams(location.search).get('email');</script>
</body></html>"#;

/// A page that requests `?u=<url>` from its own script once loaded (a sub-resource request the
/// page makes on its own).
pub const FETCHER: &str = r#"<!doctype html><html><head><title>Fetcher</title></head>
<body><h1>Fetcher</h1><p id="out">waiting</p>
<script>var u = new URLSearchParams(location.search).get('u'); fetch(u).then(function(r){ return r.text(); }).then(function(t){ document.getElementById('out').textContent = 'got ' + t; }).catch(function(e){ document.getElementById('out').textContent = 'failed'; });</script>
</body></html>"#;

/// A page that opens a WebSocket to `?u=<ws url>` from its own script once loaded, and reports
/// whether it opened, failed or closed.
pub const WS_OPENER: &str = r#"<!doctype html><html><head><title>Socket</title></head>
<body><h1>Socket</h1><p id="out">waiting</p>
<script>var o = document.getElementById('out'); try { var w = new WebSocket(new URLSearchParams(location.search).get('u')); w.onopen = function(){ o.textContent = 'opened'; }; w.onerror = function(){ o.textContent = 'failed'; }; w.onclose = function(){ if (o.textContent === 'waiting') o.textContent = 'closed'; }; } catch (e) { o.textContent = 'failed'; }</script>
</body></html>"#;

/// The request paths a [`serve_logged`] server has received, in order.
pub type RequestLog = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

/// How many requests in `log` asked for a path starting with `prefix`.
pub fn hits(log: &RequestLog, prefix: &str) -> usize {
    log.lock()
        .map(|g| g.iter().filter(|p| p.starts_with(prefix)).count())
        .unwrap_or(0)
}
/// HUP-S2.3: a dApp page that asks the wallet for an address and then a sign-in signature, and
/// embeds a frame that tries to reach the sign-in bridge directly.
pub const DAPP: &str = r#"<!doctype html><html><head><title>dapp</title></head>
<body><h1>Example dApp</h1><p id="state">idle</p><p id="frame">frame: waiting</p>
<button id="go">Sign in</button>
<iframe src="/frame"></iframe>
<script>
var st = document.getElementById('state');
st.textContent = 'provider ' + (window.ethereum && window.ethereum.isCitrateHermes ? 'yes' : 'no') + ', binding ' + (typeof window.__citrateHermesSignIn);
window.addEventListener('message', function (e) { document.getElementById('frame').textContent = 'frame: ' + e.data; });
document.getElementById('go').onclick = function () {
  window.ethereum.request({ method: 'eth_chainId' }).then(function (c) {
    return window.ethereum.request({ method: 'eth_requestAccounts' }).then(function (a) {
      st.textContent = 'chain ' + c + ' account ' + a[0];
      return window.ethereum.request({ method: 'personal_sign', params: ['0x6869', a[0]] });
    });
  }).then(function (sig) { st.textContent = 'signed ' + sig.slice(0, 6); })
    .catch(function (e) { st.textContent = 'refused ' + e.code; });
};
</script></body></html>"#;

/// The frame inside [`DAPP`]: reports whether it can see the bridge or a provider.
pub const FRAME: &str = r#"<!doctype html><html><body><script>
var r = 'binding ' + (typeof window.__citrateHermesSignIn) + ', provider ' + (window.ethereum ? 'yes' : 'no');
window.parent.postMessage(r, '*');
</script></body></html>"#;

/// Serve LOGIN at /login and NEXT at /next on 127.0.0.1; returns the base URL.
pub fn serve() -> String {
    serve_logged().0
}

/// [`serve`], also returning the log of every request path it receives.
pub fn serve_logged() -> (String, RequestLog) {
    let log: RequestLog = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = log.clone();
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
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(&stream);
                let mut first = String::new();
                if reader.read_line(&mut first).is_err() {
                    return;
                }
                if let Ok(mut g) = seen.lock() {
                    g.push(first.split_whitespace().nth(1).unwrap_or("/").to_string());
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
                } else if path.starts_with("/spa") {
                    ("200 OK", SPA)
                } else if path.starts_with("/should-move") {
                    let yes = SPA_MOVE.load(std::sync::atomic::Ordering::SeqCst);
                    ("200 OK", if yes { "yes" } else { "no" })
                } else if path.starts_with("/next") {
                    ("200 OK", NEXT)
                } else if path.starts_with("/fetcher") {
                    ("200 OK", FETCHER)
                } else if path.starts_with("/wsopener") {
                    ("200 OK", WS_OPENER)
                } else if path.starts_with("/secret") {
                    ("200 OK", "local secret")
                } else if path.starts_with("/dapp") {
                    ("200 OK", DAPP)
                } else if path.starts_with("/frame") {
                    ("200 OK", FRAME)
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
    (format!("http://{addr}"), log)
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

/// [`config`] for a managed browser that may open `base`, a local test server (the managed
/// browser opens public addresses only unless an origin is allowed).
pub fn config_allowing(exe: PathBuf, base: &str) -> BrowserConfig {
    let allow = match citrate_agent_browser::gate::parse_allow_private(base) {
        Ok(a) => a,
        Err(e) => panic!("{base}: {e}"),
    };
    BrowserConfig {
        allow_private: allow,
        ..config(exe)
    }
}

/// A free loopback port (bound then released).
pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(0)
}

/// Serve a redirect (302) from every path to `to` on 127.0.0.1; returns the base URL.
pub fn serve_redirect(to: String) -> String {
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
            let to = to.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(&stream);
                loop {
                    let mut l = String::new();
                    match reader.read_line(&mut l) {
                        Ok(0) | Err(_) => break,
                        Ok(_) if l == "\r\n" || l == "\n" => break,
                        Ok(_) => {}
                    }
                }
                let resp = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let mut s = &stream;
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    format!("http://{addr}")
}
