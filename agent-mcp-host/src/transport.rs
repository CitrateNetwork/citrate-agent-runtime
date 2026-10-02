//! MCP transports (HUP-S4.1): stdio (an env-filtered child process, newline-delimited JSON-RPC)
//! and streamable HTTP (one POST per message; a JSON or SSE answer). Both enforce a per-request
//! deadline, a response size cap and cancellation, and both answer server-to-client requests
//! with "method not found" (this host advertises no client capabilities) except `ping`.

use crate::config::{child_env, ServerConfig, TransportConfig};
use crate::error::McpError;
use citrate_agent_loop::StopFlag;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

type Reply = Result<Value, McpError>;

/// One way of exchanging JSON-RPC messages with a server.
pub(crate) trait Transport: Send + Sync {
    /// Send a request and wait for its result (the `result` member) or an error.
    fn request(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
        stop: Option<&StopFlag>,
    ) -> Result<Value, McpError>;
    /// Send a notification (no answer).
    fn notify(&self, method: &str, params: Value) -> Result<(), McpError>;
    /// Record the negotiated protocol version (HTTP sends it as a header on later requests).
    fn set_protocol_version(&self, _v: &str) {}
    /// The server process is gone (stdio only).
    fn exited(&self) -> bool {
        false
    }
    /// Messages that were not valid JSON-RPC and were skipped.
    fn bad_messages(&self) -> u64;
    /// The server said its tool list changed (recorded, not acted on).
    fn tools_changed(&self) -> bool;
    /// Stop the server now (stdio: close its input and kill the process). Idempotent.
    fn close(&self) {}
}

pub(crate) fn connect(cfg: &ServerConfig) -> Result<Box<dyn Transport>, McpError> {
    match &cfg.transport {
        TransportConfig::Stdio { .. } => Ok(Box::new(StdioTransport::spawn(cfg)?)),
        TransportConfig::Http { url } => Ok(Box::new(HttpTransport::new(url, cfg))),
    }
}

fn message(id: Option<u64>, method: &str, params: Value) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("jsonrpc".into(), json!("2.0"));
    if let Some(id) = id {
        m.insert("id".into(), json!(id));
    }
    m.insert("method".into(), json!(method));
    if !params.is_null() {
        m.insert("params".into(), params);
    }
    Value::Object(m)
}

/// Our answer to a server-to-client request.
fn answer_server_request(id: &Value, method: &str) -> Value {
    if method == "ping" {
        json!({"jsonrpc": "2.0", "id": id, "result": {}})
    } else {
        json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "Method not found"}})
    }
}

/// The outcome carried by a response message.
fn response_outcome(msg: &Value) -> Reply {
    if let Some(err) = msg.get("error") {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        let message = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("")
            .chars()
            .take(500)
            .collect();
        return Err(McpError::Rpc { code, message });
    }
    match msg.get("result") {
        Some(r) => Ok(r.clone()),
        None => Err(McpError::BadResponse(
            "a response had neither result nor error".into(),
        )),
    }
}

enum WaitEnd {
    Timeout,
    Cancelled,
    Disconnected,
}

fn wait<T>(
    rx: &mpsc::Receiver<T>,
    timeout: Duration,
    stop: Option<&StopFlag>,
) -> Result<T, WaitEnd> {
    let deadline = Instant::now() + timeout;
    loop {
        if stop.is_some_and(|s| s.is_stopped()) {
            return Err(WaitEnd::Cancelled);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(WaitEnd::Timeout);
        }
        let slice = (deadline - now).min(Duration::from_millis(25));
        match rx.recv_timeout(slice) {
            Ok(v) => return Ok(v),
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(WaitEnd::Disconnected),
        }
    }
}

fn cancel_params(id: u64, why: &str) -> Value {
    json!({"requestId": id, "reason": why})
}

// ---------------------------------------------------------------------------------------------
// stdio
// ---------------------------------------------------------------------------------------------

struct Shared {
    pending: Mutex<HashMap<u64, mpsc::Sender<Reply>>>,
    exited: AtomicBool,
    bad: AtomicU64,
    list_changed: AtomicBool,
    writer: Mutex<Option<mpsc::Sender<String>>>,
    max_bytes: usize,
}

impl Shared {
    fn send_line(&self, line: String) -> Result<(), McpError> {
        let guard = self
            .writer
            .lock()
            .map_err(|_| McpError::Transport("writer unavailable".into()))?;
        match guard.as_ref() {
            Some(tx) => tx
                .send(line)
                .map_err(|_| McpError::ServerExited("its input is closed".into())),
            None => Err(McpError::ServerExited("its input is closed".into())),
        }
    }

    fn take_pending(&self, id: u64) -> Option<mpsc::Sender<Reply>> {
        self.pending.lock().ok().and_then(|mut p| p.remove(&id))
    }

    fn fail_all(&self, err: McpError) {
        let drained: Vec<_> = match self.pending.lock() {
            Ok(mut p) => p.drain().map(|(_, tx)| tx).collect(),
            Err(_) => Vec::new(),
        };
        for tx in drained {
            let _ = tx.send(Err(err.clone()));
        }
    }

    fn on_line(&self, line: &[u8]) {
        let text = String::from_utf8_lossy(line);
        let text = text.trim();
        if text.is_empty() {
            return;
        }
        let Ok(msg) = serde_json::from_str::<Value>(text) else {
            self.bad.fetch_add(1, Ordering::SeqCst);
            return;
        };
        if !msg.is_object() {
            // JSON-RPC batches are not part of the protocol versions this host speaks.
            self.bad.fetch_add(1, Ordering::SeqCst);
            return;
        }
        if let Some(method) = msg.get("method").and_then(Value::as_str) {
            match msg.get("id") {
                Some(id) => {
                    let _ = self.send_line(answer_server_request(id, method).to_string());
                }
                None => {
                    if method == "notifications/tools/list_changed" {
                        self.list_changed.store(true, Ordering::SeqCst);
                    }
                }
            }
            return;
        }
        match msg.get("id").and_then(Value::as_u64) {
            Some(id) => {
                if let Some(tx) = self.take_pending(id) {
                    let _ = tx.send(response_outcome(&msg));
                }
                // An unknown id is a late answer to a call that already timed out: dropped.
            }
            None => {
                self.bad.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    /// A line longer than the cap. Attribute it to a request if we can, else fail every pending
    /// request (none of them can be trusted to receive a correct answer).
    fn on_oversize(&self, prefix: &[u8]) {
        let err = McpError::Oversize(self.max_bytes);
        let pending_ids: Vec<u64> = self
            .pending
            .lock()
            .map(|p| p.keys().copied().collect())
            .unwrap_or_default();
        let target = if pending_ids.len() == 1 {
            pending_ids.first().copied()
        } else {
            scan_ids(prefix)
                .into_iter()
                .find(|id| pending_ids.contains(id))
        };
        match target.and_then(|id| self.take_pending(id)) {
            Some(tx) => {
                let _ = tx.send(Err(err));
            }
            None => self.fail_all(err),
        }
    }
}

/// Numeric values of `"id": <n>` occurrences in a (possibly truncated) JSON text.
fn scan_ids(prefix: &[u8]) -> Vec<u64> {
    let s = String::from_utf8_lossy(prefix);
    let mut out = Vec::new();
    let mut rest: &str = &s;
    while let Some(pos) = rest.find("\"id\"") {
        rest = &rest[pos + 4..];
        let after = rest.trim_start();
        if let Some(after) = after.strip_prefix(':') {
            let digits: String = after
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(n) = digits.parse::<u64>() {
                out.push(n);
            }
        }
    }
    out
}

/// Split a byte stream into lines, never holding more than `max` bytes of one line. Lines over
/// the cap are reported by their first bytes only.
fn read_lines(mut r: impl Read, max: usize, shared: &Shared) {
    const PREFIX: usize = 4096;
    let mut buf = vec![0u8; 64 * 1024];
    let mut cur: Vec<u8> = Vec::new();
    let mut overflow = false;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        let mut chunk = &buf[..n];
        loop {
            let nl = chunk.iter().position(|b| *b == b'\n');
            let (part, done) = match nl {
                Some(i) => (&chunk[..i], true),
                None => (chunk, false),
            };
            if !overflow {
                if cur.len() + part.len() > max {
                    overflow = true;
                    let room = PREFIX.saturating_sub(cur.len().min(PREFIX));
                    cur.truncate(PREFIX);
                    cur.extend_from_slice(&part[..part.len().min(room)]);
                } else {
                    cur.extend_from_slice(part);
                }
            }
            if !done {
                break;
            }
            if overflow {
                shared.on_oversize(&cur);
            } else {
                shared.on_line(&cur);
            }
            cur.clear();
            overflow = false;
            chunk = match nl {
                Some(i) => &chunk[i + 1..],
                None => &[],
            };
        }
    }
}

pub(crate) struct StdioTransport {
    shared: Arc<Shared>,
    child: Mutex<Option<Child>>,
    next_id: AtomicU64,
}

impl StdioTransport {
    fn spawn(cfg: &ServerConfig) -> Result<Self, McpError> {
        let TransportConfig::Stdio {
            command,
            args,
            env,
            cwd,
        } = &cfg.transport
        else {
            return Err(McpError::Spawn("not a stdio server".into()));
        };
        let mut cmd = Command::new(command);
        cmd.args(args)
            .env_clear()
            .envs(child_env(env, std::env::vars()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // MCP servers log to stderr; it is discarded so a chatty server can never block.
            .stderr(Stdio::null());
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        let mut child = cmd.spawn().map_err(|e| McpError::Spawn(e.to_string()))?;
        let (stdin, stdout) = match (child.stdin.take(), child.stdout.take()) {
            (Some(i), Some(o)) => (i, o),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(McpError::Spawn("no stdio pipes".into()));
            }
        };
        let (wtx, wrx) = mpsc::channel::<String>();
        let shared = Arc::new(Shared {
            pending: Mutex::new(HashMap::new()),
            exited: AtomicBool::new(false),
            bad: AtomicU64::new(0),
            list_changed: AtomicBool::new(false),
            writer: Mutex::new(Some(wtx)),
            max_bytes: cfg.max_response_bytes,
        });
        // Writer: requests never block the caller, even if the server stops reading.
        std::thread::spawn(move || {
            let mut stdin = stdin;
            while let Ok(line) = wrx.recv() {
                if stdin.write_all(line.as_bytes()).is_err()
                    || stdin.write_all(b"\n").is_err()
                    || stdin.flush().is_err()
                {
                    break;
                }
            }
        });
        let reader_shared = shared.clone();
        let max = cfg.max_response_bytes;
        std::thread::spawn(move || {
            read_lines(stdout, max, &reader_shared);
            reader_shared.exited.store(true, Ordering::SeqCst);
            reader_shared.fail_all(McpError::ServerExited("its output closed".into()));
        });
        Ok(StdioTransport {
            shared,
            child: Mutex::new(Some(child)),
            next_id: AtomicU64::new(0),
        })
    }

    fn cancel(&self, id: u64, why: &str) {
        let _ = self.shared.send_line(
            message(None, "notifications/cancelled", cancel_params(id, why)).to_string(),
        );
    }
}

impl Transport for StdioTransport {
    fn request(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
        stop: Option<&StopFlag>,
    ) -> Result<Value, McpError> {
        if self.shared.exited.load(Ordering::SeqCst) {
            return Err(McpError::ServerExited("not running".into()));
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        let (tx, rx) = mpsc::channel();
        match self.shared.pending.lock() {
            Ok(mut p) => {
                p.insert(id, tx);
            }
            Err(_) => return Err(McpError::Transport("request table unavailable".into())),
        }
        // Ordered after the insert: the reader sets `exited` before draining the table.
        if self.shared.exited.load(Ordering::SeqCst) {
            self.shared.take_pending(id);
            return Err(McpError::ServerExited("not running".into()));
        }
        if let Err(e) = self
            .shared
            .send_line(message(Some(id), method, params).to_string())
        {
            self.shared.take_pending(id);
            return Err(e);
        }
        match wait(&rx, timeout, stop) {
            Ok(reply) => reply,
            Err(WaitEnd::Timeout) => {
                self.shared.take_pending(id);
                self.cancel(id, "timed out");
                Err(McpError::Timeout(timeout))
            }
            Err(WaitEnd::Cancelled) => {
                self.shared.take_pending(id);
                self.cancel(id, "stopped by the member");
                Err(McpError::Cancelled)
            }
            Err(WaitEnd::Disconnected) => Err(McpError::ServerExited("its output closed".into())),
        }
    }

    fn notify(&self, method: &str, params: Value) -> Result<(), McpError> {
        self.shared
            .send_line(message(None, method, params).to_string())
    }

    fn exited(&self) -> bool {
        self.shared.exited.load(Ordering::SeqCst)
    }

    fn bad_messages(&self) -> u64 {
        self.shared.bad.load(Ordering::SeqCst)
    }

    fn tools_changed(&self) -> bool {
        self.shared.list_changed.load(Ordering::SeqCst)
    }

    fn close(&self) {
        // Closing the writer closes the server's stdin; then make sure the process is gone.
        if let Ok(mut w) = self.shared.writer.lock() {
            w.take();
        }
        if let Ok(mut c) = self.child.lock() {
            if let Some(mut child) = c.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        self.close();
    }
}

// ---------------------------------------------------------------------------------------------
// streamable HTTP
// ---------------------------------------------------------------------------------------------

/// What one HTTP exchange needs; cloned into the worker thread.
#[derive(Clone)]
struct HttpCtx {
    url: String,
    loopback: bool,
    version: Option<String>,
    session: Option<String>,
    max_bytes: usize,
    bad: Arc<AtomicU64>,
    list_changed: Arc<AtomicBool>,
}

struct HttpAnswer {
    reply: Option<Reply>,
    session: Option<String>,
}

fn coarse(e: &reqwest::Error) -> McpError {
    if e.is_timeout() {
        McpError::Transport("the request timed out".into())
    } else if e.is_connect() {
        McpError::Transport("could not connect".into())
    } else {
        McpError::Transport("the request failed".into())
    }
}

fn valid_session_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

impl HttpCtx {
    fn client(&self, timeout: Duration) -> Result<reqwest::blocking::Client, McpError> {
        let mut b = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none());
        if self.loopback {
            b = b.no_proxy();
        }
        b.build()
            .map_err(|_| McpError::Transport("could not build the HTTP client".into()))
    }

    /// POST one message. `expect` is the request id to wait for (None for notifications and
    /// our answers to server requests).
    fn exchange(
        &self,
        body: String,
        expect: Option<u64>,
        timeout: Duration,
    ) -> Result<HttpAnswer, McpError> {
        let client = self.client(timeout)?;
        let mut req = client
            .post(&self.url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(body);
        if let Some(v) = &self.version {
            req = req.header("mcp-protocol-version", v);
        }
        if let Some(s) = &self.session {
            req = req.header("mcp-session-id", s);
        }
        let resp = req.send().map_err(|e| coarse(&e))?;
        let status = resp.status();
        let session = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .filter(|s| valid_session_id(s))
            .map(str::to_string);
        let Some(id) = expect else {
            return if status.is_success() {
                Ok(HttpAnswer {
                    reply: None,
                    session,
                })
            } else {
                Err(McpError::Transport(format!("HTTP {}", status.as_u16())))
            };
        };
        if status.as_u16() == 404 && self.session.is_some() {
            return Err(McpError::Transport(
                "the server ended the session (HTTP 404)".into(),
            ));
        }
        if !status.is_success() {
            return Err(McpError::Transport(format!("HTTP {}", status.as_u16())));
        }
        let ctype = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let reply = if ctype.starts_with("text/event-stream") {
            self.read_sse(resp, id, timeout)?
        } else {
            let mut body = Vec::new();
            resp.take(self.max_bytes as u64 + 1)
                .read_to_end(&mut body)
                .map_err(|_| McpError::Transport("reading the response failed".into()))?;
            if body.len() > self.max_bytes {
                return Err(McpError::Oversize(self.max_bytes));
            }
            let msg: Value = serde_json::from_slice(&body)
                .map_err(|_| McpError::BadResponse("the body was not JSON".into()))?;
            if msg.get("id").and_then(Value::as_u64) != Some(id) {
                return Err(McpError::BadResponse(
                    "the response did not answer this request".into(),
                ));
            }
            response_outcome(&msg)
        };
        Ok(HttpAnswer {
            reply: Some(reply),
            session,
        })
    }

    /// Read an SSE stream until the response to `id` arrives (bounded by the size cap).
    fn read_sse(
        &self,
        resp: reqwest::blocking::Response,
        id: u64,
        timeout: Duration,
    ) -> Result<Reply, McpError> {
        let mut reader = BufReader::new(resp.take(self.max_bytes as u64 + 1));
        let mut total = 0usize;
        let mut data = String::new();
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader
                .read_line(&mut line)
                .map_err(|_| McpError::Transport("reading the event stream failed".into()))?;
            total += n;
            if total > self.max_bytes {
                return Err(McpError::Oversize(self.max_bytes));
            }
            let eof = n == 0;
            let l = line.trim_end_matches(['\r', '\n']);
            if eof || l.is_empty() {
                if !data.is_empty() {
                    if let Some(reply) = self.on_event(&data, id, timeout) {
                        return Ok(reply);
                    }
                    data.clear();
                }
                if eof {
                    return Err(McpError::BadResponse(
                        "the event stream ended without a response".into(),
                    ));
                }
                continue;
            }
            if let Some(d) = l.strip_prefix("data:") {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(d.strip_prefix(' ').unwrap_or(d));
            }
            // `event:`, `id:`, `retry:` and comments carry nothing this host needs.
        }
    }

    fn on_event(&self, data: &str, id: u64, timeout: Duration) -> Option<Reply> {
        let Ok(msg) = serde_json::from_str::<Value>(data) else {
            self.bad.fetch_add(1, Ordering::SeqCst);
            return None;
        };
        if let Some(method) = msg.get("method").and_then(Value::as_str) {
            match msg.get("id") {
                Some(rid) => {
                    let answer = answer_server_request(rid, method).to_string();
                    let _ = self.exchange(answer, None, timeout.min(Duration::from_secs(10)));
                }
                None => {
                    if method == "notifications/tools/list_changed" {
                        self.list_changed.store(true, Ordering::SeqCst);
                    }
                }
            }
            return None;
        }
        if msg.get("id").and_then(Value::as_u64) == Some(id) {
            return Some(response_outcome(&msg));
        }
        None
    }
}

pub(crate) struct HttpTransport {
    url: String,
    loopback: bool,
    version: Mutex<Option<String>>,
    session: Mutex<Option<String>>,
    next_id: AtomicU64,
    max_bytes: usize,
    bad: Arc<AtomicU64>,
    list_changed: Arc<AtomicBool>,
}

impl HttpTransport {
    fn new(url: &str, cfg: &ServerConfig) -> Self {
        HttpTransport {
            url: url.to_string(),
            loopback: url.starts_with("http://"),
            version: Mutex::new(None),
            session: Mutex::new(None),
            next_id: AtomicU64::new(0),
            max_bytes: cfg.max_response_bytes,
            bad: Arc::new(AtomicU64::new(0)),
            list_changed: Arc::new(AtomicBool::new(false)),
        }
    }

    fn ctx(&self) -> HttpCtx {
        HttpCtx {
            url: self.url.clone(),
            loopback: self.loopback,
            version: self.version.lock().ok().and_then(|v| v.clone()),
            session: self.session.lock().ok().and_then(|v| v.clone()),
            max_bytes: self.max_bytes,
            bad: self.bad.clone(),
            list_changed: self.list_changed.clone(),
        }
    }

    /// Post a notification from a worker thread (the blocking HTTP client must never run on an
    /// async runtime thread). `wait_for` = None: fire and forget.
    fn post_notification(&self, msg: Value, wait_for: Option<Duration>) -> Result<(), McpError> {
        let ctx = self.ctx();
        let (tx, rx) = mpsc::channel();
        let t = wait_for.unwrap_or(Duration::from_secs(5));
        std::thread::spawn(move || {
            let r = ctx.exchange(msg.to_string(), None, t).map(|_| ());
            let _ = tx.send(r);
        });
        match wait_for {
            None => Ok(()),
            Some(d) => match wait(&rx, d, None) {
                Ok(r) => r,
                Err(_) => Err(McpError::Timeout(d)),
            },
        }
    }
}

impl Transport for HttpTransport {
    fn request(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
        stop: Option<&StopFlag>,
    ) -> Result<Value, McpError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        let ctx = self.ctx();
        let body = message(Some(id), method, params).to_string();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(ctx.exchange(body, Some(id), timeout));
        });
        let ended = match wait(&rx, timeout, stop) {
            Ok(Ok(answer)) => {
                if method == "initialize" {
                    if let (Some(s), Ok(mut slot)) = (answer.session, self.session.lock()) {
                        *slot = Some(s);
                    }
                }
                return answer
                    .reply
                    .unwrap_or_else(|| Err(McpError::BadResponse("no response".into())));
            }
            Ok(Err(McpError::Transport(m))) if m == "the request timed out" => {
                Err(McpError::Timeout(timeout))
            }
            Ok(Err(e)) => return Err(e),
            Err(WaitEnd::Timeout) => Err(McpError::Timeout(timeout)),
            Err(WaitEnd::Cancelled) => Err(McpError::Cancelled),
            Err(WaitEnd::Disconnected) => {
                return Err(McpError::Transport("the request worker ended".into()))
            }
        };
        let why = if matches!(ended, Err(McpError::Cancelled)) {
            "stopped by the member"
        } else {
            "timed out"
        };
        let _ = self.post_notification(
            message(None, "notifications/cancelled", cancel_params(id, why)),
            None,
        );
        ended
    }

    fn notify(&self, method: &str, params: Value) -> Result<(), McpError> {
        self.post_notification(message(None, method, params), Some(Duration::from_secs(5)))
    }

    fn set_protocol_version(&self, v: &str) {
        if let Ok(mut slot) = self.version.lock() {
            *slot = Some(v.to_string());
        }
    }

    fn bad_messages(&self) -> u64 {
        self.bad.load(Ordering::SeqCst)
    }

    fn tools_changed(&self) -> bool {
        self.list_changed.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared(max: usize) -> Shared {
        Shared {
            pending: Mutex::new(HashMap::new()),
            exited: AtomicBool::new(false),
            bad: AtomicU64::new(0),
            list_changed: AtomicBool::new(false),
            writer: Mutex::new(None),
            max_bytes: max,
        }
    }

    #[test]
    fn lines_split_across_reads_and_oversize_lines_are_isolated() {
        let s = shared(64);
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        if let Ok(mut p) = s.pending.lock() {
            p.insert(1, tx1);
            p.insert(2, tx2);
            p.insert(3, tx3);
        }
        let big = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":\"{}\"}}",
            "x".repeat(500)
        );
        let input = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":7}}\n{big}\nnot json\n{{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":9}}\n"
        );
        // A reader that hands out 7 bytes at a time exercises the split-line path.
        struct Slow(Vec<u8>, usize);
        impl Read for Slow {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = 7.min(self.0.len() - self.1).min(buf.len());
                buf[..n].copy_from_slice(&self.0[self.1..self.1 + n]);
                self.1 += n;
                Ok(n)
            }
        }
        read_lines(Slow(input.into_bytes(), 0), 64, &s);
        assert_eq!(rx1.recv().ok(), Some(Ok(json!(7))));
        assert_eq!(rx2.recv().ok(), Some(Err(McpError::Oversize(64))));
        assert_eq!(rx3.recv().ok(), Some(Ok(json!(9))));
        assert_eq!(s.bad.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn scan_ids_finds_numeric_ids_in_a_prefix() {
        assert_eq!(
            scan_ids(br#"{"jsonrpc":"2.0", "id" : 42, "result": {"#),
            vec![42]
        );
        assert_eq!(scan_ids(br#"{"result":{"id":"x"},"id":5"#), vec![5]);
        assert!(scan_ids(b"garbage").is_empty());
    }

    #[test]
    fn rpc_errors_and_missing_results_are_typed() {
        let e = response_outcome(&json!({"id": 1, "error": {"code": -32602, "message": "bad"}}));
        assert_eq!(
            e,
            Err(McpError::Rpc {
                code: -32602,
                message: "bad".into()
            })
        );
        assert!(matches!(
            response_outcome(&json!({"id": 1})),
            Err(McpError::BadResponse(_))
        ));
    }

    #[test]
    fn server_requests_get_method_not_found_except_ping() {
        let a = answer_server_request(&json!("s1"), "sampling/createMessage");
        assert_eq!(a["error"]["code"], json!(-32601));
        let p = answer_server_request(&json!(9), "ping");
        assert_eq!(p["result"], json!({}));
    }

    #[test]
    fn session_ids_must_be_visible_ascii() {
        assert!(valid_session_id("abc-123"));
        assert!(!valid_session_id(""));
        assert!(!valid_session_id("a b"));
        assert!(!valid_session_id(&"a".repeat(300)));
    }
}
