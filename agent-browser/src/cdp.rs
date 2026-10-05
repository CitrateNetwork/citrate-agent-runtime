//! HUP-S5.1: a small blocking Chrome DevTools Protocol client.
//!
//! One WebSocket per browser, flat sessions (`Target.attachToTarget { flatten: true }`), so every
//! page command carries a `sessionId`. One I/O thread owns the socket: it writes queued commands,
//! reads replies and events, routes each reply to its caller, and hands events to one handler
//! (which may answer with a command, e.g. a screencast frame ack). Loopback only: the client
//! refuses a DevTools URL whose host is not a loopback address.

use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{json, Value};
use tungstenite::Message;

/// How long the I/O thread blocks on a read before it checks its outbox again.
const POLL: Duration = Duration::from_millis(15);

/// An event from the browser.
#[derive(Debug, Clone)]
pub struct CdpEvent {
    pub method: String,
    pub params: Value,
    /// The flat session the event belongs to (absent for browser-level events).
    pub session_id: Option<String>,
}

/// A command the event handler wants sent (no reply is awaited).
#[derive(Debug, Clone)]
pub struct Reply {
    pub method: String,
    pub params: Value,
    pub session_id: Option<String>,
}

/// Called on the I/O thread for every event. Keep it short.
pub type EventHandler = Arc<dyn Fn(&CdpEvent) -> Option<Reply> + Send + Sync>;

type Waiter = mpsc::Sender<Result<Value, String>>;

/// A live DevTools connection.
pub struct Cdp {
    outbox: Mutex<Option<mpsc::Sender<String>>>,
    pending: Arc<Mutex<HashMap<u64, Waiter>>>,
    next_id: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
    timeout: Duration,
    io: Mutex<Option<JoinHandle<()>>>,
}

/// Check that a DevTools WebSocket URL points at this machine, and return its socket address.
pub fn loopback_ws_addr(ws_url: &str) -> Result<SocketAddr, String> {
    let u = url::Url::parse(ws_url).map_err(|e| format!("not a DevTools address: {e}"))?;
    if u.scheme() != "ws" {
        return Err("the DevTools address must be a ws:// address".to_string());
    }
    let port = u
        .port()
        .ok_or_else(|| "the DevTools address has no port".to_string())?;
    let ip: std::net::IpAddr = match u.host() {
        Some(url::Host::Ipv4(ip)) => ip.into(),
        Some(url::Host::Ipv6(ip)) => ip.into(),
        Some(url::Host::Domain(d)) if d.eq_ignore_ascii_case("localhost") => {
            std::net::Ipv4Addr::LOCALHOST.into()
        }
        _ => return Err("the DevTools address must be on this machine (loopback)".to_string()),
    };
    if !ip.is_loopback() {
        return Err("the DevTools address must be on this machine (loopback)".to_string());
    }
    let addr = (ip, port)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| "the DevTools address did not resolve".to_string())?;
    Ok(addr)
}

fn fail_all(pending: &Mutex<HashMap<u64, Waiter>>, why: &str) {
    let drained: Vec<Waiter> = match pending.lock() {
        Ok(mut g) => g.drain().map(|(_, w)| w).collect(),
        Err(p) => p.into_inner().drain().map(|(_, w)| w).collect(),
    };
    for w in drained {
        let _ = w.send(Err(why.to_string()));
    }
}

impl Cdp {
    /// Connect to a DevTools WebSocket on loopback. `timeout` bounds every command.
    pub fn connect(ws_url: &str, on_event: EventHandler, timeout: Duration) -> Result<Cdp, String> {
        let addr = loopback_ws_addr(ws_url)?;
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
            .map_err(|e| format!("could not reach the browser: {e}"))?;
        // The handshake waits as long as a command may (at least 10 s): a loaded machine can take
        // longer than that to answer it (A51).
        stream
            .set_read_timeout(Some(timeout.max(Duration::from_secs(10))))
            .map_err(|e| e.to_string())?;
        let (mut ws, _resp) = tungstenite::client(ws_url, stream)
            .map_err(|e| format!("the browser refused the DevTools connection: {e}"))?;
        ws.get_mut()
            .set_read_timeout(Some(POLL))
            .map_err(|e| e.to_string())?;
        let _ = ws.get_mut().set_nodelay(true);

        let (tx, rx) = mpsc::channel::<String>();
        let pending: Arc<Mutex<HashMap<u64, Waiter>>> = Arc::new(Mutex::new(HashMap::new()));
        let closed = Arc::new(AtomicBool::new(false));
        let next_id = Arc::new(AtomicU64::new(1));
        let (p2, c2, n2) = (pending.clone(), closed.clone(), next_id.clone());
        let io = std::thread::Builder::new()
            .name("citrate-cdp".to_string())
            .spawn(move || {
                let why = loop {
                    // Write everything queued (a disconnected outbox means close).
                    let mut close = false;
                    let mut write_err = None;
                    loop {
                        match rx.try_recv() {
                            Ok(text) => {
                                if let Err(e) = ws.send(Message::Text(text)) {
                                    write_err = Some(e.to_string());
                                    break;
                                }
                            }
                            Err(mpsc::TryRecvError::Empty) => break,
                            Err(mpsc::TryRecvError::Disconnected) => {
                                close = true;
                                break;
                            }
                        }
                    }
                    if let Some(e) = write_err {
                        break format!("the browser connection failed: {e}");
                    }
                    if close || c2.load(Ordering::SeqCst) {
                        let _ = ws.close(None);
                        let _ = ws.flush();
                        break "the browser connection was closed".to_string();
                    }
                    match ws.read() {
                        Ok(Message::Text(text)) => {
                            let Ok(v) = serde_json::from_str::<Value>(&text) else {
                                continue;
                            };
                            if let Some(id) = v["id"].as_u64() {
                                let waiter = p2.lock().ok().and_then(|mut g| g.remove(&id));
                                if let Some(w) = waiter {
                                    let res = if v.get("error").is_some() {
                                        Err(v["error"]["message"]
                                            .as_str()
                                            .unwrap_or("the browser returned an error")
                                            .to_string())
                                    } else {
                                        Ok(v["result"].clone())
                                    };
                                    let _ = w.send(res);
                                }
                            } else if let Some(method) = v["method"].as_str() {
                                let ev = CdpEvent {
                                    method: method.to_string(),
                                    params: v["params"].clone(),
                                    session_id: v["sessionId"].as_str().map(str::to_string),
                                };
                                if let Some(r) = on_event(&ev) {
                                    let id = n2.fetch_add(1, Ordering::SeqCst);
                                    let mut msg =
                                        json!({"id": id, "method": r.method, "params": r.params});
                                    if let Some(s) = r.session_id {
                                        msg["sessionId"] = json!(s);
                                    }
                                    let _ = ws.send(Message::Text(msg.to_string()));
                                }
                            }
                        }
                        Ok(Message::Close(_)) => {
                            break "the browser closed the connection".to_string()
                        }
                        Ok(_) => {}
                        Err(tungstenite::Error::Io(e))
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut => {}
                        Err(e) => break format!("the browser connection failed: {e}"),
                    }
                };
                c2.store(true, Ordering::SeqCst);
                fail_all(&p2, &why);
            })
            .map_err(|e| e.to_string())?;
        Ok(Cdp {
            outbox: Mutex::new(Some(tx)),
            pending,
            next_id,
            closed,
            timeout,
            io: Mutex::new(Some(io)),
        })
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Send one command and wait for its result.
    pub fn call(
        &self,
        method: &str,
        params: Value,
        session: Option<&str>,
    ) -> Result<Value, String> {
        self.call_with_timeout(method, params, session, self.timeout)
    }

    pub fn call_with_timeout(
        &self,
        method: &str,
        params: Value,
        session: Option<&str>,
        timeout: Duration,
    ) -> Result<Value, String> {
        if self.is_closed() {
            return Err("the browser connection is closed".to_string());
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let mut msg = json!({"id": id, "method": method, "params": params});
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        let (tx, rx) = mpsc::channel();
        self.pending
            .lock()
            .map_err(|_| "internal: the CDP state is unavailable".to_string())?
            .insert(id, tx);
        let sent = self
            .outbox
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|o| o.send(msg.to_string()).is_ok()))
            .unwrap_or(false);
        if !sent {
            if let Ok(mut g) = self.pending.lock() {
                g.remove(&id);
            }
            return Err("the browser connection is closed".to_string());
        }
        match rx.recv_timeout(timeout) {
            Ok(r) => r.map_err(|e| format!("{method}: {e}")),
            Err(_) => {
                if let Ok(mut g) = self.pending.lock() {
                    g.remove(&id);
                }
                Err(format!(
                    "{method}: the browser did not answer within {}s",
                    timeout.as_secs()
                ))
            }
        }
    }

    /// Close the connection. In-flight calls fail at once. Idempotent.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        if let Ok(mut g) = self.outbox.lock() {
            g.take();
        }
        fail_all(&self.pending, "the browser connection was closed");
        let handle = self.io.lock().ok().and_then(|mut g| g.take());
        if let Some(h) = handle {
            if h.thread().id() != std::thread::current().id() {
                let _ = h.join();
            }
        }
    }
}

impl Drop for Cdp {
    fn drop(&mut self) {
        self.close();
    }
}
