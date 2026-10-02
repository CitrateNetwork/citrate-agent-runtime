//! A tiny, real HTTP/1.1 server on loopback for the integration tests (std only).

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone)]
pub struct Route {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub delay: Option<Duration>,
}

impl Route {
    pub fn ok(content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Route {
            status: 200,
            headers: vec![("Content-Type".into(), content_type.into())],
            body: body.into(),
            delay: None,
        }
    }
    pub fn redirect(to: &str) -> Self {
        Route {
            status: 302,
            headers: vec![("Location".into(), to.into())],
            body: vec![],
            delay: None,
        }
    }
    pub fn status(code: u16) -> Self {
        Route {
            status: code,
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body: b"nope".to_vec(),
            delay: None,
        }
    }
    pub fn slow(mut self, d: Duration) -> Self {
        self.delay = Some(d);
        self
    }
}

/// One request the server saw.
#[derive(Debug, Clone)]
pub struct Seen {
    pub path: String,
    pub headers: HashMap<String, String>,
}

pub struct Server {
    pub addr: SocketAddr,
    pub hits: Arc<AtomicUsize>,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

/// Serve `routes` (exact path match; anything else is 404) until the process exits.
pub fn serve(routes: Vec<(&str, Route)>) -> Server {
    let map: HashMap<String, Route> = routes
        .into_iter()
        .map(|(p, r)| (p.to_string(), r))
        .collect();
    let map = Arc::new(map);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (h, s) = (hits.clone(), seen.clone());
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (map, h, s) = (map.clone(), h.clone(), s.clone());
            std::thread::spawn(move || handle(stream, &map, &h, &s));
        }
    });
    Server { addr, hits, seen }
}

fn handle(
    stream: TcpStream,
    map: &HashMap<String, Route>,
    hits: &AtomicUsize,
    seen: &Mutex<Vec<Seen>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
    let mut headers = HashMap::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).is_err() || h.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    hits.fetch_add(1, Ordering::SeqCst);
    if let Ok(mut s) = seen.lock() {
        s.push(Seen {
            path: path.clone(),
            headers,
        });
    }
    // Exact match first, then a prefix route ending in '*'.
    let route = map.get(&path).cloned().or_else(|| {
        map.iter()
            .find(|(k, _)| k.ends_with('*') && path.starts_with(k.trim_end_matches('*')))
            .map(|(_, r)| r.clone())
    });
    let route = route.unwrap_or(Route::status(404));
    if let Some(d) = route.delay {
        std::thread::sleep(d);
    }
    let mut out = stream;
    let mut head = format!(
        "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
        route.status,
        route.body.len()
    );
    for (k, v) in &route.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    let _ = out.write_all(head.as_bytes());
    let _ = out.write_all(&route.body);
    let _ = out.flush();
    let mut sink = [0u8; 64];
    let _ = reader.get_mut().read(&mut sink);
}
