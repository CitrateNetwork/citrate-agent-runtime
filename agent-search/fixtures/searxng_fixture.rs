//! A real, tiny stand-in for `searxng-run`, used only by this crate's integration tests. It reads
//! the settings file named by `SEARXNG_SETTINGS_PATH` the way SearXNG does (only
//! `server.bind_address` and `server.port` matter here), then serves `/healthz` and
//! `/search?q=…&format=json` on that address. Each result snippet carries this process id (so a
//! test can see the process was reused) and the word LEAK if a probe variable from the test
//! process reached it (so a test can see the environment was scrubbed). Not installed or shipped.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

fn setting(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let l = l.trim();
        let rest = l.strip_prefix(key)?.trim_start().strip_prefix(':')?;
        Some(rest.trim().trim_matches('"').to_string())
    })
}

fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let h = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(h, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn main() {
    let Ok(path) = std::env::var("SEARXNG_SETTINGS_PATH") else {
        eprintln!("SEARXNG_SETTINGS_PATH is not set");
        std::process::exit(2);
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!("cannot read settings");
        std::process::exit(2);
    };
    let bind = setting(&text, "bind_address").unwrap_or_else(|| "127.0.0.1".into());
    let port = setting(&text, "port").unwrap_or_else(|| "8888".into());
    let Ok(listener) = TcpListener::bind(format!("{bind}:{port}")) else {
        eprintln!("cannot bind");
        std::process::exit(3);
    };
    let leak = std::env::var_os("CITRATE_N4_LEAK_PROBE").is_some();
    let pid = std::process::id();
    for stream in listener.incoming().flatten() {
        let Ok(read_half) = stream.try_clone() else {
            continue;
        };
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            continue;
        }
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h).is_err() || h.trim().is_empty() {
                break;
            }
        }
        let target = line.split_whitespace().nth(1).unwrap_or("/").to_string();
        let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
        let (status, ctype, body) = match path {
            "/healthz" => (200, "text/plain", "OK".to_string()),
            "/search" => {
                let q = query
                    .split('&')
                    .find_map(|kv| kv.strip_prefix("q="))
                    .map(decode)
                    .unwrap_or_default();
                let enc = q.replace(' ', "%20");
                let snippet = format!("pid {pid}{}", if leak { " LEAK" } else { "" });
                let results: Vec<String> = ["one", "two", "three"]
                    .iter()
                    .enumerate()
                    .map(|(i, host)| {
                        format!(
                            "{{\"url\":{},\"title\":{},\"content\":{},\"engine\":\"fixture\"}}",
                            json_str(&format!("https://{host}.example/{enc}")),
                            json_str(&format!("{q} result {}", i + 1)),
                            json_str(&snippet)
                        )
                    })
                    .chain(std::iter::once(
                        "{\"url\":\"javascript:alert(1)\",\"title\":\"bad\",\"content\":\"\"}"
                            .to_string(),
                    ))
                    .collect();
                (
                    200,
                    "application/json",
                    format!(
                        "{{\"query\":{},\"results\":[{}]}}",
                        json_str(&q),
                        results.join(",")
                    ),
                )
            }
            _ => (404, "text/plain", "not found".to_string()),
        };
        let mut out = stream;
        let _ = write!(
            out,
            "HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = out.flush();
    }
}
