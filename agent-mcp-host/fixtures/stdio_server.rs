//! A real, tiny MCP server over stdio (newline-delimited JSON-RPC), used only by this crate's
//! integration tests. Flags: `--version <v>` answers initialize with that protocol version;
//! `--paged` splits tools/list over two pages; `--noisy` writes to stderr on every message;
//! `--modern` speaks only 2026-07-28 (stateless, `server/discover`); `--dual` speaks both.

#[path = "logic.rs"]
mod logic;

use logic::{Fixture, FxEra, Out};
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};

fn write_line(out: &Arc<Mutex<std::io::Stdout>>, line: &str) {
    if let Ok(mut o) = out.lock() {
        let _ = writeln!(o, "{line}");
        let _ = o.flush();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let version = args
        .iter()
        .position(|a| a == "--version")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let paged = args.iter().any(|a| a == "--paged");
    let noisy = args.iter().any(|a| a == "--noisy");
    let era = if args.iter().any(|a| a == "--modern") {
        FxEra::Modern
    } else if args.iter().any(|a| a == "--dual") {
        FxEra::Dual
    } else {
        FxEra::Legacy
    };
    let fixture = Arc::new(Mutex::new(Fixture::new(version, paged).with_era(era)));
    if let Ok(mut f) = fixture.lock() {
        f.env = std::env::vars().collect();
    }
    let out = Arc::new(Mutex::new(std::io::stdout()));
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if noisy {
            eprintln!("fixture: got {} bytes", line.len());
        }
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let outs = match fixture.lock() {
            Ok(mut f) => f.handle(&msg),
            Err(_) => break,
        };
        for o in outs {
            match o {
                Out::Msg(v) => write_line(&out, &v.to_string()),
                Out::Raw(s) => write_line(&out, &s),
                Out::Sse(vs) => {
                    for v in vs {
                        write_line(&out, &v.to_string());
                    }
                }
                Out::Exit(code) => std::process::exit(code),
                Out::Delayed { ms, id, msg } => {
                    let out = out.clone();
                    let fixture = fixture.clone();
                    std::thread::spawn(move || {
                        let start = std::time::Instant::now();
                        while start.elapsed() < std::time::Duration::from_millis(ms) {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                            let cancelled = fixture
                                .lock()
                                .map(|f| f.cancelled.contains(&id))
                                .unwrap_or(false);
                            if cancelled {
                                return;
                            }
                        }
                        write_line(&out, &msg.to_string());
                    });
                }
            }
        }
    }
}
