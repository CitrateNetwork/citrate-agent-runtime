//! The worker wire protocol: one JSON object per line over the child's stdin (requests) and
//! stdout (responses). The child's stderr is the operator log and is not part of the protocol.
//!
//! Requests carry an `id` the response echoes, so calls can run concurrently in the worker and
//! complete out of order. Three methods:
//!
//! - `ping`: answered at once, from the reading thread, even while calls are running. The
//!   supervisor's health check.
//! - `call`: `params` go to the worker's [`Handler`] on their own thread.
//! - `shutdown`: answered, then [`serve`] returns [`ServeEnd::Shutdown`] and the worker exits.
//!
//! End of input (the parent closed the pipe or died) returns [`ServeEnd::Eof`], so a worker never
//! outlives its sidecar by more than the time it takes to notice.

use std::io::{BufRead, Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const METHOD_PING: &str = "ping";
pub const METHOD_CALL: &str = "call";
pub const METHOD_SHUTDOWN: &str = "shutdown";

/// Longest line either side accepts (a toolchain envelope carries up to a few MiB of output).
pub const MAX_LINE_BYTES: usize = 32 * 1024 * 1024;
/// Most calls a worker runs at once; more are refused with an error, not queued.
pub const MAX_CONCURRENT_CALLS: usize = 16;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// What a worker does with a `call`.
pub trait Handler: Send + Sync + 'static {
    fn call(&self, params: Value) -> Result<Value, String>;
}

/// Why [`serve`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeEnd {
    /// The supervisor asked the worker to stop.
    Shutdown,
    /// The input closed: the supervisor is gone.
    Eof,
}

/// Read one line of at most [`MAX_LINE_BYTES`]. `Ok(None)` at end of input. An over-long line is
/// consumed and returned as an empty string (it then fails to parse and is skipped).
pub fn read_line_capped<R: BufRead>(input: &mut R) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    let n = input
        .by_ref()
        .take(MAX_LINE_BYTES as u64 + 1)
        .read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.len() > MAX_LINE_BYTES && buf.last() != Some(&b'\n') {
        // Drain the rest of the over-long line.
        let mut sink = Vec::new();
        input.read_until(b'\n', &mut sink)?;
        return Ok(Some(String::new()));
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

fn write_response<W: Write>(out: &Mutex<W>, resp: &Response) {
    let Ok(mut line) = serde_json::to_string(resp) else {
        return;
    };
    line.push('\n');
    if let Ok(mut w) = out.lock() {
        // A write error means the supervisor is gone; the read side sees EOF next.
        let _ = w.write_all(line.as_bytes());
        let _ = w.flush();
    }
}

/// The worker side: serve requests from `input` until `shutdown` or end of input.
pub fn serve<R: BufRead, W: Write + Send + 'static>(
    mut input: R,
    output: W,
    handler: Arc<dyn Handler>,
) -> ServeEnd {
    let out = Arc::new(Mutex::new(output));
    let in_flight = Arc::new(AtomicUsize::new(0));
    loop {
        let line = match read_line_capped(&mut input) {
            Ok(Some(l)) => l,
            Ok(None) | Err(_) => return ServeEnd::Eof,
        };
        let Ok(req) = serde_json::from_str::<Request>(line.trim()) else {
            continue;
        };
        match req.method.as_str() {
            METHOD_PING => write_response(
                &out,
                &Response {
                    id: req.id,
                    result: Some(serde_json::json!({
                        "pong": true,
                        "pid": std::process::id(),
                        "in_flight": in_flight.load(Ordering::SeqCst),
                    })),
                    error: None,
                },
            ),
            METHOD_SHUTDOWN => {
                write_response(
                    &out,
                    &Response {
                        id: req.id,
                        result: Some(Value::Bool(true)),
                        error: None,
                    },
                );
                return ServeEnd::Shutdown;
            }
            METHOD_CALL => {
                if in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_CONCURRENT_CALLS {
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    write_response(
                        &out,
                        &Response {
                            id: req.id,
                            result: None,
                            error: Some("the worker is at its concurrent call limit".into()),
                        },
                    );
                    continue;
                }
                let (out, h, in_flight) = (out.clone(), handler.clone(), in_flight.clone());
                std::thread::spawn(move || {
                    let resp = match h.call(req.params) {
                        Ok(v) => Response {
                            id: req.id,
                            result: Some(v),
                            error: None,
                        },
                        Err(e) => Response {
                            id: req.id,
                            result: None,
                            error: Some(e),
                        },
                    };
                    write_response(&out, &resp);
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                });
            }
            other => write_response(
                &out,
                &Response {
                    id: req.id,
                    result: None,
                    error: Some(format!("unknown method '{other}'")),
                },
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::Duration;

    struct Upper;
    impl Handler for Upper {
        fn call(&self, params: Value) -> Result<Value, String> {
            match params.as_str() {
                Some(s) => Ok(Value::String(s.to_uppercase())),
                None => Err("want a string".into()),
            }
        }
    }

    /// A writer the test can read back after `serve` returns.
    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);
    impl Write for Shared {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::ErrorKind::Other)?
                .extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Shared {
        fn responses(&self) -> Vec<Response> {
            let bytes = self.0.lock().map(|v| v.clone()).unwrap_or_default();
            String::from_utf8_lossy(&bytes)
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect()
        }
    }

    fn wait_responses(out: &Shared, n: usize) -> Vec<Response> {
        for _ in 0..200 {
            let r = out.responses();
            if r.len() >= n {
                return r;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        out.responses()
    }

    #[test]
    fn ping_call_error_unknown_and_garbage_lines() {
        let input = concat!(
            "{\"id\":1,\"method\":\"ping\"}\n",
            "not json at all\n",
            "{\"id\":2,\"method\":\"call\",\"params\":\"abc\"}\n",
            "{\"id\":3,\"method\":\"call\",\"params\":7}\n",
            "{\"id\":4,\"method\":\"teleport\"}\n",
        );
        let out = Shared::default();
        let end = serve(Cursor::new(input), out.clone(), Arc::new(Upper));
        assert_eq!(end, ServeEnd::Eof);
        let mut r = wait_responses(&out, 4);
        r.sort_by_key(|x| x.id);
        assert_eq!(r.len(), 4, "garbage is skipped, everything else answered");
        assert_eq!(r[0].result.as_ref().unwrap()["pong"], true);
        assert_eq!(r[1].result, Some(Value::String("ABC".into())));
        assert_eq!(r[2].error.as_deref(), Some("want a string"));
        assert_eq!(r[3].error.as_deref(), Some("unknown method 'teleport'"));
    }

    #[test]
    fn shutdown_answers_then_returns_without_reading_further() {
        let input = concat!(
            "{\"id\":9,\"method\":\"shutdown\"}\n",
            "{\"id\":10,\"method\":\"ping\"}\n",
        );
        let out = Shared::default();
        assert_eq!(
            serve(Cursor::new(input), out.clone(), Arc::new(Upper)),
            ServeEnd::Shutdown
        );
        let r = out.responses();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].id, 9);
    }

    #[test]
    fn an_over_long_line_is_skipped_and_the_next_line_still_parses() {
        let mut input = vec![b'x'; MAX_LINE_BYTES + 10];
        input.push(b'\n');
        input.extend_from_slice(b"{\"id\":5,\"method\":\"ping\"}\n");
        let mut cur = Cursor::new(input);
        assert_eq!(read_line_capped(&mut cur).unwrap(), Some(String::new()));
        let next = read_line_capped(&mut cur).unwrap().unwrap();
        assert!(next.contains("\"id\":5"));
        assert_eq!(read_line_capped(&mut cur).unwrap(), None);
    }

    #[test]
    fn wire_shapes_omit_absent_fields() {
        let ok = Response {
            id: 1,
            result: Some(Value::Bool(true)),
            error: None,
        };
        assert_eq!(
            serde_json::to_string(&ok).unwrap(),
            "{\"id\":1,\"result\":true}"
        );
        let req: Request = serde_json::from_str("{\"id\":2,\"method\":\"ping\"}").unwrap();
        assert_eq!(req.params, Value::Null);
    }
}
