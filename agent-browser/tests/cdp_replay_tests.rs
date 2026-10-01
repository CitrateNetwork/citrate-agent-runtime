//! HUP-S5.1: the CDP protocol layer against recorded browser replies, so it is covered on
//! machines with no Chromium. A local WebSocket server replays message shapes recorded from
//! Chrome 154: replies routed by id, error replies, an event the client must ack, a reply that
//! never comes, and the browser going away.

use std::net::TcpListener;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use citrate_agent_browser::cdp::{loopback_ws_addr, Cdp, CdpEvent, EventHandler, Reply};
use serde_json::{json, Value};
use tungstenite::Message;

/// Start a replay server; returns its ws URL and a channel of every method the client sent.
fn replay() -> (String, mpsc::Receiver<Value>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (seen_tx, seen_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let Ok(mut ws) = tungstenite::accept(stream) else {
            return;
        };
        loop {
            let msg = match ws.read() {
                Ok(Message::Text(t)) => t,
                Ok(Message::Close(_)) | Err(_) => return,
                Ok(_) => continue,
            };
            let v: Value = serde_json::from_str(&msg).unwrap_or(Value::Null);
            let _ = seen_tx.send(v.clone());
            let id = v["id"].clone();
            let reply = match v["method"].as_str().unwrap_or_default() {
                "Browser.getVersion" => Some(json!({"id": id, "result": {
                    "protocolVersion": "1.3", "product": "HeadlessChrome/154.0.8037.59",
                    "userAgent": "Mozilla/5.0", "jsVersion": "15.4"}})),
                "Page.navigate" => Some(json!({"id": id, "sessionId": v["sessionId"], "result": {
                    "frameId": "T1", "loaderId": "L1", "errorText": "net::ERR_NAME_NOT_RESOLVED"}})),
                "No.suchMethod" => Some(json!({"id": id, "error": {
                    "code": -32601, "message": "'No.suchMethod' wasn't found"}})),
                "Page.startScreencast" => {
                    let _ = ws.send(Message::Text(
                        json!({"id": id, "sessionId": "S1", "result": {}}).to_string(),
                    ));
                    Some(
                        json!({"method": "Page.screencastFrame", "sessionId": "S1", "params": {
                        "data": "/9j/4AAQ", "sessionId": 3,
                        "metadata": {"deviceWidth": 1280, "deviceHeight": 800}}}),
                    )
                }
                "Browser.close" => {
                    let _ = ws.close(None);
                    let _ = ws.flush();
                    return;
                }
                "Page.screencastFrameAck" => {
                    Some(json!({"id": id, "sessionId": "S1", "result": {}}))
                }
                _ => None, // never answered
            };
            if let Some(r) = reply {
                if ws.send(Message::Text(r.to_string())).is_err() {
                    return;
                }
            }
        }
    });
    (
        format!("ws://127.0.0.1:{port}/devtools/browser/replay"),
        seen_rx,
    )
}

fn quiet() -> EventHandler {
    Arc::new(|_| None)
}

#[test]
fn replies_are_routed_to_their_callers() {
    let (url, _seen) = replay();
    let cdp = Cdp::connect(&url, quiet(), Duration::from_secs(5)).expect("connects");
    let v = cdp
        .call("Browser.getVersion", json!({}), None)
        .expect("version");
    assert_eq!(v["product"], "HeadlessChrome/154.0.8037.59");
    let nav = cdp
        .call(
            "Page.navigate",
            json!({"url": "https://x.invalid"}),
            Some("S1"),
        )
        .expect("navigate replies");
    assert_eq!(nav["errorText"], "net::ERR_NAME_NOT_RESOLVED");
}

#[test]
fn page_commands_carry_their_session_and_browser_commands_do_not() {
    let (url, seen) = replay();
    let cdp = Cdp::connect(&url, quiet(), Duration::from_secs(5)).expect("connects");
    cdp.call("Browser.getVersion", json!({}), None).expect("ok");
    cdp.call(
        "Page.navigate",
        json!({"url": "https://a.example"}),
        Some("S9"),
    )
    .expect("ok");
    let first = seen.recv_timeout(Duration::from_secs(2)).expect("seen");
    assert!(first.get("sessionId").is_none(), "{first}");
    let second = seen.recv_timeout(Duration::from_secs(2)).expect("seen");
    assert_eq!(second["sessionId"], "S9");
    assert_eq!(second["params"]["url"], "https://a.example");
    assert!(second["id"].as_u64() > first["id"].as_u64(), "ids increase");
}

#[test]
fn an_error_reply_is_an_error() {
    let (url, _seen) = replay();
    let cdp = Cdp::connect(&url, quiet(), Duration::from_secs(5)).expect("connects");
    let e = cdp
        .call("No.suchMethod", json!({}), None)
        .expect_err("error");
    assert!(e.contains("wasn't found"), "{e}");
    // The connection stays usable.
    assert!(cdp.call("Browser.getVersion", json!({}), None).is_ok());
}

#[test]
fn a_reply_that_never_comes_times_out() {
    let (url, _seen) = replay();
    let cdp = Cdp::connect(&url, quiet(), Duration::from_millis(300)).expect("connects");
    let e = cdp
        .call("Silent.method", json!({}), None)
        .expect_err("times out");
    assert!(e.contains("did not answer"), "{e}");
    assert!(
        cdp.call("Browser.getVersion", json!({}), None).is_ok(),
        "still usable"
    );
}

#[test]
fn events_reach_the_handler_and_its_ack_is_sent() {
    let (url, seen) = replay();
    let (ev_tx, ev_rx) = mpsc::channel::<CdpEvent>();
    let ev_tx = std::sync::Mutex::new(ev_tx);
    let handler: EventHandler = Arc::new(move |ev: &CdpEvent| {
        if let Ok(t) = ev_tx.lock() {
            let _ = t.send(ev.clone());
        }
        Some(Reply {
            method: "Page.screencastFrameAck".into(),
            params: json!({"sessionId": ev.params["sessionId"].clone()}),
            session_id: ev.session_id.clone(),
        })
    });
    let cdp = Cdp::connect(&url, handler, Duration::from_secs(5)).expect("connects");
    cdp.call(
        "Page.startScreencast",
        json!({"format": "jpeg"}),
        Some("S1"),
    )
    .expect("starts");
    let ev = ev_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("the frame event");
    assert_eq!(ev.method, "Page.screencastFrame");
    assert_eq!(ev.session_id.as_deref(), Some("S1"));
    assert_eq!(ev.params["metadata"]["deviceWidth"], 1280);
    let ack = loop {
        let m = seen.recv_timeout(Duration::from_secs(2)).expect("the ack");
        if m["method"] == "Page.screencastFrameAck" {
            break m;
        }
    };
    assert_eq!(ack["params"]["sessionId"], 3);
    assert_eq!(ack["sessionId"], "S1");
}

#[test]
fn when_the_browser_goes_away_calls_fail_instead_of_hanging() {
    let (url, _seen) = replay();
    let cdp = Cdp::connect(&url, quiet(), Duration::from_secs(5)).expect("connects");
    let _ = cdp.call_with_timeout("Browser.close", json!({}), None, Duration::from_millis(500));
    let end = std::time::Instant::now() + Duration::from_secs(3);
    while !cdp.is_closed() && std::time::Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(cdp.is_closed());
    let e = cdp
        .call("Browser.getVersion", json!({}), None)
        .expect_err("closed");
    assert!(e.contains("closed"), "{e}");
}

#[test]
fn close_fails_an_in_flight_call_at_once() {
    let (url, _seen) = replay();
    let cdp = Arc::new(Cdp::connect(&url, quiet(), Duration::from_secs(30)).expect("connects"));
    let c = cdp.clone();
    let t = std::thread::spawn(move || c.call("Silent.method", json!({}), None));
    std::thread::sleep(Duration::from_millis(200));
    let started = std::time::Instant::now();
    cdp.close();
    let r = t.join().expect("joins");
    assert!(r.is_err());
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn only_loopback_devtools_addresses_are_accepted() {
    for ok in [
        "ws://127.0.0.1:9222/devtools/browser/x",
        "ws://localhost:9222/devtools/browser/x",
        "ws://[::1]:9222/devtools/browser/x",
    ] {
        assert!(loopback_ws_addr(ok).is_ok(), "{ok}");
    }
    for bad in [
        "ws://192.168.1.10:9222/devtools/browser/x",
        "ws://example.com:9222/devtools/browser/x",
        "wss://127.0.0.1:9222/devtools/browser/x",
        "http://127.0.0.1:9222/json",
        "ws://127.0.0.1/devtools/browser/x",
        "garbage",
    ] {
        assert!(loopback_ws_addr(bad).is_err(), "{bad}");
        assert!(
            Cdp::connect(bad, quiet(), Duration::from_secs(1)).is_err(),
            "{bad}"
        );
    }
}
