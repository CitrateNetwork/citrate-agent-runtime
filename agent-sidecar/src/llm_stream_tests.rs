// HUP-S1.1 (g1-render) — streamed answers: the assembler, the transport, and the session events.
use super::*;
use citrate_agent_loop::{Message, ToolSpec};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;

fn chunk(delta: Value) -> String {
    format!("data: {}\n\n", json!({"choices": [{"index": 0, "delta": delta, "finish_reason": null}]}))
}

fn text_stream(parts: &[&str]) -> String {
    let mut s = String::new();
    for p in parts {
        s.push_str(&chunk(json!({"content": p})));
    }
    s.push_str(&format!(
        "data: {}\n\n",
        json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
    ));
    s.push_str(&format!(
        "data: {}\n\n",
        json!({"choices": [], "usage": {"prompt_tokens": 12, "completion_tokens": 5}})
    ));
    s.push_str("data: [DONE]\n\n");
    s
}

type Streamed = Result<(AssistantTurn, Option<TokenUsage>), LlmError>;

fn feed(stream: &str) -> (Vec<String>, Streamed) {
    let mut deltas = Vec::new();
    let r = read_streamed("text/event-stream", stream.as_bytes(), &mut |d| deltas.push(d.to_string()));
    (deltas, r)
}

#[test]
fn text_deltas_arrive_in_order_and_the_turn_is_the_whole_answer() {
    let (deltas, r) = feed(&text_stream(&["Height ", "is ", "6,310."]));
    assert_eq!(deltas, vec!["Height ", "is ", "6,310."]);
    let (turn, usage) = r.unwrap();
    assert_eq!(turn.content, "Height is 6,310.");
    assert!(turn.tool_calls.is_empty());
    assert_eq!(usage, Some(TokenUsage { prompt_tokens: 12, completion_tokens: 5, generation_ms: None }), "metering keeps the provider's counts");
}

#[test]
fn tool_call_pieces_are_joined_by_index() {
    let mut s = String::new();
    s.push_str(&chunk(json!({"tool_calls": [{"index": 0, "id": "call_a", "type": "function", "function": {"name": "node_status", "arguments": ""}}]})));
    s.push_str(&chunk(json!({"tool_calls": [{"index": 1, "id": "call_b", "function": {"name": "get_balance", "arguments": "{\"addr"}}]})));
    s.push_str(&chunk(json!({"tool_calls": [{"index": 1, "function": {"arguments": "ess\":\"0x1\"}"}}]})));
    s.push_str(&format!("data: {}\n\n", json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})));
    s.push_str("data: [DONE]\n\n");
    let (deltas, r) = feed(&s);
    assert!(deltas.is_empty(), "tool calls are not assistant text");
    let (turn, _) = r.unwrap();
    assert_eq!(turn.tool_calls.len(), 2);
    assert_eq!(turn.tool_calls[0].id, "call_a");
    assert_eq!(turn.tool_calls[0].arguments, "{}", "no arguments means an empty object");
    assert_eq!(turn.tool_calls[1].name, "get_balance");
    assert_eq!(turn.tool_calls[1].arguments, "{\"address\":\"0x1\"}");
}

#[test]
fn a_stream_cut_off_before_it_finished_is_an_error_not_a_short_answer() {
    let s = chunk(json!({"content": "Half an ans"}));
    let (deltas, r) = feed(&s);
    assert_eq!(deltas, vec!["Half an ans"], "what arrived was shown");
    assert!(matches!(r, Err(LlmError::Transport(_))), "{r:?}");
}

#[test]
fn an_error_chunk_and_a_garbled_chunk_fail_honestly() {
    let (_, r) = feed("data: {\"error\":{\"message\":\"context overflow\"}}\n\n");
    assert!(matches!(r, Err(LlmError::Provider(_))), "{r:?}");
    let (_, r) = feed("data: {not json\n\n");
    assert!(matches!(r, Err(LlmError::BadResponse(_))), "{r:?}");
    let (_, r) = feed("data: [DONE]\n\n");
    assert!(matches!(r, Err(LlmError::BadResponse(_))), "an empty answer is refused like the whole-body path: {r:?}");
}

#[test]
fn comments_blank_lines_and_crlf_are_tolerated() {
    let s = text_stream(&["ok"]).replace("\n", "\r\n");
    let s = format!(": keep-alive\r\n\r\nevent: message\r\n{s}");
    let (deltas, r) = feed(&s);
    assert_eq!(deltas, vec!["ok"]);
    assert_eq!(r.unwrap().0.content, "ok");
}

#[test]
fn a_server_that_ignores_stream_true_is_read_as_one_answer_without_deltas() {
    let body = r#"{"choices":[{"message":{"content":"whole"}}],"usage":{"prompt_tokens":3,"completion_tokens":1}}"#;
    let mut deltas = Vec::new();
    let (turn, usage) = read_streamed("application/json", body.as_bytes(), &mut |d| deltas.push(d.to_string())).unwrap();
    assert!(deltas.is_empty());
    assert_eq!(turn.content, "whole");
    assert_eq!(usage.map(|u| u.completion_tokens), Some(1));
}

#[test]
fn an_absurd_tool_call_index_is_refused() {
    let s = chunk(json!({"tool_calls": [{"index": 100000, "function": {"name": "x"}}]}));
    let (_, r) = feed(&s);
    assert!(matches!(r, Err(LlmError::BadResponse(_))), "{r:?}");
}

#[test]
fn the_stream_switch_is_on_unless_explicitly_off() {
    assert!(streaming_from_value(None));
    assert!(streaming_from_value(Some("1")));
    assert!(!streaming_from_value(Some("0")));
    assert!(!streaming_from_value(Some(" off ")));
    assert!(!streaming_from_value(Some("false")));
}

fn req() -> CompletionRequest {
    CompletionRequest {
        model: "m".into(),
        messages: vec![Message::user("hi")],
        tools: vec![ToolSpec {
            name: "node_status".into(),
            description: "d".into(),
            parameters: json!({"type": "object"}),
            host: citrate_agent_loop::HostKind::Core,
            annotations: Default::default(),
        }],
        max_tokens: 64,
    }
}

#[test]
fn the_stream_body_asks_for_a_stream_with_usage_and_the_plain_body_does_not() {
    let b = to_stream_body(&req());
    assert_eq!(b["stream"], true);
    assert_eq!(b["stream_options"]["include_usage"], true);
    assert_eq!(b["tools"][0]["function"]["name"], "node_status");
    let plain = to_wire_body(&req());
    assert_eq!(plain["stream"], false);
    assert!(plain.get("stream_options").is_none());
}

/// A one-shot loopback server: records the request body, answers with `content_type` + `body`.
fn serve_once(content_type: &'static str, body: String) -> (String, std::sync::mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut reader = BufReader::new(sock.try_clone().expect("clone"));
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            let mut buf = vec![0u8; len];
            let _ = reader.read_exact(&mut buf);
            let _ = tx.send(String::from_utf8_lossy(&buf).to_string());
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes());
        }
    });
    (format!("http://127.0.0.1:{port}/v1"), rx)
}

#[test]
fn the_client_streams_over_http_and_hands_each_delta_on() {
    let (url, seen) = serve_once("text/event-stream", text_stream(&["Hel", "lo"]));
    let c = OpenAiCompatClient::new(&url, "", Duration::from_secs(5));
    let mut deltas = Vec::new();
    let (turn, usage) = c.complete_streaming(&req(), &mut |d| deltas.push(d.to_string())).unwrap();
    assert_eq!(deltas, vec!["Hel", "lo"]);
    assert_eq!(turn.content, "Hello");
    assert!(usage.is_some());
    let sent: Value = serde_json::from_str(&seen.recv().unwrap()).unwrap();
    assert_eq!(sent["stream"], true);
}

#[test]
fn with_streaming_off_the_client_sends_a_plain_request() {
    let (url, seen) = serve_once("application/json", r#"{"choices":[{"message":{"content":"plain"}}]}"#.to_string());
    let c = OpenAiCompatClient::new(&url, "", Duration::from_secs(5)).with_streaming(false);
    let mut deltas = Vec::new();
    let (turn, _) = c.complete_streaming(&req(), &mut |d| deltas.push(d.to_string())).unwrap();
    assert!(deltas.is_empty());
    assert_eq!(turn.content, "plain");
    let sent: Value = serde_json::from_str(&seen.recv().unwrap()).unwrap();
    assert_eq!(sent["stream"], false);
}

/// HUP-S7.6 with HUP-S1.1: llama-server's `timings.predicted_ms` on the last chunk reaches the
/// streamed usage, so the monitor can show tokens per second for streamed answers too.
#[test]
fn a_streamed_answer_keeps_the_generation_time() {
    let mut s = chunk(json!({"content": "hi"}));
    s.push_str(&format!(
        "data: {}\n\n",
        json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 7, "completion_tokens": 2}, "timings": {"predicted_ms": 41.6}})
    ));
    s.push_str("data: [DONE]\n\n");
    let (_, r) = feed(&s);
    let (_, usage) = r.unwrap();
    assert_eq!(usage, Some(TokenUsage { prompt_tokens: 7, completion_tokens: 2, generation_ms: Some(42) }));
}
