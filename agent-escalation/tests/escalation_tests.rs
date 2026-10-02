//! HUP-S1.5 (runtime half): pricing, request validation, the wire shape, settlement, the
//! transport over a real loopback HTTP server, and the disabled registry route.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use citrate_agent_escalation::{
    input_token_bound, parse_reply, run, settle, validate_base_url, wire_body,
    x402_payment_request, ApiKey, DisabledRegistry, EscalationError, EscalationRequest,
    HttpTransport, Price, RegistryError, RegistryEscalation, Transport, Usage, MAX_PROMPT_BYTES,
    PER_MESSAGE_OVERHEAD_TOKENS,
};
use serde_json::{json, Value};

const KEY: &str = "sk-test-escalation-key-0123456789";

fn price() -> Price {
    // $3 per 1M input tokens, $15 per 1M output tokens, in micro-USD.
    Price {
        input_micros_per_mtok: 3_000_000,
        output_micros_per_mtok: 15_000_000,
    }
}

fn request(base_url: &str) -> EscalationRequest {
    let p = price();
    let system = Some("You are a careful planner.".to_string());
    let prompt = "Plan the steps to add a mint page.".to_string();
    let input = input_token_bound(&[system.as_deref().unwrap_or(""), &prompt]);
    let reserved = p.upper_bound(input, 512).unwrap_or(u64::MAX);
    EscalationRequest {
        escalation_id: "esc-1".into(),
        base_url: base_url.into(),
        model: "planner-large".into(),
        api_key: ApiKey::new(KEY.to_string()).expect("valid test key"),
        system,
        prompt,
        max_tokens: 512,
        price: p,
        reserved_micros: reserved,
    }
}

// ---------------------------------------------------------------------------
// Pricing
// ---------------------------------------------------------------------------

#[test]
fn upper_bound_rounds_up_to_the_next_micro() {
    let p = price();
    // 1000 in * 3 + 500 out * 15 = 10_500 micro-USD-per-mtok units... / 1e6 per token
    // 1000 * 3_000_000 / 1e6 = 3000; 500 * 15_000_000 / 1e6 = 7500 -> 10_500 micros
    assert_eq!(p.upper_bound(1000, 500), Some(10_500));
    // one input token at $3/M is 3 micros exactly
    assert_eq!(p.upper_bound(1, 0), Some(3));
    // a fractional micro is rounded up, never down
    let cheap = Price {
        input_micros_per_mtok: 1,
        output_micros_per_mtok: 0,
    };
    assert_eq!(cheap.upper_bound(1, 0), Some(1));
    assert_eq!(cheap.upper_bound(0, 0), Some(0));
}

#[test]
fn upper_bound_fails_closed_on_overflow() {
    let p = Price {
        input_micros_per_mtok: u64::MAX,
        output_micros_per_mtok: u64::MAX,
    };
    assert_eq!(p.upper_bound(u64::MAX, u64::MAX), None);
}

#[test]
fn cost_of_reported_usage_matches_the_upper_bound_formula() {
    let p = price();
    let u = Usage {
        prompt_tokens: 1000,
        completion_tokens: 500,
    };
    assert_eq!(p.cost(u), Some(10_500));
}

#[test]
fn input_token_bound_is_at_least_the_byte_count_plus_overhead() {
    let texts = ["héllo", "world"];
    let bytes: u64 = texts.iter().map(|t| t.len() as u64).sum();
    assert_eq!(
        input_token_bound(&texts),
        bytes + PER_MESSAGE_OVERHEAD_TOKENS * 2
    );
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

#[test]
fn base_url_accepts_https_and_loopback_http_only() {
    assert!(validate_base_url("https://api.example.com/v1").is_ok());
    assert!(validate_base_url("http://127.0.0.1:1234/v1").is_ok());
    assert!(validate_base_url("http://localhost:8080/v1").is_ok());
    assert!(validate_base_url("http://[::1]:8080/v1").is_ok());
    assert!(validate_base_url("http://api.example.com/v1").is_err());
    assert!(validate_base_url("ftp://api.example.com").is_err());
    assert!(validate_base_url("https://user:pw@api.example.com/v1").is_err());
    assert!(validate_base_url("https://api.example.com/v1?x=1").is_err());
    assert!(validate_base_url("https://api.example.com/v1#f").is_err());
    assert!(validate_base_url("https://").is_err());
    assert!(validate_base_url("https://api.example.com/v1\r\nX: y").is_err());
}

#[test]
fn api_key_refuses_header_breaking_bytes_and_never_prints() {
    assert!(ApiKey::new(String::new()).is_none());
    assert!(ApiKey::new("sk bad".into()).is_none());
    assert!(ApiKey::new("sk\r\nX: y".into()).is_none());
    assert!(ApiKey::new("x".repeat(513)).is_none());
    let k = ApiKey::new(KEY.into()).expect("valid");
    assert!(!format!("{k:?}").contains("sk-test"));
    let r = request("https://api.example.com/v1");
    assert!(!format!("{r:?}").contains("sk-test"));
}

#[test]
fn request_deserializes_from_cores_camel_case_body() {
    let body = json!({
        "escalationId": "esc-9",
        "baseUrl": "https://api.example.com/v1",
        "model": "m",
        "apiKey": KEY,
        "system": null,
        "prompt": "hi",
        "maxTokens": 16,
        "price": {"inputMicrosPerMtok": 3_000_000u64, "outputMicrosPerMtok": 15_000_000u64},
        "reservedMicros": 1_000u64,
    });
    let r: EscalationRequest = serde_json::from_value(body).expect("parses");
    assert_eq!(r.escalation_id, "esc-9");
    assert_eq!(r.max_tokens, 16);
    assert!(r.validate().is_ok());
}

#[test]
fn validate_refuses_a_reservation_below_the_worst_case() {
    let mut r = request("https://api.example.com/v1");
    assert!(r.validate().is_ok());
    let worst = r.worst_case_micros().expect("no overflow");
    assert_eq!(worst, r.reserved_micros);
    r.reserved_micros = worst - 1;
    match r.validate() {
        Err(EscalationError::Invalid(m)) => assert!(m.contains("reservation"), "{m}"),
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn validate_refuses_bad_shapes() {
    let ok = request("https://api.example.com/v1");
    let mut r = request("http://example.com/v1");
    assert!(r.validate().is_err(), "plain http to a remote host");
    r = request("https://api.example.com/v1");
    r.max_tokens = 0;
    assert!(r.validate().is_err());
    r.max_tokens = 100_000;
    assert!(r.validate().is_err());
    r = request("https://api.example.com/v1");
    r.prompt = String::new();
    assert!(r.validate().is_err());
    r.prompt = "x".repeat(MAX_PROMPT_BYTES + 1);
    assert!(r.validate().is_err());
    r = request("https://api.example.com/v1");
    r.escalation_id = "bad id!".into();
    assert!(r.validate().is_err());
    r = request("https://api.example.com/v1");
    r.model = String::new();
    assert!(r.validate().is_err());
    assert!(ok.validate().is_ok());
}

// ---------------------------------------------------------------------------
// Wire shape and parsing
// ---------------------------------------------------------------------------

#[test]
fn wire_body_is_a_plain_chat_completion_with_no_tools() {
    let r = request("https://api.example.com/v1");
    let b = wire_body(&r);
    assert_eq!(b["model"], "planner-large");
    assert_eq!(b["max_tokens"], 512);
    assert_eq!(b["stream"], false);
    assert!(b.get("tools").is_none());
    let msgs = b["messages"].as_array().expect("messages");
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0]["role"], "system");
    assert_eq!(msgs[1]["role"], "user");
    assert_eq!(msgs[1]["content"], "Plan the steps to add a mint page.");
    assert!(
        !b.to_string().contains(KEY),
        "the key is a header, never in the body"
    );
}

#[test]
fn parse_reply_reads_content_and_usage() {
    let body = json!({
        "choices": [{"message": {"role": "assistant", "content": "1. do x\n2. do y"}}],
        "usage": {"prompt_tokens": 40, "completion_tokens": 12, "total_tokens": 52}
    })
    .to_string();
    let (text, usage) = parse_reply(&body).expect("parses");
    assert_eq!(text, "1. do x\n2. do y");
    assert_eq!(
        usage,
        Some(Usage {
            prompt_tokens: 40,
            completion_tokens: 12
        })
    );
}

#[test]
fn parse_reply_without_usage_is_honest_none() {
    let body = json!({"choices": [{"message": {"content": "ok"}}]}).to_string();
    let (_, usage) = parse_reply(&body).expect("parses");
    assert_eq!(usage, None);
}

#[test]
fn parse_reply_refuses_empty_or_malformed() {
    assert!(parse_reply("not json").is_err());
    assert!(parse_reply(&json!({"choices": []}).to_string()).is_err());
    assert!(parse_reply(&json!({"choices": [{"message": {"content": ""}}]}).to_string()).is_err());
}

// ---------------------------------------------------------------------------
// Settlement
// ---------------------------------------------------------------------------

#[test]
fn settle_charges_reported_usage_up_to_the_reservation() {
    let p = price();
    let c = settle(
        &p,
        10_000,
        Some(Usage {
            prompt_tokens: 100,
            completion_tokens: 100,
        }),
    );
    assert_eq!(c.charged_micros, 1_800);
    assert!(c.usage_reported);
    assert!(!c.exceeded_quote);
}

#[test]
fn settle_never_charges_more_than_the_reservation_and_flags_it() {
    let p = price();
    let c = settle(
        &p,
        100,
        Some(Usage {
            prompt_tokens: 1_000_000,
            completion_tokens: 0,
        }),
    );
    assert_eq!(c.charged_micros, 100);
    assert!(c.exceeded_quote);
}

#[test]
fn settle_without_usage_charges_the_full_reservation() {
    let c = settle(&price(), 777, None);
    assert_eq!(c.charged_micros, 777);
    assert!(!c.usage_reported);
}

// ---------------------------------------------------------------------------
// run() over a scripted transport
// ---------------------------------------------------------------------------

struct Scripted {
    reply: Result<(u16, String), EscalationError>,
    seen: Mutex<Vec<(String, String, Value)>>,
}

impl Transport for Scripted {
    fn post_json(
        &self,
        url: &str,
        bearer: &str,
        body: &Value,
        _timeout: Duration,
    ) -> Result<(u16, String), EscalationError> {
        if let Ok(mut s) = self.seen.lock() {
            s.push((url.to_string(), bearer.to_string(), body.clone()));
        }
        self.reply.clone()
    }
}

#[test]
fn run_posts_to_chat_completions_with_the_key_and_settles() {
    let t = Scripted {
        reply: Ok((
            200,
            json!({"choices": [{"message": {"content": "the plan"}}], "usage": {"prompt_tokens": 10, "completion_tokens": 10}}).to_string(),
        )),
        seen: Mutex::new(vec![]),
    };
    let r = request("https://api.example.com/v1/");
    let out = run(&r, &t, Duration::from_secs(5)).expect("runs");
    assert_eq!(out.content, "the plan");
    assert_eq!(out.escalation_id, "esc-1");
    assert_eq!(out.charged_micros, 180);
    let seen = t.seen.lock().expect("lock");
    assert_eq!(seen[0].0, "https://api.example.com/v1/chat/completions");
    assert_eq!(seen[0].1, KEY);
    let ser = serde_json::to_string(&out).expect("ser");
    assert!(!ser.contains(KEY));
}

#[test]
fn run_refuses_an_invalid_request_before_any_egress() {
    let t = Scripted {
        reply: Ok((200, String::new())),
        seen: Mutex::new(vec![]),
    };
    let mut r = request("https://api.example.com/v1");
    r.reserved_micros = 0;
    let e = run(&r, &t, Duration::from_secs(5)).expect_err("refused");
    assert!(!e.may_have_reached_provider());
    assert!(t.seen.lock().expect("lock").is_empty());
}

#[test]
fn run_maps_provider_errors_without_echoing_the_body() {
    let t = Scripted {
        reply: Ok((401, format!("bad key {KEY}"))),
        seen: Mutex::new(vec![]),
    };
    let e = run(
        &request("https://api.example.com/v1"),
        &t,
        Duration::from_secs(5),
    )
    .expect_err("401");
    assert!(matches!(e, EscalationError::Provider(401)));
    assert!(e.may_have_reached_provider());
    assert!(!e.to_string().contains(KEY));
}

// ---------------------------------------------------------------------------
// HttpTransport against a real loopback server
// ---------------------------------------------------------------------------

/// A one-shot HTTP/1.1 server on 127.0.0.1 that records the request head + body and answers
/// with `status` and `body`.
fn serve_once(status: u16, body: String) -> (String, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let seen = Arc::new(Mutex::new(String::new()));
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut reader = BufReader::new(sock.try_clone().expect("clone"));
            let mut head = String::new();
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
                head.push_str(&line);
                if line == "\r\n" {
                    break;
                }
            }
            let mut buf = vec![0u8; len];
            let _ = reader.read_exact(&mut buf);
            head.push_str(&String::from_utf8_lossy(&buf));
            if let Ok(mut s) = seen2.lock() {
                *s = head;
            }
            let resp = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes());
        }
    });
    (format!("http://127.0.0.1:{}/v1", addr.port()), seen)
}

#[test]
fn http_transport_sends_bearer_and_json_to_a_loopback_endpoint() {
    let (base, seen) = serve_once(
        200,
        json!({"choices": [{"message": {"content": "remote plan"}}], "usage": {"prompt_tokens": 3, "completion_tokens": 4}}).to_string(),
    );
    let out = run(&request(&base), &HttpTransport, Duration::from_secs(10)).expect("runs");
    assert_eq!(out.content, "remote plan");
    assert_eq!(out.charged_micros, 69);
    let head = seen.lock().expect("lock").clone();
    assert!(head.starts_with("POST /v1/chat/completions "), "{head}");
    assert!(
        head.to_ascii_lowercase().contains(&format!(
            "authorization: bearer {}",
            KEY.to_ascii_lowercase()
        )),
        "{head}"
    );
    assert!(head.contains("\"planner-large\""));
}

#[test]
fn http_transport_reports_a_provider_status() {
    let (base, _) = serve_once(429, "{\"error\":\"slow down\"}".into());
    let e = run(&request(&base), &HttpTransport, Duration::from_secs(10)).expect_err("429");
    assert!(matches!(e, EscalationError::Provider(429)));
}

#[test]
fn http_transport_connect_failure_is_coarse() {
    // Bind then drop: nothing listens on this port.
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr").port()
    };
    let e = run(
        &request(&format!("http://127.0.0.1:{port}/v1")),
        &HttpTransport,
        Duration::from_secs(5),
    )
    .expect_err("refused");
    assert!(matches!(e, EscalationError::Transport(_)));
    assert!(!e.to_string().contains("127.0.0.1"));
}

/// A one-shot loopback server that drains the request and answers with `raw` (a full HTTP/1.1
/// response, head and body).
fn serve_raw(raw: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut reader = BufReader::new(sock.try_clone().expect("clone"));
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
                if line == "\r\n" {
                    break;
                }
            }
            let mut buf = vec![0u8; len];
            let _ = reader.read_exact(&mut buf);
            let _ = sock.write_all(&raw);
        }
    });
    format!("http://127.0.0.1:{}/v1", addr.port())
}

#[test]
fn http_transport_refuses_an_answer_larger_than_the_reply_cap() {
    // A valid completion whose text alone is past the cap: it is refused, not buffered whole.
    let big = "x".repeat(citrate_agent_escalation::MAX_REPLY_BYTES + 1);
    let body = json!({"choices": [{"message": {"content": big}}]}).to_string();
    let mut raw = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    raw.extend_from_slice(body.as_bytes());
    let base = serve_raw(raw);
    let e = run(&request(&base), &HttpTransport, Duration::from_secs(10)).expect_err("too large");
    assert!(
        matches!(&e, EscalationError::BadResponse(m) if m.contains("too large")),
        "{e:?}"
    );
    // The request did reach the provider, so core keeps the reservation charged.
    assert!(e.may_have_reached_provider());
}

#[test]
fn http_transport_does_not_follow_a_redirect() {
    // The redirect target would answer with a completion; it must never be contacted.
    let (target, seen) = serve_once(
        200,
        json!({"choices": [{"message": {"content": "redirected"}}]}).to_string(),
    );
    let raw = format!(
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: {target}/chat/completions\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let base = serve_raw(raw);
    let e = run(&request(&base), &HttpTransport, Duration::from_secs(10)).expect_err("307");
    assert!(matches!(e, EscalationError::Provider(307)), "{e:?}");
    assert!(
        seen.lock().expect("lock").is_empty(),
        "the key went to the redirect target"
    );
}

// ---------------------------------------------------------------------------
// Registry route: interface present, shipped disabled
// ---------------------------------------------------------------------------

#[test]
fn registry_route_is_disabled_with_an_honest_status() {
    let reg = DisabledRegistry;
    let s = reg.status();
    assert!(!s.enabled);
    assert!(s.reason.contains("not deployed"), "{}", s.reason);
    assert!(s.missing.iter().any(|m| m.contains("InferenceRouter")));
    assert!(s.missing.iter().any(|m| m.contains("x402")));
    let pay = x402_payment_request(
        "q-1",
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "1000",
        "cid:bafy",
    )
    .expect("well-formed");
    match reg.escalate("bafy", &pay) {
        Err(RegistryError::Disabled(r)) => assert!(r.contains("not deployed")),
        other => panic!("expected Disabled, got {other:?}"),
    }
}

#[test]
fn x402_payment_request_is_structured_never_raw_typed_data() {
    let ok = x402_payment_request(
        "q-1",
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "1000",
        "cid:bafy",
    )
    .expect("ok");
    let v = serde_json::to_value(&ok).expect("ser");
    let mut keys: Vec<_> = v.as_object().expect("obj").keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        ["amount", "asset", "quoteId", "recipient", "resource"]
    );
    assert!(x402_payment_request(
        "q",
        "0x12",
        "0x2222222222222222222222222222222222222222",
        "1",
        "r"
    )
    .is_err());
    assert!(x402_payment_request(
        "q",
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "-1",
        "r"
    )
    .is_err());
    assert!(x402_payment_request(
        "q",
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "0",
        "r"
    )
    .is_err());
    assert!(x402_payment_request(
        "q",
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "1e9",
        "r"
    )
    .is_err());
    assert!(x402_payment_request(
        "",
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "1",
        "r"
    )
    .is_err());
}

/// Cross-repo golden: citrate-core's quote for the same request must equal this worst case
/// (core `escalation_tests.rs::the_quote_matches_the_sidecars_worst_case_golden`), or the sidecar
/// would refuse core's reservation.
#[test]
fn worst_case_golden_shared_with_core() {
    let body = json!({
        "escalationId": "esc-g",
        "baseUrl": "https://api.example.com/v1",
        "model": "m",
        "apiKey": KEY,
        "prompt": "Plan it.",
        "maxTokens": 64,
        "price": {"inputMicrosPerMtok": 1_000_000u64, "outputMicrosPerMtok": 2_000_000u64},
        "reservedMicros": 152u64,
    });
    let r: EscalationRequest = serde_json::from_value(body).expect("parses");
    // (8 bytes + 16) * 1 + 64 * 2 = 152 micros; an absent system prompt is not counted.
    assert_eq!(r.worst_case_micros(), Some(152));
    assert!(r.validate().is_ok());
    let mut with_empty_system = r;
    with_empty_system.system = Some(String::new());
    assert_eq!(with_empty_system.worst_case_micros(), Some(152));
}
