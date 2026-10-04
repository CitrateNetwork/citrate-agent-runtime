//! HUP-S1.5 (runtime half): the registry route. A signed x402 payment from core is carried as the
//! `X-PAYMENT` header of one chat completion to the provider the router named; the provider's
//! `X-PAYMENT-RESPONSE` receipt comes back with the answer. Real loopback HTTP servers throughout;
//! the last test settles on a local anvil chain (ignored unless the e2e script runs it).

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use citrate_agent_escalation::{
    parse_payment_required, parse_payment_response, registry_route_status, run_registry,
    EscalationError, HttpTransport, RegistryEscalationRequest, SignedPayment, SETTLE_MARGIN_SECS,
    X402_SCHEME, X402_VERSION,
};
use serde_json::{json, Value};

const NOW: u64 = 1_790_000_000;

fn b64(v: &Value) -> String {
    base64::engine::general_purpose::STANDARD.encode(v.to_string())
}

fn payment() -> SignedPayment {
    SignedPayment {
        network: "eip155:40204".into(),
        asset: "0xaa918302b94a4b0e75e01e019cc6b819b4f7c906".into(),
        from: "0x9858effd232b4033e47d90003d41ec34ecaeda94".into(),
        to: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8".into(),
        value: "10000000000000000".into(),
        valid_after: NOW - 60,
        valid_before: NOW + 600,
        nonce: format!("0x{}", "01".repeat(32)),
        signature: format!("0x{}1c", "ab".repeat(64)),
    }
}

fn request(base_url: &str) -> RegistryEscalationRequest {
    RegistryEscalationRequest {
        escalation_id: "esc-reg-1".into(),
        base_url: base_url.into(),
        model: format!("0x{}", "cd".repeat(32)),
        system: Some("You are a careful planner.".into()),
        prompt: "Plan the steps to add a mint page.".into(),
        max_tokens: 256,
        payment: payment(),
    }
}

/// What a loopback provider saw.
#[derive(Default, Debug)]
struct Seen {
    headers: BTreeMap<String, String>,
    body: String,
    hits: usize,
}

/// A one-shot loopback provider answering `status`, `body` and optional extra header lines.
fn provider(status: u16, body: String, extra: Option<String>) -> (String, Arc<Mutex<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let s2 = seen.clone();
    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut reader = BufReader::new(sock.try_clone().expect("clone"));
            let mut len = 0usize;
            let mut headers = BTreeMap::new();
            let mut first = true;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if first {
                    first = false;
                    continue;
                }
                if let Some((k, v)) = line.split_once(':') {
                    let k = k.trim().to_ascii_lowercase();
                    if k == "content-length" {
                        len = v.trim().parse().unwrap_or(0);
                    }
                    headers.insert(k, v.trim().to_string());
                }
            }
            let mut buf = vec![0u8; len];
            let _ = reader.read_exact(&mut buf);
            {
                let mut g = s2.lock().expect("lock");
                g.headers = headers;
                g.body = String::from_utf8_lossy(&buf).into_owned();
                g.hits += 1;
            }
            let extra = extra.unwrap_or_default();
            let resp = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes());
        }
    });
    (format!("http://127.0.0.1:{port}/v1"), seen)
}

fn completion() -> String {
    json!({
        "choices": [{"message": {"role": "assistant", "content": "1. Render the template. 2. Verify."}}],
        "usage": {"prompt_tokens": 40, "completion_tokens": 12}
    })
    .to_string()
}

fn receipt_header(tx: &str) -> String {
    format!(
        "X-PAYMENT-RESPONSE: {}\r\n",
        b64(&json!({"success": true, "transaction": tx, "network": "eip155:40204",
            "payer": "0x9858effd232b4033e47d90003d41ec34ecaeda94"}))
    )
}

#[test]
fn the_sidecar_half_reports_what_it_carries_and_leaves_the_decision_to_core() {
    let s = registry_route_status();
    assert!(s.enabled);
    assert!(s.transport.contains("x402 v1 exact"), "{}", s.transport);
    assert!(s.reason.contains("Citrate Core"), "{}", s.reason);
    assert!(s.missing.is_empty());
}

#[test]
fn a_well_formed_payment_validates() {
    assert_eq!(payment().validate(NOW, SETTLE_MARGIN_SECS), Ok(()));
}

#[test]
fn malformed_payments_are_refused_before_anything_is_sent() {
    let cases: Vec<(&str, Box<dyn Fn(&mut SignedPayment)>)> = vec![
        ("network", Box::new(|p| p.network = "base-sepolia".into())),
        ("network digits", Box::new(|p| p.network = "eip155:x".into())),
        ("asset", Box::new(|p| p.asset = "0x12".into())),
        ("payer", Box::new(|p| p.from = "nope".into())),
        ("payee", Box::new(|p| p.to = format!("0x{}", "zz".repeat(20)))),
        ("zero amount", Box::new(|p| p.value = "0".into())),
        ("decimal amount", Box::new(|p| p.value = "1.5".into())),
        ("nonce", Box::new(|p| p.nonce = "0x01".into())),
        ("signature", Box::new(|p| p.signature = format!("0x{}", "ab".repeat(64)))),
        ("window", Box::new(|p| p.valid_after = p.valid_before)),
        ("expired", Box::new(|p| p.valid_before = NOW)),
        ("about to expire", Box::new(|p| p.valid_before = NOW + SETTLE_MARGIN_SECS)),
    ];
    for (name, mutate) in cases {
        let mut p = payment();
        mutate(&mut p);
        assert!(p.validate(NOW, SETTLE_MARGIN_SECS).is_err(), "{name} accepted");
    }
}

#[test]
fn the_payment_header_is_the_x402_v1_exact_payload() {
    let p = payment();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(p.header_value())
        .expect("base64");
    let v: Value = serde_json::from_slice(&raw).expect("json");
    assert_eq!(v["x402Version"], X402_VERSION);
    assert_eq!(v["scheme"], X402_SCHEME);
    assert_eq!(v["network"], "eip155:40204");
    assert_eq!(v["payload"]["signature"], p.signature);
    let a = &v["payload"]["authorization"];
    assert_eq!(a["from"], p.from);
    assert_eq!(a["to"], p.to);
    assert_eq!(a["value"], p.value);
    assert_eq!(a["validAfter"], (NOW - 60).to_string());
    assert_eq!(a["validBefore"], (NOW + 600).to_string());
    assert_eq!(a["nonce"], p.nonce);
}

#[test]
fn receipts_are_parsed_and_junk_fields_dropped() {
    let tx = format!("0x{}", "12".repeat(32));
    let r = parse_payment_response(&b64(&json!({"success": true, "transaction": tx,
        "network": "eip155:40204", "payer": "0x9858EFFD232B4033E47D90003D41EC34ECAEDA94"})))
    .expect("receipt");
    assert!(r.success);
    assert_eq!(r.transaction.as_deref(), Some(tx.as_str()));
    assert_eq!(r.payer.as_deref(), Some("0x9858effd232b4033e47d90003d41ec34ecaeda94"));
    let junk = parse_payment_response(&b64(&json!({"success": false, "transaction": "0xnope",
        "payer": "<script>"})))
    .expect("receipt");
    assert!(!junk.success);
    assert_eq!(junk.transaction, None);
    assert_eq!(junk.payer, None);
    assert_eq!(parse_payment_response("%%%not-base64"), None);
    assert_eq!(parse_payment_response(&b64(&json!({"transaction": tx}))), None);
    assert_eq!(parse_payment_response(&"A".repeat(5000)), None);
}

#[test]
fn a_402_body_says_what_the_provider_wanted() {
    let body = json!({"x402Version": 1, "error": "X-PAYMENT header is required", "accepts": [{
        "scheme": "exact", "network": "eip155:40204", "maxAmountRequired": "20000000000000000",
        "payTo": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
        "asset": "0xaa918302b94a4b0e75e01e019cc6b819b4f7c906"}]})
    .to_string();
    let p = parse_payment_required(&body).expect("402");
    assert_eq!(p.max_amount_required.as_deref(), Some("20000000000000000"));
    assert_eq!(p.network.as_deref(), Some("eip155:40204"));
    assert_eq!(parse_payment_required("{}"), None);
}

#[test]
fn a_paid_request_carries_the_payment_and_returns_the_answer_and_receipt() {
    let tx = format!("0x{}", "34".repeat(32));
    let (base, seen) = provider(200, completion(), Some(receipt_header(&tx)));
    let req = request(&base);
    let out = run_registry(&req, &HttpTransport, Duration::from_secs(10), NOW).expect("ok");
    assert_eq!(out.escalation_id, "esc-reg-1");
    assert!(out.content.contains("Render the template"));
    assert_eq!(out.charged_base_units, "10000000000000000");
    assert_eq!(out.payee, req.payment.to);
    assert_eq!(out.network, "eip155:40204");
    let receipt = out.receipt.expect("receipt");
    assert!(receipt.success);
    assert_eq!(receipt.transaction.as_deref(), Some(tx.as_str()));
    let g = seen.lock().expect("lock");
    assert_eq!(g.hits, 1);
    assert_eq!(
        g.headers.get("x-payment").map(String::as_str),
        Some(req.payment.header_value().as_str())
    );
    assert!(!g.headers.contains_key("authorization"), "no bearer on the paid route");
    let body: Value = serde_json::from_str(&g.body).expect("body");
    assert_eq!(body["model"], req.model);
    assert_eq!(body["max_tokens"], 256);
    assert_eq!(body["messages"][1]["content"], req.prompt);
}

#[test]
fn a_paid_answer_without_a_receipt_still_returns_with_no_receipt() {
    let (base, _seen) = provider(200, completion(), None);
    let out = run_registry(&request(&base), &HttpTransport, Duration::from_secs(10), NOW)
        .expect("ok");
    assert_eq!(out.receipt, None);
}

#[test]
fn a_402_is_a_refused_payment_that_may_have_reached_the_provider() {
    let body = json!({"x402Version": 1, "accepts": [{"maxAmountRequired": "20000000000000000",
        "payTo": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"}]})
    .to_string();
    let (base, _seen) = provider(402, body, None);
    let e = run_registry(&request(&base), &HttpTransport, Duration::from_secs(10), NOW)
        .expect_err("402");
    assert!(e.may_have_reached_provider());
    match e {
        EscalationError::BadResponse(m) => {
            assert!(m.contains("refused the payment"), "{m}");
            assert!(m.contains("20000000000000000"), "{m}");
        }
        other => panic!("expected BadResponse, got {other:?}"),
    }
}

#[test]
fn an_expired_payment_is_refused_and_nothing_is_sent() {
    let (base, seen) = provider(200, completion(), None);
    let mut req = request(&base);
    req.payment.valid_before = NOW + 1;
    let e = run_registry(&req, &HttpTransport, Duration::from_secs(10), NOW).expect_err("expired");
    assert!(!e.may_have_reached_provider());
    assert_eq!(seen.lock().expect("lock").hits, 0);
}

#[test]
fn a_provider_error_is_reported_with_its_status() {
    let (base, _seen) = provider(500, "{}".into(), None);
    let e = run_registry(&request(&base), &HttpTransport, Duration::from_secs(10), NOW)
        .expect_err("500");
    assert!(matches!(e, EscalationError::Provider(500)), "{e:?}");
}

#[test]
fn a_redirect_is_not_followed_so_the_payment_cannot_be_forwarded() {
    let (target, seen) = provider(200, completion(), None);
    let raw = format!("Location: {target}/chat/completions\r\n");
    let (base, _first) = provider(307, String::new(), Some(raw));
    let e = run_registry(&request(&base), &HttpTransport, Duration::from_secs(10), NOW)
        .expect_err("307");
    assert!(matches!(e, EscalationError::Provider(307)), "{e:?}");
    assert_eq!(seen.lock().expect("lock").hits, 0, "payment reached the redirect target");
}

#[test]
fn bad_request_fields_are_refused() {
    let mut r = request("https://provider.example/v1");
    r.base_url = "http://provider.example/v1".into();
    assert!(r.validate(NOW).is_err(), "plain http off loopback");
    let mut r = request("https://provider.example/v1");
    r.max_tokens = 0;
    assert!(r.validate(NOW).is_err());
    let mut r = request("https://provider.example/v1");
    r.prompt = " ".into();
    assert!(r.validate(NOW).is_err());
    let mut r = request("https://provider.example/v1");
    r.escalation_id = "bad id".into();
    assert!(r.validate(NOW).is_err());
    assert!(request("https://provider.example/v1").validate(NOW).is_ok());
}

// ---------------------------------------------------------------------------
// Local chain end to end (citrate-core scripts/escalation-registry-anvil-e2e.sh runs this)
// ---------------------------------------------------------------------------

fn rpc(url: &str, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let v: Value = reqwest::blocking::Client::new()
        .post(url)
        .json(&body)
        .send()
        .expect("rpc send")
        .json()
        .expect("rpc json");
    assert!(v.get("error").is_none(), "{method}: {v}");
    v["result"].clone()
}

fn word(hex_no_prefix: &str) -> String {
    format!("{:0>64}", hex_no_prefix)
}

fn word_u64(n: u64) -> String {
    format!("{n:064x}")
}

fn word_dec(dec: &str) -> String {
    format!("{:064x}", dec.parse::<u128>().expect("u128 amount"))
}

/// The provider half of the e2e: settle the authorization on chain (as the payee, an unlocked anvil
/// account), then answer with the receipt.
fn settling_provider(port: u16, rpc_url: String, asset: String, payee: String) {
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind provider port");
    std::thread::spawn(move || {
        let Ok((mut sock, _)) = listener.accept() else {
            return;
        };
        let mut reader = BufReader::new(sock.try_clone().expect("clone"));
        let mut len = 0usize;
        let mut pay = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                match k.trim().to_ascii_lowercase().as_str() {
                    "content-length" => len = v.trim().parse().unwrap_or(0),
                    "x-payment" => pay = v.trim().to_string(),
                    _ => {}
                }
            }
        }
        let mut buf = vec![0u8; len];
        let _ = reader.read_exact(&mut buf);
        let raw = base64::engine::general_purpose::STANDARD
            .decode(pay)
            .expect("x-payment base64");
        let p: Value = serde_json::from_slice(&raw).expect("x-payment json");
        let a = &p["payload"]["authorization"];
        let sig = p["payload"]["signature"].as_str().expect("sig");
        let sig = sig.trim_start_matches("0x");
        let s = |k: &str| a[k].as_str().expect("field").trim_start_matches("0x").to_string();
        let data = format!(
            "0xe3ee160e{}{}{}{}{}{}{}{}{}",
            word(&s("from")),
            word(&s("to")),
            word_dec(&s("value")),
            word_u64(s("validAfter").parse().expect("va")),
            word_u64(s("validBefore").parse().expect("vb")),
            s("nonce"),
            word(&sig[128..130]),
            &sig[0..64],
            &sig[64..128],
        );
        let tx = rpc(
            &rpc_url,
            "eth_sendTransaction",
            json!([{"from": payee, "to": asset, "data": data, "gas": "0x30000"}]),
        );
        let tx = tx.as_str().expect("tx hash").to_string();
        // Poll: a node may answer the send before the receipt is queryable.
        let mut ok = false;
        for _ in 0..50 {
            let receipt = rpc(&rpc_url, "eth_getTransactionReceipt", json!([tx]));
            if !receipt.is_null() {
                ok = receipt["status"] == "0x1";
                if !ok {
                    eprintln!("settlement reverted: {receipt}");
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let body = completion();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            if ok { receipt_header(&tx) } else { String::new() },
            body.len()
        );
        let _ = sock.write_all(resp.as_bytes());
    });
}

#[test]
#[ignore = "needs a local anvil chain: run citrate-core scripts/escalation-registry-anvil-e2e.sh"]
fn anvil_e2e_registry_payment_settles_on_chain() {
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} is not set"));
    let rpc_url = env("CITRATE_X402_E2E_RPC");
    let body = std::fs::read_to_string(env("CITRATE_X402_E2E_REQUEST")).expect("request file");
    let req: RegistryEscalationRequest = serde_json::from_str(&body).expect("request json");
    // The endpoint came from the router; serve it on exactly that port.
    let port: u16 = req
        .base_url
        .trim_start_matches("http://127.0.0.1:")
        .split('/')
        .next()
        .and_then(|p| p.parse().ok())
        .expect("loopback provider port from the router");
    let asset = req.payment.asset.clone();
    let payee = req.payment.to.clone();
    let balance = |who: &str| {
        let r = rpc(
            &rpc_url,
            "eth_call",
            json!([{"to": asset, "data": format!("0x70a08231{}", word(who.trim_start_matches("0x")))}, "latest"]),
        );
        u128::from_str_radix(r.as_str().expect("hex").trim_start_matches("0x"), 16).expect("u128")
    };
    let before = balance(&payee);
    settling_provider(port, rpc_url.clone(), asset.clone(), payee.clone());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let out = run_registry(&req, &HttpTransport, Duration::from_secs(60), now).expect("paid run");
    let receipt = out.receipt.clone().expect("the provider settled and sent a receipt");
    assert!(receipt.success);
    let after = balance(&payee);
    let value: u128 = req.payment.value.parse().expect("value");
    assert_eq!(after - before, value, "the payee received exactly the authorized value");
    let state = rpc(
        &rpc_url,
        "eth_call",
        json!([{"to": asset, "data": format!("0xe94a0102{}{}",
            word(req.payment.from.trim_start_matches("0x")),
            req.payment.nonce.trim_start_matches("0x"))}, "latest"]),
    );
    assert!(state.as_str().expect("hex").ends_with('1'), "authorization consumed on chain");
    if let Ok(out_path) = std::env::var("CITRATE_X402_E2E_OUTCOME") {
        std::fs::write(out_path, serde_json::to_string(&out).expect("outcome json"))
            .expect("write outcome");
    }
}
