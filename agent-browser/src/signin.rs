//! HUP-S2.3: the sign-in bridge in the managed browser (Sign-In with Ethereum, EIP-4361).
//!
//! A dApp asks a wallet for an address (`eth_requestAccounts`) and then for a `personal_sign`
//! over a sign-in message. In the **managed** browser only, this module gives the page's top frame
//! a minimal EIP-1193 provider (also announced through EIP-6963) whose two wallet methods do not
//! answer anything themselves: each becomes a [`SignInRequest`] that waits here for citrate-core.
//! Core reads the request over the sidecar's bearer-authed control route, checks the page origin
//! with its own read of this browser's DevTools endpoint, and decides through its signature
//! ceremony (a budget the member granted, or the member's own approval card). Core then hands back
//! the answer, which is delivered only to the page context that asked.
//!
//! What this module never does: hold or see a key, sign, decide, or choose what is signed. It
//! carries text one way and an answer the other way.
//!
//! Provenance the sidecar contributes, from Chrome's own events (never from the page): the
//! execution context that called the binding, that context's frame, whether that frame is the
//! tab's top frame, and the context's origin. A request from an embedded frame is still passed on,
//! marked `topFrame: false`; core never budgets it (ADR D2 #2) and shows it as an approval card.
//!
//! Attached mode (the member's own Chrome) gets no provider at all (ADR D2 #3).

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Value};

use crate::cdp::{CdpEvent, Reply};

/// The CDP binding the provider calls. Removed from the page's global scope by the provider
/// script before any page script runs, so pages reach it only through the provider.
pub const BINDING: &str = "__citrateHermesSignIn";
/// The function core's answer is delivered through (defined by the provider script).
pub const RESOLVER: &str = "__citrateHermesSignInResolve";
/// Citrate mainnet, 40204.
pub const CHAIN_ID: u64 = 40204;
pub const CHAIN_ID_HEX: &str = "0x9d0c";
/// At most this many requests wait for core at once; more are refused at once.
pub const MAX_PENDING: usize = 4;
/// Longest message accepted for a `personal_sign` (core budgets at most 2048 bytes; a longer one
/// can still be shown on an approval card).
pub const MAX_MESSAGE_BYTES: usize = 4096;
/// A request core has not answered within this time is refused to the page.
pub const REQUEST_TTL: Duration = Duration::from_secs(120);
/// Longest binding payload read.
const MAX_PAYLOAD_BYTES: usize = 16 * 1024;

/// EIP-1193 error codes used here.
pub const CODE_USER_REJECTED: i64 = 4001;
pub const CODE_UNAUTHORIZED: i64 = 4100;
pub const CODE_UNSUPPORTED: i64 = 4200;

/// The provider script (runs in every frame before page scripts; installs only in the top frame).
pub fn provider_script() -> String {
    format!(
        r#"(() => {{
  const B = "{BINDING}";
  const bind = window[B];
  try {{ delete window[B]; }} catch (_) {{}}
  if (window.top !== window || typeof bind !== "function") return;
  const CHAIN = "{CHAIN_ID_HEX}";
  const waiting = new Map();
  let next = 1;
  let accounts = [];
  const listeners = {{}};
  const fail = (code, message) => Object.assign(new Error(message), {{ code }});
  const emit = (ev, v) => (listeners[ev] || []).slice().forEach((f) => {{ try {{ f(v); }} catch (_) {{}} }});
  Object.defineProperty(window, "{RESOLVER}", {{
    value: (id, ok, value) => {{
      const w = waiting.get(id);
      if (!w) return;
      waiting.delete(id);
      if (ok) {{
        if (w.method === "eth_requestAccounts" && Array.isArray(value)) {{
          accounts = value.slice();
          emit("connect", {{ chainId: CHAIN }});
          emit("accountsChanged", accounts.slice());
        }}
        w.resolve(value);
      }} else {{
        w.reject(fail((value && value.code) || 4001, (value && value.message) || "The request was declined"));
      }}
    }},
    configurable: false,
    writable: false,
  }});
  const ask = (method, params) => new Promise((resolve, reject) => {{
    const id = next++;
    waiting.set(id, {{ method, resolve, reject }});
    try {{
      bind(JSON.stringify({{ id, method, params: Array.isArray(params) ? params : [] }}));
    }} catch (_) {{
      waiting.delete(id);
      reject(fail(4900, "Hermes's sign-in bridge is not available"));
    }}
  }});
  const request = (args) => {{
    const method = args && args.method;
    const params = args && args.params;
    switch (method) {{
      case "eth_chainId": return Promise.resolve(CHAIN);
      case "net_version": return Promise.resolve("{CHAIN_ID}");
      case "eth_accounts": return Promise.resolve(accounts.slice());
      case "wallet_switchEthereumChain": {{
        const c = params && params[0] && String(params[0].chainId).toLowerCase();
        return c === CHAIN ? Promise.resolve(null) : Promise.reject(fail(4902, "Hermes signs in on Citrate (chain 40204) only"));
      }}
      case "eth_requestAccounts":
      case "personal_sign":
        return ask(method, params);
      default:
        return Promise.reject(fail(4200, "Hermes's browser can share an address and sign in, nothing else (" + String(method) + " is not supported)"));
    }}
  }};
  const provider = {{
    isCitrateHermes: true,
    request,
    enable: () => request({{ method: "eth_requestAccounts" }}),
    on: (e, f) => {{ (listeners[e] = listeners[e] || []).push(f); return provider; }},
    removeListener: (e, f) => {{ listeners[e] = (listeners[e] || []).filter((g) => g !== f); return provider; }},
  }};
  Object.freeze(provider);
  if (!("ethereum" in window)) {{
    try {{ Object.defineProperty(window, "ethereum", {{ value: provider, configurable: true }}); }} catch (_) {{}}
  }}
  const uuid = (window.crypto && window.crypto.randomUUID) ? window.crypto.randomUUID() : "00000000-0000-4000-8000-000000000000";
  const info = Object.freeze({{
    uuid,
    name: "Citrate (Hermes)",
    icon: "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PGNpcmNsZSBjeD0iMTYiIGN5PSIxNiIgcj0iMTQiIGZpbGw9IiNmNWExMWQiLz48L3N2Zz4=",
    rdns: "ai.citrate.hermes",
  }});
  const announce = () => window.dispatchEvent(new CustomEvent("eip6963:announceProvider", {{ detail: Object.freeze({{ info, provider }}) }}));
  window.addEventListener("eip6963:requestProvider", announce);
  announce();
}})();"#
    )
}

/// What the page asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignInKind {
    /// `eth_requestAccounts`: share the member's address with this site.
    Accounts,
    /// `personal_sign` over a message (a Sign-In with Ethereum message, or anything else, which
    /// core then shows as an ordinary approval card).
    PersonalSign,
}

/// One request waiting for core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInRequest {
    pub id: String,
    pub kind: SignInKind,
    /// The origin of the execution context that asked, as Chrome reported it when the context was
    /// created (not anything the page said).
    pub raise_origin: String,
    /// Whether that context is the default context of the tab's top frame.
    pub top_frame: bool,
    /// The exact bytes to sign, hex (`personal_sign` only).
    pub message_hex: Option<String>,
    /// The address the page named (`personal_sign` only), when it was a well-formed address.
    pub address: Option<String>,
    pub created_ms: u64,
}

/// Core's answer for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignInAnswer {
    /// `eth_requestAccounts`: these addresses (exactly one).
    Accounts(Vec<String>),
    /// `personal_sign`: the 65-byte signature, `0x` + 130 hex.
    Signature(String),
    /// Declined, with an EIP-1193 code and a message for the page.
    Refused { code: i64, message: String },
}

#[derive(Debug, Clone)]
struct Ctx {
    frame_id: String,
    origin: String,
    is_default: bool,
}

#[derive(Debug, Clone)]
struct Waiting {
    req: SignInRequest,
    context_id: i64,
    page_id: u64,
    at: Instant,
}

#[derive(Default)]
struct Inner {
    contexts: HashMap<i64, Ctx>,
    waiting: Vec<Waiting>,
    next: u64,
    read_origins: BTreeSet<String>,
}

/// Where an answer goes: the page context and the page's own request number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delivery {
    pub context_id: i64,
    pub page_id: u64,
}

/// The bridge state for one browser connection.
#[derive(Default)]
pub struct SignInBridge {
    inner: Mutex<Inner>,
}

fn lock(m: &Mutex<Inner>) -> std::sync::MutexGuard<'_, Inner> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `0x` + 40 hex.
pub fn is_address(s: &str) -> bool {
    s.len() == 42 && s.starts_with("0x") && s.as_bytes()[2..].iter().all(|b| b.is_ascii_hexdigit())
}

/// `0x` + 130 hex (r, s, v).
pub fn is_signature(s: &str) -> bool {
    s.len() == 132 && s.starts_with("0x") && s.as_bytes()[2..].iter().all(|b| b.is_ascii_hexdigit())
}

/// The bytes a `personal_sign` data parameter names: `0x`-hex is decoded, anything else is the
/// UTF-8 text itself (wallets accept both).
pub fn message_bytes(data: &str) -> Vec<u8> {
    if let Some(h) = data.strip_prefix("0x") {
        if h.len().is_multiple_of(2) && h.bytes().all(|b| b.is_ascii_hexdigit()) {
            let mut out = Vec::with_capacity(h.len() / 2);
            let raw = h.as_bytes();
            let mut i = 0;
            while i + 1 < raw.len() {
                let hi = (raw[i] as char).to_digit(16);
                let lo = (raw[i + 1] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                }
                i += 2;
            }
            return out;
        }
    }
    data.as_bytes().to_vec()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `personal_sign` params are `[data, address]`; some dApps send `[address, data]`.
fn split_personal_sign(params: &[Value]) -> Option<(String, Option<String>)> {
    let a = params.first()?.as_str()?;
    let b = params.get(1).and_then(|v| v.as_str());
    match b {
        Some(b) if is_address(a) && !is_address(b) => Some((b.to_string(), Some(a.to_string()))),
        Some(b) => Some((a.to_string(), is_address(b).then(|| b.to_string()))),
        None => Some((a.to_string(), None)),
    }
}

/// The JavaScript that delivers `answer` for `page_id` (evaluated in the asking context only).
pub fn delivery_expression(page_id: u64, answer: &SignInAnswer) -> String {
    let (ok, value) = match answer {
        SignInAnswer::Accounts(a) => (true, json!(a)),
        SignInAnswer::Signature(s) => (true, json!(s)),
        SignInAnswer::Refused { code, message } => {
            (false, json!({"code": code, "message": message}))
        }
    };
    // JSON is a JavaScript literal; nothing the page sent is interpolated here.
    format!("window.{RESOLVER}({page_id}, {ok}, {value})")
}

fn refusal_reply(session: Option<String>, context_id: i64, page_id: u64, msg: &str) -> Reply {
    Reply {
        method: "Runtime.evaluate".to_string(),
        params: json!({
            "expression": delivery_expression(page_id, &SignInAnswer::Refused { code: CODE_USER_REJECTED, message: msg.to_string() }),
            "contextId": context_id,
        }),
        session_id: session,
    }
}

impl SignInBridge {
    /// Handle one CDP event of the worker's own tab session. `top_frame` is the tab's main frame
    /// id (the target id). Returns an immediate reply for a request refused on arrival.
    pub fn on_event(&self, ev: &CdpEvent, top_frame: Option<&str>) -> Option<Reply> {
        match ev.method.as_str() {
            "Runtime.executionContextCreated" => {
                let c = &ev.params["context"];
                let (Some(id), Some(frame)) = (c["id"].as_i64(), c["auxData"]["frameId"].as_str())
                else {
                    return None;
                };
                lock(&self.inner).contexts.insert(
                    id,
                    Ctx {
                        frame_id: frame.to_string(),
                        origin: c["origin"].as_str().unwrap_or("").to_string(),
                        is_default: c["auxData"]["isDefault"].as_bool().unwrap_or(false),
                    },
                );
                None
            }
            "Runtime.executionContextDestroyed" => {
                if let Some(id) = ev.params["executionContextId"].as_i64() {
                    let mut g = lock(&self.inner);
                    g.contexts.remove(&id);
                    // The page that asked is gone: nobody can receive an answer any more.
                    g.waiting.retain(|w| w.context_id != id);
                }
                None
            }
            "Runtime.executionContextsCleared" => {
                let mut g = lock(&self.inner);
                g.contexts.clear();
                g.waiting.clear();
                None
            }
            "Runtime.bindingCalled" if ev.params["name"].as_str() == Some(BINDING) => {
                self.on_binding(ev, top_frame)
            }
            _ => None,
        }
    }

    fn on_binding(&self, ev: &CdpEvent, top_frame: Option<&str>) -> Option<Reply> {
        let context_id = ev.params["executionContextId"].as_i64()?;
        let payload = ev.params["payload"].as_str()?;
        if payload.len() > MAX_PAYLOAD_BYTES {
            return None;
        }
        let v: Value = serde_json::from_str(payload).ok()?;
        let page_id = v["id"].as_u64().filter(|n| *n > 0 && *n < (1u64 << 53))?;
        let session = ev.session_id.clone();
        let kind = match v["method"].as_str() {
            Some("eth_requestAccounts") => SignInKind::Accounts,
            Some("personal_sign") => SignInKind::PersonalSign,
            _ => {
                return Some(refusal_reply(
                    session,
                    context_id,
                    page_id,
                    "this request is not supported",
                ))
            }
        };
        let params: Vec<Value> = v["params"].as_array().cloned().unwrap_or_default();
        let (message_hex, address) = match kind {
            SignInKind::Accounts => (None, None),
            SignInKind::PersonalSign => {
                let Some((data, addr)) = split_personal_sign(&params) else {
                    return Some(refusal_reply(
                        session,
                        context_id,
                        page_id,
                        "personal_sign needs a message",
                    ));
                };
                let bytes = message_bytes(&data);
                if bytes.is_empty() || bytes.len() > MAX_MESSAGE_BYTES {
                    return Some(refusal_reply(
                        session,
                        context_id,
                        page_id,
                        "the message is empty or too long",
                    ));
                }
                (Some(to_hex(&bytes)), addr)
            }
        };
        let mut g = lock(&self.inner);
        let Some(ctx) = g.contexts.get(&context_id).cloned() else {
            return Some(refusal_reply(
                session,
                context_id,
                page_id,
                "the page that asked could not be identified",
            ));
        };
        if g.waiting.len() >= MAX_PENDING {
            drop(g);
            return Some(refusal_reply(
                session,
                context_id,
                page_id,
                "too many requests are already waiting",
            ));
        }
        g.next += 1;
        let id = format!("signin-{}-{}", g.next, now_ms() % 1_000_000_000);
        let top = ctx.is_default && top_frame.is_some_and(|t| t == ctx.frame_id);
        g.waiting.push(Waiting {
            req: SignInRequest {
                id,
                kind,
                raise_origin: ctx.origin,
                top_frame: top,
                message_hex,
                address,
                created_ms: now_ms(),
            },
            context_id,
            page_id,
            at: Instant::now(),
        });
        None
    }

    /// Requests still waiting, oldest first. Expired ones are removed and returned separately so
    /// the caller can refuse them to the page.
    pub fn pending(&self) -> (Vec<SignInRequest>, Vec<Delivery>) {
        let mut g = lock(&self.inner);
        let (live, expired): (Vec<Waiting>, Vec<Waiting>) = g
            .waiting
            .drain(..)
            .partition(|w| w.at.elapsed() < REQUEST_TTL);
        g.waiting = live;
        (
            g.waiting.iter().map(|w| w.req.clone()).collect(),
            expired
                .into_iter()
                .map(|w| Delivery {
                    context_id: w.context_id,
                    page_id: w.page_id,
                })
                .collect(),
        )
    }

    /// Take one request for delivery, checking the answer fits what was asked.
    pub fn take(&self, id: &str, answer: &SignInAnswer) -> Result<Delivery, String> {
        let mut g = lock(&self.inner);
        let pos = g
            .waiting
            .iter()
            .position(|w| w.req.id == id)
            .ok_or_else(|| "no sign-in request with that id is waiting".to_string())?;
        let kind = g.waiting[pos].req.kind;
        match (kind, answer) {
            (SignInKind::Accounts, SignInAnswer::Accounts(a))
                if a.len() == 1 && a.iter().all(|x| is_address(x)) => {}
            (SignInKind::PersonalSign, SignInAnswer::Signature(s)) if is_signature(s) => {}
            (_, SignInAnswer::Refused { code, message })
                if (1000..=4999).contains(code) && message.len() <= 300 => {}
            _ => return Err("that answer does not fit the request".to_string()),
        }
        let w = g.waiting.remove(pos);
        Ok(Delivery {
            context_id: w.context_id,
            page_id: w.page_id,
        })
    }

    /// Remember that content from `url`'s origin reached the model (HUP-S2.7 / ADR D2 #19).
    pub fn note_read(&self, url: &str) {
        if let Some(o) = origin_of(url) {
            lock(&self.inner).read_origins.insert(o);
        }
    }

    /// Origins whose page content has reached the model since the browser started.
    pub fn read_origins(&self) -> Vec<String> {
        lock(&self.inner).read_origins.iter().cloned().collect()
    }

    /// Forget everything (the browser was torn down).
    pub fn clear(&self) {
        let mut g = lock(&self.inner);
        g.contexts.clear();
        g.waiting.clear();
        g.read_origins.clear();
    }
}

/// `scheme://host[:port]` of an http(s) URL; `None` for anything else (about:blank and the like).
pub fn origin_of(url: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    if !matches!(u.scheme(), "http" | "https") {
        return None;
    }
    let o = u.origin();
    o.is_tuple().then(|| o.ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(method: &str, params: Value) -> CdpEvent {
        CdpEvent {
            method: method.to_string(),
            params,
            session_id: Some("S".to_string()),
        }
    }

    fn ctx(id: i64, frame: &str, origin: &str, default: bool) -> CdpEvent {
        ev(
            "Runtime.executionContextCreated",
            json!({"context": {"id": id, "origin": origin, "name": "", "auxData": {"isDefault": default, "type": "default", "frameId": frame}}}),
        )
    }

    fn call(ctx: i64, payload: Value) -> CdpEvent {
        ev(
            "Runtime.bindingCalled",
            json!({"name": BINDING, "payload": payload.to_string(), "executionContextId": ctx}),
        )
    }

    const SIWE: &str = "app.example.org wants you to sign in with your Ethereum account:\n0x0000000000000000000000000000000000000001\n\nURI: https://app.example.org\nVersion: 1\nChain ID: 40204\nNonce: abcdefgh12345678\nIssued At: 2026-10-01T00:00:00Z";

    #[test]
    fn a_top_frame_sign_in_is_queued_with_chromes_origin_not_the_pages() {
        let b = SignInBridge::default();
        b.on_event(&ctx(7, "T1", "https://app.example.org", true), Some("T1"));
        let hex = format!("0x{}", to_hex(SIWE.as_bytes()));
        let r = b.on_event(
            &call(
                7,
                json!({"id": 1, "method": "personal_sign", "params": [hex, "0x0000000000000000000000000000000000000001"]}),
            ),
            Some("T1"),
        );
        assert!(r.is_none(), "queued, not answered");
        let (p, expired) = b.pending();
        assert!(expired.is_empty());
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].kind, SignInKind::PersonalSign);
        assert_eq!(p[0].raise_origin, "https://app.example.org");
        assert!(p[0].top_frame);
        assert_eq!(
            p[0].message_hex.as_deref(),
            Some(to_hex(SIWE.as_bytes()).as_str())
        );
        assert_eq!(
            p[0].address.as_deref(),
            Some("0x0000000000000000000000000000000000000001")
        );
    }

    #[test]
    fn an_embedded_frame_or_isolated_world_is_never_marked_top() {
        let b = SignInBridge::default();
        b.on_event(
            &ctx(3, "CHILD", "https://ads.example.net", true),
            Some("T1"),
        );
        b.on_event(&ctx(4, "T1", "https://app.example.org", false), Some("T1"));
        b.on_event(
            &call(3, json!({"id": 1, "method": "eth_requestAccounts"})),
            Some("T1"),
        );
        b.on_event(
            &call(4, json!({"id": 2, "method": "eth_requestAccounts"})),
            Some("T1"),
        );
        let (p, _) = b.pending();
        assert_eq!(p.len(), 2);
        assert!(p.iter().all(|r| !r.top_frame), "{p:?}");
    }

    #[test]
    fn an_unknown_context_unsupported_method_or_full_queue_is_refused_at_once() {
        let b = SignInBridge::default();
        let r = b.on_event(
            &call(
                99,
                json!({"id": 1, "method": "personal_sign", "params": ["hi"]}),
            ),
            Some("T1"),
        );
        assert!(r.is_some(), "unknown context");
        b.on_event(&ctx(7, "T1", "https://app.example.org", true), Some("T1"));
        let r = b.on_event(
            &call(
                7,
                json!({"id": 2, "method": "eth_sendTransaction", "params": []}),
            ),
            Some("T1"),
        );
        let r = r.expect("refused");
        assert_eq!(r.method, "Runtime.evaluate");
        assert_eq!(r.params["contextId"], 7);
        for i in 0..MAX_PENDING as u64 {
            assert!(b
                .on_event(
                    &call(7, json!({"id": 10 + i, "method": "eth_requestAccounts"})),
                    Some("T1")
                )
                .is_none());
        }
        assert!(
            b.on_event(
                &call(7, json!({"id": 50, "method": "eth_requestAccounts"})),
                Some("T1")
            )
            .is_some(),
            "a fifth waiting request is refused"
        );
    }

    #[test]
    fn a_destroyed_context_drops_its_requests() {
        let b = SignInBridge::default();
        b.on_event(&ctx(7, "T1", "https://app.example.org", true), Some("T1"));
        b.on_event(
            &call(7, json!({"id": 1, "method": "eth_requestAccounts"})),
            Some("T1"),
        );
        b.on_event(
            &ev(
                "Runtime.executionContextDestroyed",
                json!({"executionContextId": 7}),
            ),
            Some("T1"),
        );
        assert!(b.pending().0.is_empty());
        b.on_event(&ctx(8, "T1", "https://app.example.org", true), Some("T1"));
        b.on_event(
            &call(8, json!({"id": 1, "method": "eth_requestAccounts"})),
            Some("T1"),
        );
        b.on_event(
            &ev("Runtime.executionContextsCleared", json!({})),
            Some("T1"),
        );
        assert!(b.pending().0.is_empty());
    }

    #[test]
    fn an_answer_must_fit_its_request() {
        let b = SignInBridge::default();
        b.on_event(&ctx(7, "T1", "https://app.example.org", true), Some("T1"));
        b.on_event(
            &call(7, json!({"id": 1, "method": "eth_requestAccounts"})),
            Some("T1"),
        );
        let id = b.pending().0[0].id.clone();
        let sig = format!("0x{}", "ab".repeat(65));
        assert!(
            b.take(&id, &SignInAnswer::Signature(sig)).is_err(),
            "a signature for an accounts request"
        );
        assert!(
            b.take(&id, &SignInAnswer::Accounts(vec![])).is_err(),
            "no address"
        );
        assert!(b
            .take(&id, &SignInAnswer::Accounts(vec!["0x01".into()]))
            .is_err());
        let d = b
            .take(
                &id,
                &SignInAnswer::Accounts(vec!["0x0000000000000000000000000000000000000001".into()]),
            )
            .expect("fits");
        assert_eq!(
            d,
            Delivery {
                context_id: 7,
                page_id: 1
            }
        );
        assert!(
            b.take(
                &id,
                &SignInAnswer::Refused {
                    code: 4001,
                    message: "no".into()
                }
            )
            .is_err(),
            "answered once"
        );
    }

    #[test]
    fn personal_sign_accepts_hex_or_text_and_either_parameter_order() {
        assert_eq!(message_bytes("0x6869"), b"hi".to_vec());
        assert_eq!(message_bytes("hi"), b"hi".to_vec());
        assert_eq!(message_bytes("0xzz"), b"0xzz".to_vec());
        let a = "0x0000000000000000000000000000000000000001";
        let (d, addr) = split_personal_sign(&[json!(a), json!("0x6869")]).unwrap();
        assert_eq!((d.as_str(), addr.as_deref()), ("0x6869", Some(a)));
        let (d, addr) = split_personal_sign(&[json!("0x6869"), json!(a)]).unwrap();
        assert_eq!((d.as_str(), addr.as_deref()), ("0x6869", Some(a)));
        assert!(split_personal_sign(&[]).is_none());
    }

    #[test]
    fn the_delivery_expression_carries_json_only() {
        let e = delivery_expression(
            3,
            &SignInAnswer::Refused {
                code: 4001,
                message: "x\"); alert(1); (\"".into(),
            },
        );
        assert!(e.starts_with(&format!("window.{RESOLVER}(3, false, {{")));
        assert!(
            e.contains(r#"\"); alert(1); (\""#),
            "quotes stay inside the JSON string: {e}"
        );
    }

    #[test]
    fn read_origins_are_normalised_and_skip_non_web_pages() {
        let b = SignInBridge::default();
        b.note_read("https://APP.example.org:443/x?y");
        b.note_read("about:blank");
        b.note_read("http://127.0.0.1:8080/");
        assert_eq!(
            b.read_origins(),
            vec![
                "http://127.0.0.1:8080".to_string(),
                "https://app.example.org".to_string()
            ]
        );
        b.clear();
        assert!(b.read_origins().is_empty());
    }

    #[test]
    fn the_provider_script_removes_the_binding_and_installs_only_in_the_top_frame() {
        let s = provider_script();
        assert!(s.contains("delete window[B]"));
        assert!(s.contains("window.top !== window"));
        assert!(s.contains("eip6963:announceProvider"));
        assert!(s.contains(CHAIN_ID_HEX));
        for m in ["eth_sendTransaction", "eth_signTypedData_v4", "eth_sign"] {
            assert!(
                !s.contains(m),
                "{m} must not be special-cased: it falls to the 4200 refusal"
            );
        }
    }
}
